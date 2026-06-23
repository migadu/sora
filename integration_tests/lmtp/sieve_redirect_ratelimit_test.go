//go:build integration

package lmtp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// captureRelayQueue records every Enqueue so the test can assert which redirects
// actually reached the relay (vs. being rate-limited back to INBOX). It satisfies
// delivery.RelayQueue structurally.
type captureRelayQueue struct {
	mu       sync.Mutex
	enqueued []relayItem
}

type relayItem struct {
	from, to, msgType string
}

func (q *captureRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.enqueued = append(q.enqueued, relayItem{from: from, to: to, msgType: messageType})
	return nil
}

func (q *captureRelayQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.enqueued)
}

// TestLMTP_SieveRedirect_RateLimited drives the full LMTP delivery path against a
// per-account SIEVE `redirect` rule and proves the redirect rate limit (audit H3):
//   - the first N messages within the window relay (Enqueue called, not stored locally),
//   - message N+1 is rate-limited: it is NOT relayed and falls back to INBOX (no loss),
//   - once the window's log entries clear, redirects resume.
//
// A non-:copy redirect that succeeds is not stored locally, so INBOX count is the
// exact count of *blocked* redirects — a clean observable for the limit.
func TestLMTP_SieveRedirect_RateLimited(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, accountA := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountAID, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	if err != nil {
		t.Fatalf("account A id: %v", err)
	}

	// Start from a clean redirect_log for this account so a prior run within the
	// (1h) window can't contaminate the count.
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountAID); err != nil {
		t.Fatalf("clear redirect_log: %v", err)
	}

	// Recipient A's active SIEVE redirects all incoming mail to an external address.
	// `redirect` is a core action (RFC 5228) and needs no `require`.
	const redirectTarget = "external@example.net"
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountAID); err != nil {
		t.Fatalf("clear sieve: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())`,
		accountAID, "redirect-all", "redirect \""+redirectTarget+"\";\r\n", true); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}

	const limit = 3
	rq := &captureRelayQueue{}
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, limit, time.Hour)

	// === Phase 1: deliver limit+1 messages; first `limit` relay, the last is kept. ===
	for i := 0; i < limit+1; i++ {
		deliverLMTP(t, lmtpAddr, accountA.Email, "redirect-rl")
	}
	time.Sleep(300 * time.Millisecond)

	if got := rq.count(); got != limit {
		t.Errorf("phase 1: expected exactly %d relayed redirects, got %d", limit, got)
	}
	if n := countInMailbox(t, rdb, accountAID, "INBOX"); n != 1 {
		t.Errorf("phase 1: the rate-limited message must fall back to INBOX (1), got %d", n)
	}
	// Sanity: every relayed item is a redirect to the configured target.
	rq.mu.Lock()
	for _, it := range rq.enqueued {
		if it.msgType != "redirect" || it.to != redirectTarget {
			t.Errorf("phase 1: unexpected relay item %+v", it)
		}
	}
	rq.mu.Unlock()

	// === Phase 2: window clears (mirror the cleaner's DELETE); redirects resume. ===
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountAID); err != nil {
		t.Fatalf("clear redirect_log (phase 2): %v", err)
	}
	deliverLMTP(t, lmtpAddr, accountA.Email, "redirect-rl-resumed")
	time.Sleep(300 * time.Millisecond)

	if got := rq.count(); got != limit+1 {
		t.Errorf("phase 2: redirect must resume after the window clears (expected %d total relays, got %d)", limit+1, got)
	}
	if n := countInMailbox(t, rdb, accountAID, "INBOX"); n != 1 {
		t.Errorf("phase 2: a resumed redirect must not be stored locally; INBOX should be unchanged (1), got %d", n)
	}
}

// startTestLMTPServerWithRedirect starts an LMTP server backed by rdb with a relay
// queue and an explicit redirect rate limit, returning its address.
func startTestLMTPServerWithRedirect(t *testing.T, rdb *resilient.ResilientDatabase, rq *captureRelayQueue, limit int, window time.Duration) string {
	t.Helper()
	up, err := uploader.NewWithS3Interface(
		t.TempDir(), 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	addr := common.GetRandomAddress(t)
	srv, err := lmtpserver.New(context.Background(), "test-lmtp-redirect", "localhost", addr,
		&storage.S3Storage{}, rdb, up, lmtpserver.LMTPServerOptions{
			RelayQueue:         rq,
			RedirectRateLimit:  limit,
			RedirectRateWindow: window,
		})
	if err != nil {
		t.Fatalf("lmtp new: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Start(make(chan error, 1))
	time.Sleep(200 * time.Millisecond)
	return addr
}
