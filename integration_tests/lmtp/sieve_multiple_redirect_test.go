//go:build integration

package lmtp_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
)

// relayedTo returns the sorted redirect targets the queue has received.
func (q *captureRelayQueue) relayedTo() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var to []string
	for _, it := range q.enqueued {
		if it.msgType == "redirect" {
			to = append(to, it.to)
		}
	}
	slices.Sort(to)
	return to
}

// setActiveSieveScript makes script the account's only, active Sieve script and
// empties its redirect_log, so a test starts from a clean rate-limit window.
func setActiveSieveScript(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, script string) {
	t.Helper()
	ctx := context.Background()
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear redirect_log: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear sieve: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())`,
		accountID, "multi-redirect", script, true); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}
}

func countRedirectLog(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) int {
	t.Helper()
	var n int
	if err := rdb.QueryRowWithRetry(context.Background(),
		"SELECT COUNT(*) FROM redirect_log WHERE account_id = $1", accountID).Scan(&n); err != nil {
		t.Fatalf("count redirect_log: %v", err)
	}
	return n
}

// TestLMTP_SieveMultipleRedirects is issue #230 on the LMTP path: a script may
// run several redirect actions (RFC 5228 §2.10.4) and the message must be relayed
// to every address, not only the first. What is charged against the redirect
// rate limit must be what was relayed.
func TestLMTP_SieveMultipleRedirects(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}

	targets := []string{"one@example.com", "three@example.net", "two@example.org"} // sorted

	cases := []struct {
		name      string
		script    []string
		wantInbox int
	}{
		{
			name: "copy keeps a local copy",
			script: []string{
				`require ["copy"];`,
				`redirect :copy "one@example.com";`,
				`redirect :copy "two@example.org";`,
				`redirect :copy "three@example.net";`,
			},
			wantInbox: 1,
		},
		{
			name: "without copy nothing is stored",
			script: []string{
				`redirect "one@example.com";`,
				`redirect "two@example.org";`,
				`redirect "three@example.net";`,
			},
			wantInbox: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setActiveSieveScript(t, rdb, accountID, strings.Join(tc.script, "\r\n")+"\r\n")
			rq := &captureRelayQueue{}
			lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 100, time.Hour)
			inboxBefore := countInMailbox(t, rdb, accountID, "INBOX")

			deliverLMTP(t, lmtpAddr, account.Email, "multi-redirect")
			time.Sleep(300 * time.Millisecond)

			got := rq.relayedTo()
			if !slices.Equal(got, targets) {
				t.Errorf("relayed to %v, want every redirect address %v", got, targets)
			}
			if n := countInMailbox(t, rdb, accountID, "INBOX") - inboxBefore; n != tc.wantInbox {
				t.Errorf("copies added to INBOX = %d, want %d", n, tc.wantInbox)
			}
			if logged := countRedirectLog(t, rdb, accountID); logged != len(got) {
				t.Errorf("rate limit charged %d redirects for %d relayed", logged, len(got))
			}
		})
	}
}
