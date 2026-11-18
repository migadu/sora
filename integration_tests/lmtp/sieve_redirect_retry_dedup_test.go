//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_SieveRedirectRetryNotRequeued is issue #1912: an MTA that does not see the
// 250 of a delivery (the connection is lost after the reply) delivers the same message
// again. The stored copy is deduplicated; the redirects must not be queued again either,
// with or without :copy. The retry is sent to a second LMTP server with its own relay
// queue, as a retry may land on another backend node: only the database is shared.
func TestLMTP_SieveRedirectRetryNotRequeued(t *testing.T) {
	for _, tc := range []struct {
		name      string
		script    string
		targets   []string // sorted
		wantInbox int
		rateLimit int
		noMsgID   bool
	}{
		{"redirect", `redirect "fwd@example.org";`, []string{"fwd@example.org"}, 0, 0, false},
		{"redirect copy", `require ["copy"]; redirect :copy "fwd@example.org";`, []string{"fwd@example.org"}, 1, 0, false},
		{"several redirects", `redirect "one@example.com"; redirect "two@example.org";`, []string{"one@example.com", "two@example.org"}, 0, 0, false},
		{"redirect without Message-ID", `redirect "fwd@example.org";`, []string{"fwd@example.org"}, 0, 0, true},
		{"redirect rate limited", `redirect "fwd@example.org";`, []string{"fwd@example.org"}, 0, 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)

			imapSrv, account := common.SetupIMAPServer(t)
			defer imapSrv.Close()
			rdb := imapSrv.ResilientDB

			accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
			if err != nil {
				t.Fatalf("account id: %v", err)
			}
			setActiveSieveScript(t, rdb, accountID, tc.script+"\r\n")

			newNode := func() (string, *captureRelayQueue) {
				rq := &captureRelayQueue{}
				addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
					RelayQueue:         rq,
					RedirectRateLimit:  tc.rateLimit,
					RedirectRateWindow: time.Hour,
				})
				return addr, rq
			}
			nodeA, rqA := newNode()
			nodeB, rqB := newNode()

			const sender = "sender@example.com"
			lines := []string{
				"From: " + sender,
				"To: " + account.Email,
				"Subject: redirect retry",
			}
			if !tc.noMsgID {
				lines = append(lines, fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()))
			} else {
				lines = append(lines, fmt.Sprintf("X-Test-Nonce: %d", time.Now().UnixNano()))
			}
			msg := strings.Join(append(lines, "", "body"), "\r\n")

			if resp := deliverLMTPRaw(t, nodeA, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("first delivery: want 250, got %s", resp)
			}
			if got := rqA.relayedTo(); !slices.Equal(got, tc.targets) {
				t.Fatalf("first delivery relayed to %v, want %v", got, tc.targets)
			}

			// The MTA's retry of the same queue entry, on another node.
			if resp := deliverLMTPRaw(t, nodeB, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("retry: want 250, got %s", resp)
			}
			if got := rqB.relayedTo(); len(got) != 0 {
				t.Errorf("the retry queued the redirects again: %v (the first delivery already queued %v)", got, tc.targets)
			}
			if n := countInMailbox(t, rdb, accountID, "INBOX"); n != tc.wantInbox {
				t.Errorf("INBOX holds %d copies after the retry, want %d", n, tc.wantInbox)
			}
			if tc.rateLimit > 0 {
				if n := countRedirectLog(t, rdb, accountID); n != len(tc.targets) {
					t.Errorf("the redirects were charged %d times against the rate limit, want %d", n, len(tc.targets))
				}
			}
		})
	}
}

// TestLMTP_SieveRedirectSameMessageIDNewContent: a message that is not a retry, only
// shares the Message-ID of one already redirected, is redirected too.
func TestLMTP_SieveRedirectSameMessageIDNewContent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	setActiveSieveScript(t, rdb, accountID, `redirect "fwd@example.org";`+"\r\n")
	rq := &captureRelayQueue{}
	addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{RelayQueue: rq})

	const sender = "sender@example.com"
	msgID := fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano())
	for _, body := range []string{"first body", "second body"} {
		msg := strings.Join([]string{"From: " + sender, "To: " + account.Email, "Subject: same id", msgID, "", body}, "\r\n")
		if resp := deliverLMTPRaw(t, addr, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
			t.Fatalf("delivery: want 250, got %s", resp)
		}
	}
	if got, want := rq.relayedTo(), []string{"fwd@example.org", "fwd@example.org"}; !slices.Equal(got, want) {
		t.Errorf("relayed to %v, want %v: two different messages are two redirects", got, want)
	}
}
