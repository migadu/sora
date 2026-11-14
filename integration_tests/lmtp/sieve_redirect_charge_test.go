//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// refusingRelayQueue refuses one address and records the rest.
type refusingRelayQueue struct {
	captureRelayQueue
	refuse string
}

func (q *refusingRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	if to == q.refuse {
		return fmt.Errorf("relay queue refused %s", to)
	}
	return q.captureRelayQueue.Enqueue(from, to, messageType, messageBytes)
}

// TestLMTP_SieveRedirect_ChargesOnlyWhatIsRelayed is #327 on the LMTP path: the
// redirect rate limit counts redirects that were queued. A redirect with no relay
// queue to take it, or one the queue refused, keeps the message in INBOX and must
// not use up the account's allowance.
func TestLMTP_SieveRedirect_ChargesOnlyWhatIsRelayed(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	script := strings.Join([]string{
		`redirect "one@example.com";`,
		`redirect "two@example.org";`,
		`redirect "three@example.net";`,
	}, "\r\n") + "\r\n"

	for _, tc := range []struct {
		name        string
		opts        lmtpserver.LMTPServerOptions
		wantCharged int
	}{
		{
			name:        "no relay queue",
			opts:        lmtpserver.LMTPServerOptions{},
			wantCharged: 0,
		},
		{
			name:        "queue refuses one address",
			opts:        lmtpserver.LMTPServerOptions{RelayQueue: &refusingRelayQueue{refuse: "two@example.org"}},
			wantCharged: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setActiveSieveScript(t, rdb, accountID, script)
			tc.opts.RedirectRateLimit = 100
			tc.opts.RedirectRateWindow = time.Hour
			lmtpAddr, _ := startTestLMTPServerWithOptions(t, rdb, tc.opts)
			inboxBefore := countInMailbox(t, rdb, accountID, "INBOX")

			deliverLMTP(t, lmtpAddr, account.Email, "redirect-charge")
			time.Sleep(300 * time.Millisecond)

			if n := countInMailbox(t, rdb, accountID, "INBOX") - inboxBefore; n != 1 {
				t.Errorf("copies added to INBOX = %d, want the message kept (1)", n)
			}
			if charged := countRedirectLog(t, rdb, accountID); charged != tc.wantCharged {
				t.Errorf("rate limit charged %d redirects, want %d", charged, tc.wantCharged)
			}
		})
	}
}
