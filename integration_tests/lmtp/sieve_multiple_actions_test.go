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
)

// TestLMTP_SieveEveryFilingAndRedirectHappens is issue #322: a script that runs
// fileinto and redirect, or fileinto more than once, must have every one of those
// actions carried out. Only the first fileinto target used to be filed, and a
// redirect next to a fileinto was dropped without a word. RFC 5228 §2.10.4 lets a
// site limit the actions, but hitting such a limit is an error, not a silent skip.
// The implicit or explicit keep still decides the INBOX copy (§2.10.2), and the
// redirect rate limit is charged for what was relayed.
func TestLMTP_SieveEveryFilingAndRedirectHappens(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	for _, name := range []string{"Archive", "Projects"} {
		if _, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	const target = "other@example.org"
	cases := []struct {
		name       string
		script     []string
		wantStored []string // sorted mailbox names, one entry per copy
		wantRelay  []string
	}{
		{
			name:       "fileinto and redirect",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `redirect "` + target + `";`},
			wantStored: []string{"Archive"},
			wantRelay:  []string{target},
		},
		{
			name:       "redirect and fileinto",
			script:     []string{`require ["fileinto"];`, `redirect "` + target + `";`, `fileinto "Archive";`},
			wantStored: []string{"Archive"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto twice",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `fileinto "Projects";`},
			wantStored: []string{"Archive", "Projects"},
		},
		{
			// The redirect cancels the implicit keep that fileinto :copy left (RFC 3894 §3).
			name:       "fileinto :copy and redirect",
			script:     []string{`require ["fileinto", "copy"];`, `fileinto :copy "Archive";`, `redirect "` + target + `";`},
			wantStored: []string{"Archive"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto :copy and redirect :copy",
			script:     []string{`require ["fileinto", "copy"];`, `fileinto :copy "Archive";`, `redirect :copy "` + target + `";`},
			wantStored: []string{"Archive", "INBOX"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto twice and keep",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `fileinto "Projects";`, `keep;`},
			wantStored: []string{"Archive", "INBOX", "Projects"},
		},
		{
			name:       "the same mailbox twice is one copy",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `fileinto "Archive";`},
			wantStored: []string{"Archive"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setActiveSieveScript(t, rdb, accountID, strings.Join(tc.script, "\r\n")+"\r\n")
			rq := &captureRelayQueue{}
			lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 100, time.Hour)

			stamp := time.Now().UnixNano()
			subject := fmt.Sprintf("multi-action %d", stamp)
			msg := strings.Join([]string{
				"From: sender@example.com",
				"To: " + account.Email,
				"Subject: " + subject,
				fmt.Sprintf("Message-ID: <%d@example.com>", stamp),
				"",
				"body",
			}, "\r\n")
			if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			if got := mailboxesHolding(t, rdb, accountID, subject); !slices.Equal(got, tc.wantStored) {
				t.Errorf("stored in %v, want %v", got, tc.wantStored)
			}
			if got := rq.relayedTo(); !slices.Equal(got, tc.wantRelay) {
				t.Errorf("relayed to %v, want %v", got, tc.wantRelay)
			}
			if logged := countRedirectLog(t, rdb, accountID); logged != len(tc.wantRelay) {
				t.Errorf("rate limit charged %d redirects, want %d", logged, len(tc.wantRelay))
			}
		})
	}
}
