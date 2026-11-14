//go:build integration

package lmtp_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/delivery"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_SieveRedirectWithoutCopyStagesNothing is #548: a redirect without :copy
// stores nothing, so its body must not be staged for upload either. A staged and
// abandoned file sits in the spool until the orphan sweep and counts against the
// staging limit meanwhile, for every message an account forwards. The body is
// staged only when a redirect could not be queued and the message is kept.
func TestLMTP_SieveRedirectWithoutCopyStagesNothing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, tc := range []struct {
		name  string
		queue delivery.RelayQueue
		kept  bool
	}{
		{"every redirect queued", &captureRelayQueue{}, false},
		{"queue refuses one address", &refusingRelayQueue{refuse: "two@example.org"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imapSrv, account := common.SetupIMAPServer(t)
			defer imapSrv.Close()
			rdb := imapSrv.ResilientDB
			ctx := context.Background()

			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("account id: %v", err)
			}
			setActiveSieveScript(t, rdb, accountID, "redirect \"one@example.com\";\r\nredirect \"two@example.org\";\r\n")
			lmtpAddr, up := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
				RelayQueue:         tc.queue,
				RedirectRateLimit:  100,
				RedirectRateWindow: time.Hour,
			})

			deliverLMTP(t, lmtpAddr, account.Email, "redirect without copy")

			// Every file in the account's part of the spool, by content hash.
			staged := map[string]bool{}
			accountDir := filepath.Dir(up.FilePath(strings.Repeat("0", 64), accountID))
			_ = filepath.WalkDir(accountDir, func(path string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					staged[d.Name()] = true
				}
				return nil
			})

			if !tc.kept {
				if n := countInMailbox(t, rdb, accountID, "INBOX"); n != 0 {
					t.Errorf("INBOX holds %d copies, want 0", n)
				}
				for name := range staged {
					t.Errorf("a redirected message that is stored nowhere was staged in the upload spool: %s", name)
				}
				return
			}

			// Kept in INBOX: the stored row's body must be staged for the uploader.
			var contentHash string
			if err := rdb.QueryRowWithRetry(ctx, `
				SELECT m.content_hash FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
				WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL`, accountID).Scan(&contentHash); err != nil {
				t.Fatalf("the message must be kept in INBOX when a redirect fails: %v", err)
			}
			if _, err := os.Stat(up.FilePath(contentHash, accountID)); err != nil {
				t.Errorf("the kept message's body is not staged for upload: %v", err)
			}
		})
	}
}
