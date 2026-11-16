//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_DefaultSieveFilesSpamIntoJunkSpecialUse is issue #987: the default
// script's spam filing goes to the account's mailbox carrying the RFC 6154 \Junk
// attribute, the one LIST presents as the Junk folder, whatever it is named. The
// attribute survives RENAME (migration 000045), so a renamed Junk folder keeps
// receiving spam, and a plain folder named Junk next to it, which LIST does not
// mark \Junk, does not. RFC 8579 §4 gives the rule for fileinto :specialuse: it
// "first checks whether a mailbox exists in the user's personal namespace
// [NAMESPACE] with the specified special-use attribute assigned to it. If that is
// the case, that special-use mailbox is used for delivery instead." Only without
// one does the name Junk decide.
func TestLMTP_DefaultSieveFilesSpamIntoJunkSpecialUse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	lmtpAddr, _ := startLMTPForDelivery(t, rdb)
	ctx := context.Background()

	cases := []struct {
		name      string
		renameTo  string   // new name of the default Junk mailbox, "" to keep it
		noJunkUse bool     // no mailbox carries \Junk
		plainJunk bool     // an ordinary mailbox named Junk exists (made after the rename)
		script    []string // the user's active script, nil for none
		want      string   // the mailbox the spam must be stored in
	}{
		{name: "default Junk", want: "Junk"},
		{name: "renamed Junk", renameTo: "Spam", want: "Spam"},
		{name: "renamed Junk next to a plain Junk", renameTo: "Spam", plainJunk: true, want: "Spam"},
		{name: "user keep leaves the default filing", renameTo: "Spam", plainJunk: true, script: []string{`keep;`}, want: "Spam"},
		// The user's own fileinto names a mailbox (RFC 5228 §4.1); only the
		// default script's spam filing goes by the attribute.
		{
			name:     "user fileinto Junk goes by name",
			renameTo: "Spam", plainJunk: true,
			script: []string{`require ["fileinto"];`, `fileinto "Junk";`},
			want:   "Junk",
		},
		{name: "no Junk special-use files into Junk by name", noJunkUse: true, want: "Junk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("account id: %v", err)
			}

			if tc.renameTo != "" {
				junk, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Junk")
				if err != nil {
					t.Fatalf("get Junk: %v", err)
				}
				if err := rdb.RenameMailboxWithRetry(ctx, junk.ID, accountID, tc.renameTo, nil); err != nil {
					t.Fatalf("rename Junk to %s: %v", tc.renameTo, err)
				}
				renamed, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, tc.renameTo)
				if err != nil {
					t.Fatalf("get %s: %v", tc.renameTo, err)
				}
				if renamed.SpecialUse != `\Junk` {
					t.Fatalf("%s special-use %q after RENAME, want \\Junk", tc.renameTo, renamed.SpecialUse)
				}
			}
			if tc.noJunkUse {
				if _, err := rdb.ExecWithRetry(ctx,
					`UPDATE mailboxes SET special_use = NULL WHERE account_id = $1 AND special_use = '\Junk'`,
					accountID); err != nil {
					t.Fatalf("clear \\Junk: %v", err)
				}
			}
			if tc.plainJunk {
				if err := rdb.CreateMailboxWithRetry(ctx, accountID, "Junk", nil); err != nil {
					t.Fatalf("create plain Junk: %v", err)
				}
			}
			if tc.script != nil {
				// The account address in a comment keeps the script text unique, so a
				// compile cached by another test cannot serve it.
				script := strings.Join(append([]string{"# " + account.Email}, tc.script...), "\r\n") + "\r\n"
				sc, err := rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
				if err != nil {
					t.Fatalf("create sieve script: %v", err)
				}
				if err := rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
					t.Fatalf("activate sieve script: %v", err)
				}
			}

			stamp := time.Now().UnixNano()
			subject := fmt.Sprintf("spam %d", stamp)
			msg := strings.Join([]string{
				"From: sender@example.com",
				"To: " + account.Email,
				"Subject: " + subject,
				fmt.Sprintf("Message-ID: <%d@example.com>", stamp),
				"X-Spam: Yes",
				"",
				"body",
			}, "\r\n")
			if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			var mailbox string
			if err := rdb.QueryRowWithRetry(ctx, `
				SELECT mb.name FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL`,
				accountID, subject).Scan(&mailbox); err != nil {
				t.Fatalf("find delivered message: %v", err)
			}
			if mailbox != tc.want {
				t.Errorf("spam stored in %s, want %s", mailbox, tc.want)
			}
		})
	}
}
