//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAdminAPI_DeliverMail_SieveMailboxExists is issue #323 (1) on the Admin API
// path: mailboxexists is false for a mailbox the account does not have (RFC 5490
// §3.1), so the script's else branch runs. It used to be true for any name.
func TestAdminAPI_DeliverMail_SieveMailboxExists(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := setupHTTPAPIServerWithUploader(t)
	defer server.Close()

	ctx := context.Background()
	email := fmt.Sprintf("apimbxexists-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	for _, name := range []string{"Exists", "Fallback"} {
		if _, err := server.rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	for _, tc := range []struct {
		mailbox string
		want    string
	}{
		{mailbox: "Exists", want: "Exists"},
		{mailbox: fmt.Sprintf("Nonexistent-%d", time.Now().UnixNano()), want: "Fallback"},
	} {
		t.Run(tc.mailbox, func(t *testing.T) {
			// The account address in a comment keeps the script text unique, so a
			// compile cached by another test cannot serve it.
			script := "# " + email + "\r\nrequire [\"fileinto\", \"mailbox\"];\r\n" +
				`if mailboxexists "` + tc.mailbox + `" { fileinto "Exists"; } else { fileinto "Fallback"; }` + "\r\n"
			if _, err := server.rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
				t.Fatalf("clear sieve: %v", err)
			}
			sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
			if err != nil {
				t.Fatalf("create sieve script: %v", err)
			}
			if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
				t.Fatalf("activate sieve script: %v", err)
			}

			subject := fmt.Sprintf("mailboxexists-%d", time.Now().UnixNano())
			msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + subject +
				"\r\nMessage-ID: <" + subject + "@example.com>\r\n\r\nBody via API.\r\n"
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{email},
				"message":    msg,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
			}

			var mailbox string
			if err := server.rdb.QueryRowWithRetry(ctx, `
				SELECT mb.name FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL`,
				accountID, subject).Scan(&mailbox); err != nil {
				t.Fatalf("find delivered message: %v", err)
			}
			if mailbox != tc.want {
				t.Errorf("mailboxexists %q: stored in %s, want %s", tc.mailbox, mailbox, tc.want)
			}
		})
	}
}
