//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/sieveengine"
)

// TestAdminAPI_DeliverMail_UnknownCharset verifies that HTTP mail delivery
// (POST /admin/mail/deliver) accepts messages with unknown charsets or malformed
// Content-Transfer-Encoding — matching LMTP and IMAP APPEND via server.ParseMessage —
// and preserves Sieve editheader edits on them instead of failing with a 400/503 or
// reverting to the unedited message bytes.
func TestAdminAPI_DeliverMail_UnknownCharset(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	enabled := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")
	server, tempDir := setupHTTPAPIServerWithUploader(t, enabled...)
	defer server.Close()

	ctx := context.Background()

	cases := []struct {
		name        string
		mimeHeaders string
		bodyText    string
	}{
		{
			name:        "unknown charset",
			mimeHeaders: "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=x-unknown\r\n",
			bodyText:    "Body in x-unknown charset.\r\n",
		},
		{
			name:        "malformed transfer encoding",
			mimeHeaders: "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit <center>\r\n",
			bodyText:    "Body with malformed encoding.\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("apicharset-%d@example.com", time.Now().UnixNano())
			createDeliveryAccount(t, server, email)

			accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}

			marker := fmt.Sprintf("charset-%d", time.Now().UnixNano())
			script := fmt.Sprintf("require [\"editheader\", \"fileinto\"];\r\n# %s\r\n"+
				"addheader \"X-Spam-Flag\" \"YES\";\r\nfileinto \"Junk\";\r\n", marker)
			sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
			if err != nil {
				t.Fatalf("create sieve script: %v", err)
			}
			if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
				t.Fatalf("activate sieve script: %v", err)
			}

			msg := "From: sender@example.com\r\n" +
				"To: " + email + "\r\n" +
				"Subject: " + marker + "\r\n" +
				"Message-ID: <" + marker + "@example.com>\r\n" +
				tc.mimeHeaders +
				"\r\n" +
				tc.bodyText

			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{email},
				"message":    msg,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: got status %d, want 200; body=%s", resp.StatusCode, string(body))
			}

			var contentHash, mailboxName string
			var rowAccountID int64
			err = server.rdb.QueryRowWithRetry(ctx, `
				SELECT m.content_hash, mb.name, m.account_id
				FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE m.account_id = $1 AND m.expunged_at IS NULL
				ORDER BY m.uid DESC LIMIT 1
			`, accountID).Scan(&contentHash, &mailboxName, &rowAccountID)
			if err != nil {
				t.Fatalf("delivered message row: %v", err)
			}

			if mailboxName != "Junk" {
				t.Fatalf("Sieve did not file the message: mailbox=%s, want Junk", mailboxName)
			}

			stored, err := os.ReadFile(filepath.Join(tempDir, fmt.Sprintf("%d", rowAccountID), contentHash))
			if err != nil {
				t.Fatalf("stored body must be readable at content_hash %s: %v", contentHash, err)
			}
			if got := helpers.HashContent(stored); got != contentHash {
				t.Errorf("stored body does not hash to content_hash: stored=%s row=%s", got, contentHash)
			}
			if !strings.Contains(string(stored), "X-Spam-Flag: YES") {
				t.Errorf("Sieve header edit was dropped; stored head:\n%s", adminHead(string(stored)))
			}
			if !strings.Contains(string(stored), tc.bodyText) {
				t.Errorf("stored message missing original body %q; got:\n%s", tc.bodyText, string(stored))
			}
		})
	}

	t.Run("malformed MIME header rejected", func(t *testing.T) {
		email := fmt.Sprintf("apimalformed-%d@example.com", time.Now().UnixNano())
		createDeliveryAccount(t, server, email)

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
			"recipients": []string{email},
			"message":    " Invalid: header\r\nTo: " + email + "\r\n\r\nBody.\r\n",
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for malformed MIME header, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
