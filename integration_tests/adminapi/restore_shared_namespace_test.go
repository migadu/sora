//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// TestRestoreMessages_SharedNamespace: POST /admin/accounts/{email}/messages/restore gives
// the restore the server's [shared_mailboxes] config, so a deleted mailbox in the shared
// namespace, and the namespace root above it, come back as shared mailboxes the account
// owns (#1289). They came back personal, which IMAP cannot share.
func TestRestoreMessages_SharedNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	shared := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"}
	server := setupHTTPAPIServer(t, func(o *adminapi.ServerOptions) { o.SharedMailboxes = shared })
	defer server.Close()

	account := common.CreateTestAccount(t, server.rdb)
	ctx := context.Background()
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatal(err)
	}
	pool := server.rdb.GetDatabase().GetWritePool()

	// What DeleteMailbox leaves of a message of Shared/Team: expunged, no mailbox, the
	// name recorded in mailbox_path.
	if _, err := pool.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
			subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, created_modseq, expunged_at)
		VALUES ($1, NULL, 'Shared/Team', 1, 'example.com', 'restore', $2, 'team', '<team@example.com>',
			'[]'::jsonb, ''::bytea, now(), now(), 100, nextval('messages_modseq'), now())`,
		accountID, fmt.Sprintf("restore-shared-%d", time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}

	resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+account.Email+"/messages/restore",
		map[string]any{"mailbox": "Shared/Team"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore: %d %s", resp.StatusCode, body)
	}
	var result map[string]any
	server.expectJSON(t, body, &result)
	if result["restored"] != float64(1) {
		t.Fatalf("restored = %v, want 1", result["restored"])
	}

	for _, name := range []string{"Shared", "Shared/Team"} {
		var isShared bool
		var domain string
		if err := pool.QueryRow(ctx, `
			SELECT COALESCE(is_shared, FALSE), COALESCE(owner_domain, '')
			FROM mailboxes WHERE account_id = $1 AND name = $2 AND deleted_at IS NULL`,
			accountID, name).Scan(&isShared, &domain); err != nil {
			t.Fatalf("mailbox %s: %v", name, err)
		}
		if !isShared || domain != "example.com" {
			t.Errorf("mailbox %s: is_shared=%v owner_domain=%q, want is_shared=true owner_domain=%q",
				name, isShared, domain, "example.com")
		}
	}
}
