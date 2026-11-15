//go:build integration

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestImporter_SharedNamespaceFolders: with [shared_mailboxes] enabled, a maildir
// folder under the namespace prefix is imported into a shared mailbox the account
// owns, as `sora-admin mailbox create` makes one, and so is the parent level it
// needs. The importer created them as personal mailboxes (is_shared = false) inside
// the shared namespace (#1230), which IMAP then refuses to share. A folder outside
// the namespace stays personal.
func TestImporter_SharedNamespaceFolders(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "shared-import@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatal(err)
	}

	maildir := filepath.Join(t.TempDir(), "Maildir")
	createMaildirFolder(t, maildir)
	date := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	createMaildirFolder(t, filepath.Join(maildir, ".Shared.Team"))
	createMessagesInMaildir(t, filepath.Join(maildir, ".Shared.Team"), []testMessage{{uid: 1, filename: "1700000001.M1P1.host",
		flags: "S", subject: "team", from: "a@example.com", to: email, date: date}})
	createMaildirFolder(t, filepath.Join(maildir, ".Work"))
	createMessagesInMaildir(t, filepath.Join(maildir, ".Work"), []testMessage{{uid: 1, filename: "1700000002.M2P2.host",
		flags: "S", subject: "work", from: "a@example.com", to: email, date: date}})

	importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil, ImporterOptions{TestMode: true, BatchSize: 10,
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}

	type mailbox struct {
		shared   bool
		domain   string
		messages int64
	}
	want := map[string]mailbox{
		"Shared":      {shared: true, domain: "example.com"},
		"Shared/Team": {shared: true, domain: "example.com", messages: 1},
		"Work":        {messages: 1},
	}
	for name, w := range want {
		var got mailbox
		var id int64
		if err := rdb.GetOperationalDatabase().WritePool.QueryRow(ctx, `
			SELECT id, COALESCE(is_shared, FALSE), COALESCE(owner_domain, ''),
				(SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id AND expunged_at IS NULL)
			FROM mailboxes m WHERE account_id = $1 AND name = $2 AND deleted_at IS NULL`,
			accountID, name).Scan(&id, &got.shared, &got.domain, &got.messages); err != nil {
			t.Errorf("mailbox %s: %v", name, err)
			continue
		}
		if got != w {
			t.Errorf("mailbox %s: is_shared=%v owner_domain=%q messages=%d, want is_shared=%v owner_domain=%q messages=%d",
				name, got.shared, got.domain, got.messages, w.shared, w.domain, w.messages)
		}
		if !w.shared {
			continue
		}
		acls, err := rdb.GetMailboxACLsWithRetry(ctx, id)
		if err != nil {
			t.Fatalf("ACL of %s: %v", name, err)
		}
		if len(acls) != 1 || acls[0].Identifier != email || acls[0].Rights != "lrswipkxtea" {
			t.Errorf("ACL of %s = %+v, want the owner %s with lrswipkxtea", name, acls, email)
		}
	}
}
