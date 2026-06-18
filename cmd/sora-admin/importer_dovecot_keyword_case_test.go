//go:build integration

package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// TestImporter_DovecotKeywordCaseInsensitive verifies that the Dovecot maildir
// importer folds imported keywords onto the case already established for the
// destination mailbox (RFC 9051 §2.3.2). The test fixture's dovecot-keywords maps
// index 0 -> "NonJunk", and every sample message carries it (filename flags ":2,Sa",
// where 'a' is keyword index 0). We pre-seed INBOX with the lowercase spelling
// "nonjunk" so the importer must fold the maildir's "NonJunk" onto it rather than
// introduce a second case variant.
func TestImporter_DovecotKeywordCaseInsensitive(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	s3Storage := setupTestS3Storage(t)

	const testEmail = "user@demo.com"
	createTestAccount(t, rdb, testEmail, "testpassword123")

	ctx := context.Background()
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("invalid email: %v", err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("failed to get account ID: %v", err)
	}

	// Ensure INBOX exists and establish "nonjunk" (lowercase) as its canonical case
	// by seeding the per-mailbox keyword cache the importer reads.
	inbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("failed to get/create INBOX: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO mailbox_stats (mailbox_id, updated_at, custom_flags_cache)
		VALUES ($1, NOW(), '["nonjunk"]'::jsonb)
		ON CONFLICT (mailbox_id) DO UPDATE SET custom_flags_cache = EXCLUDED.custom_flags_cache
	`, inbox.ID); err != nil {
		t.Fatalf("failed to seed canonical keyword case: %v", err)
	}

	// Import the Dovecot maildir fixture (its dovecot-keywords uses "NonJunk").
	maildirPath := filepath.Join(t.TempDir(), "testmaildir")
	if err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, 5); err != nil {
		t.Fatalf("failed to copy test data: %v", err)
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, s3Storage, ImporterOptions{
		PreserveFlags: true,
		Dovecot:       true,
		TestMode:      true, // skip S3 uploads
	})
	if err != nil {
		t.Fatalf("failed to create importer: %v", err)
	}
	defer importer.Close()

	if err := importer.Run(); err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// Inspect the imported messages' keywords.
	messages, err := rdb.ListMessagesWithRetry(ctx, inbox.ID)
	if err != nil {
		t.Fatalf("failed to list imported messages: %v", err)
	}
	if len(messages) == 0 {
		t.Fatal("no messages were imported")
	}

	folded := 0
	for _, m := range messages {
		for _, kw := range m.CustomFlags {
			if kw == "NonJunk" {
				t.Errorf("imported message UID %d kept the maildir's case %q; expected it folded onto the pre-existing \"nonjunk\"", m.UID, kw)
			}
			if strings.EqualFold(kw, "nonjunk") {
				if kw != "nonjunk" {
					t.Errorf("imported message UID %d has keyword %q; want canonical \"nonjunk\"", m.UID, kw)
				}
				folded++
			}
		}
	}
	if folded == 0 {
		t.Fatalf("no imported message carried the NonJunk keyword; fixture/import may have changed (checked %d messages)", len(messages))
	}
	t.Logf("✓ %d/%d imported messages carry the keyword, all folded to canonical \"nonjunk\"", folded, len(messages))
}
