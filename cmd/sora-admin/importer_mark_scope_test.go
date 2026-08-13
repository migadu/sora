//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The SQLite cache is keyed UNIQUE(hash, mailbox) because one message can legitimately
// live in several mailboxes, and each copy needs its own PostgreSQL row. s3_uploaded is
// what an incremental import filters on (WHERE s3_uploaded = 0), so it has to mean "this
// (hash, mailbox) copy has been imported", not "this content reached S3".
//
// Marking by hash alone conflates the two. The S3 object is content-addressed, so it is
// shared by every copy, but the PostgreSQL rows are not: marking the whole hash when one
// copy is imported makes every other copy invisible to the next incremental run, and that
// copy never appears in the user's mailbox.
func TestMarkBatchInSQLiteIsScopedToTheMailbox(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	testEmail := "mark-scope@demo.com"
	createSimpleTestAccount(t, rdb, testEmail, "testpassword123")

	maildirPath := filepath.Join(t.TempDir(), "testmaildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755); err != nil {
			t.Fatalf("Failed to create maildir structure: %v", err)
		}
	}

	importer, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, ImporterOptions{Incremental: true})
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	// One content hash present in two mailboxes: the same message filed in both, which
	// UNIQUE(hash, mailbox) exists to allow.
	const sharedHash = "sharedcontenthash0000000000000000000000000000000000000000000000"
	for _, mailbox := range []string{"INBOX", "Archive"} {
		if _, err := importer.sqliteDB.Exec(
			`INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, ?, ?, 0)`,
			filepath.Join(maildirPath, mailbox, "cur", "msg:2,S"), "msg:2,S", sharedHash, 128, mailbox,
		); err != nil {
			t.Fatalf("Failed to seed %s row: %v", mailbox, err)
		}
	}

	// Import only the INBOX copy.
	if err := importer.markBatchInSQLite([]markedMessage{{hash: sharedHash, mailbox: "INBOX"}}); err != nil {
		t.Fatalf("markBatchInSQLite failed: %v", err)
	}

	uploaded := func(mailbox string) int {
		var flag int
		if err := importer.sqliteDB.QueryRow(
			`SELECT s3_uploaded FROM messages WHERE hash = ? AND mailbox = ?`, sharedHash, mailbox,
		).Scan(&flag); err != nil {
			t.Fatalf("Failed to read %s row: %v", mailbox, err)
		}
		return flag
	}

	if got := uploaded("INBOX"); got != 1 {
		t.Errorf("INBOX copy s3_uploaded = %d, want 1: the imported copy must be marked", got)
	}
	if got := uploaded("Archive"); got != 0 {
		t.Errorf("Archive copy s3_uploaded = %d, want 0: marking by hash alone marks copies that were "+
			"never imported, and an incremental run skips them forever (WHERE s3_uploaded = 0)", got)
	}
}
