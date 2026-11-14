package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMarkBatchInSQLiteNeverCommitsAfterReportingFailure: once markBatchInSQLite has
// returned an error, no row may end up marked. With --batch-transaction the caller
// answers that error by deleting the batch from PostgreSQL (rollback compensation), and
// recoverOrphanedSQLiteState trusts a row stamped with the account without checking
// PostgreSQL. A mark committed after the caller gave up would hide that message from
// every later --incremental run although it is in no mailbox.
//
// A context that is already done stands in for the 30-second deadline expiring.
func TestMarkBatchInSQLiteNeverCommitsAfterReportingFailure(t *testing.T) {
	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	importer, err := NewImporter(ctx, maildirPath, "mark-timeout@example.com", 1, nil, nil, ImporterOptions{Incremental: true})
	if err != nil {
		t.Fatal(err)
	}
	defer importer.Close()
	importer.accountID = 42

	const hash = "marktimeout000000000000000000000000000000000000000000000000000000"
	if _, err := importer.sqliteDB.Exec(
		`INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, ?, 'INBOX', 0)`,
		filepath.Join(maildirPath, "cur", "msg:2,S"), "msg:2,S", hash, 64,
	); err != nil {
		t.Fatal(err)
	}

	cancel()
	markErr := importer.markBatchInSQLite([]markedMessage{{hash: hash, mailbox: "INBOX"}})

	// A mark still running after the call returned would commit within this window.
	deadline := time.Now().Add(time.Second)
	for {
		var uploaded int
		if err := importer.sqliteDB.QueryRow(`SELECT s3_uploaded FROM messages WHERE hash = ?`, hash).Scan(&uploaded); err != nil {
			t.Fatal(err)
		}
		if markErr != nil && uploaded != 0 {
			t.Fatalf("markBatchInSQLite returned %q, yet the row was marked imported afterwards", markErr)
		}
		if markErr == nil && uploaded != 1 {
			t.Fatalf("markBatchInSQLite succeeded, yet the row is not marked")
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
