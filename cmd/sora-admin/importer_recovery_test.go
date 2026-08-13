//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRecoverOrphanedSQLiteState_AllUploadedRows verifies that orphan recovery
// inspects every row marked uploaded in the SQLite cache, not just a bounded
// prefix. Rows left marked uploaded are skipped forever by incremental imports,
// even though the cleaner already removed their PostgreSQL rows and S3 objects.
func TestRecoverOrphanedSQLiteState_AllUploadedRows(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	testEmail := "orphan-recovery@demo.com"
	createSimpleTestAccount(t, rdb, testEmail, "testpassword123")

	maildirPath := filepath.Join(t.TempDir(), "testmaildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755); err != nil {
			t.Fatalf("Failed to create maildir structure: %v", err)
		}
	}

	// Import a few real messages: their cached rows must survive recovery.
	const liveCount = 3
	for n := 0; n < liveCount; n++ {
		filename := fmt.Sprintf("1600000000.M%dP1.host:2,S", n)
		content := fmt.Sprintf("Subject: Live message %d\r\n\r\nBody %d", n, n)
		if err := os.WriteFile(filepath.Join(maildirPath, "cur", filename), []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create message file: %v", err)
		}
	}

	options := ImporterOptions{Incremental: true}
	importer, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	if err := importer.Run(); err != nil { // Run closes the importer
		t.Fatalf("Initial import failed: %v", err)
	}

	// Reopen the cache and seed rows marked uploaded that have no PostgreSQL
	// counterpart: exactly the state left behind after the cleaner purged
	// expunged messages and their S3 objects.
	importer, err = NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to reopen importer: %v", err)
	}
	defer importer.Close()

	const orphanCount = 1200
	tx, err := importer.sqliteDB.Begin()
	if err != nil {
		t.Fatalf("Failed to begin SQLite transaction: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded, s3_uploaded_at)
		VALUES (?, ?, ?, ?, 'INBOX', 1, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("Failed to prepare seed statement: %v", err)
	}
	for n := 0; n < orphanCount; n++ {
		filename := fmt.Sprintf("1700000000.M%dP1.host:2,S", n)
		hash := fmt.Sprintf("%064x", n)
		if _, err := stmt.Exec(filepath.Join(maildirPath, "cur", filename), filename, hash, 100); err != nil {
			t.Fatalf("Failed to seed row %d: %v", n, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Failed to commit seed transaction: %v", err)
	}

	if err := importer.recoverOrphanedSQLiteState(); err != nil {
		t.Fatalf("recoverOrphanedSQLiteState failed: %v", err)
	}

	// Every orphan must be reset, and only the orphans.
	var stillUploaded int
	if err := importer.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1").Scan(&stillUploaded); err != nil {
		t.Fatalf("Failed to count uploaded rows: %v", err)
	}
	if stillUploaded != liveCount {
		t.Errorf("Expected %d rows still marked uploaded, got %d: recovery either left orphans behind (incremental import silently skips them) or reset live messages", liveCount, stillUploaded)
	}

	var resetLive int
	if err := importer.sqliteDB.QueryRow(
		"SELECT COUNT(*) FROM messages WHERE s3_uploaded = 0 AND filename LIKE '1600000000.%'").Scan(&resetLive); err != nil {
		t.Fatalf("Failed to count reset live rows: %v", err)
	}
	if resetLive != 0 {
		t.Errorf("Recovery reset %d live messages that are present in PostgreSQL", resetLive)
	}
}
