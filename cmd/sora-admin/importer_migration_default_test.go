package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// createPreMigrationCache writes a sora-maildir.db in the shape it had before the
// s3_uploaded columns existed, seeded with one row.
func createPreMigrationCache(t *testing.T, maildirPath string) {
	t.Helper()

	sqliteDB, err := sql.Open("sqlite", filepath.Join(maildirPath, "sora-maildir.db"))
	if err != nil {
		t.Fatalf("Failed to create legacy SQLite db: %v", err)
	}
	defer sqliteDB.Close()

	if _, err := sqliteDB.Exec(`
		CREATE TABLE messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL,
			filename TEXT NOT NULL,
			hash TEXT NOT NULL,
			size INTEGER NOT NULL,
			mailbox TEXT NOT NULL,
			UNIQUE(hash, mailbox),
			UNIQUE(filename, mailbox)
		);
	`); err != nil {
		t.Fatalf("Failed to create legacy table: %v", err)
	}

	if _, err := sqliteDB.Exec(`INSERT INTO messages (path, filename, hash, size, mailbox)
		VALUES ('/legacy/path', 'legacy.eml', 'legacyhash', 1000, 'INBOX')`); err != nil {
		t.Fatalf("Failed to seed legacy row: %v", err)
	}
}

// newMaildirWithPreMigrationCache builds a maildir holding a legacy cache and one
// message file that cache has never seen. It returns the maildir path and the filename.
func newMaildirWithPreMigrationCache(t *testing.T) (string, string) {
	t.Helper()

	maildirPath := filepath.Join(t.TempDir(), "testmaildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755); err != nil {
			t.Fatalf("Failed to create maildir structure: %v", err)
		}
	}

	createPreMigrationCache(t, maildirPath)

	const newFilename = "1700000000.M1P1.host:2,S"
	if err := os.WriteFile(filepath.Join(maildirPath, "cur", newFilename),
		[]byte("Subject: New message\r\n\r\nBody"), 0644); err != nil {
		t.Fatalf("Failed to create message file: %v", err)
	}

	return maildirPath, newFilename
}

// scanAndReadUploadedFlag scans the maildir and returns the s3_uploaded value the cache
// recorded for the named file.
func scanAndReadUploadedFlag(t *testing.T, maildirPath, filename string) int {
	t.Helper()

	importer, err := NewImporter(context.Background(), maildirPath, "migration-default@demo.com", 1, nil, nil, ImporterOptions{Incremental: true})
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	if err := importer.scanMaildir(); err != nil {
		t.Fatalf("scanMaildir failed: %v", err)
	}

	var uploaded int
	if err := importer.sqliteDB.QueryRow(
		`SELECT s3_uploaded FROM messages WHERE filename = ?`, filename).Scan(&uploaded); err != nil {
		t.Fatalf("Failed to read newly scanned row: %v", err)
	}
	return uploaded
}

// A cache created before the s3_uploaded column existed recorded every file the scan
// saw, not every file that was imported - the pre-migration schema had no upload
// tracking at all. Whatever the migration decides those legacy rows mean, that decision
// must not become the column default, because scanMaildir inserts newly discovered
// files without naming s3_uploaded and SQLite applies the column default to them.
//
// ADD COLUMN s3_uploaded INTEGER DEFAULT 1 makes that default permanent for the
// database file, so on a migrated cache every file found by a later scan is born
// "already uploaded" and the import - which selects WHERE s3_uploaded = 0 - never sees
// it. Orphan recovery only reconciles rows that exist before the scan runs, so the run
// that discovers the file imports nothing and reports success.
func TestSQLiteMigrationLeavesNewlyScannedFilesUnimported(t *testing.T) {
	maildirPath, newFilename := newMaildirWithPreMigrationCache(t)

	if uploaded := scanAndReadUploadedFlag(t, maildirPath, newFilename); uploaded != 0 {
		t.Errorf("newly scanned file has s3_uploaded = %d, want 0: the migrated column default marks "+
			"files as imported at scan time, so the import (WHERE s3_uploaded = 0) never picks them up", uploaded)
	}

	// The pre-existing rows keep their documented meaning: assumed imported, and left
	// for recoverOrphanedSQLiteState to reconcile against PostgreSQL.
	sqliteDB, err := sql.Open("sqlite", filepath.Join(maildirPath, "sora-maildir.db"))
	if err != nil {
		t.Fatalf("Failed to reopen cache: %v", err)
	}
	defer sqliteDB.Close()

	var legacyUploaded int
	if err := sqliteDB.QueryRow(
		`SELECT s3_uploaded FROM messages WHERE filename = 'legacy.eml'`).Scan(&legacyUploaded); err != nil {
		t.Fatalf("Failed to read legacy row: %v", err)
	}
	if legacyUploaded != 1 {
		t.Errorf("legacy row has s3_uploaded = %d, want 1", legacyUploaded)
	}
}

// The exporter migrates the very same {maildir}/sora-maildir.db, so a column default it
// bakes in is the default a later import inherits. Export-then-import into one maildir
// is the documented round trip, and it must not leave the importer blind to new files.
func TestExporterMigrationLeavesNewlyScannedFilesUnimported(t *testing.T) {
	maildirPath, newFilename := newMaildirWithPreMigrationCache(t)

	// Migrate the legacy cache through the exporter, not the importer.
	exporter, err := NewExporter(context.Background(), maildirPath, "migration-default@demo.com", 1, nil, nil, ExporterOptions{})
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("Failed to close exporter: %v", err)
	}

	if uploaded := scanAndReadUploadedFlag(t, maildirPath, newFilename); uploaded != 0 {
		t.Errorf("newly scanned file has s3_uploaded = %d, want 0: the exporter's migration left a "+
			"column default that hides new files from the next import", uploaded)
	}
}
