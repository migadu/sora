//go:build integration

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// TestImportExportCycle tests the complete import/export cycle with SQLite caching
func TestImportExportCycle(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database with fresh schema
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "user@demo.com"
	testPassword := "testpassword123"
	createCacheTestAccount(t, rdb, testEmail, testPassword)

	// Setup S3 storage (use test mode to skip actual S3)
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	// Setup temporary directories
	tempDir := t.TempDir()
	importMaildir := filepath.Join(tempDir, "import")

	// Copy test data for import
	err = copyCacheTestMaildir(t, "../../testdata/Maildir", importMaildir, 10)
	if err != nil {
		t.Fatalf("Failed to copy test data: %v", err)
	}

	// Test 1: Initial import from maildir to S3
	t.Run("InitialImport", func(t *testing.T) {
		testInitialImport(t, importMaildir, testEmail, rdb, mockS3)
	})

	// Verify SQLite cache state after import
	t.Run("VerifyCacheAfterImport", func(t *testing.T) {
		verifySQLiteCache(t, importMaildir, 10, 10)
	})

	// Test 2: Re-import the same maildir (should skip everything)
	t.Run("ReimportShouldSkip", func(t *testing.T) {
		testReimportSkipsAll(t, importMaildir, testEmail, rdb, mockS3)
	})

	// Test 3: Add new messages and verify incremental import
	t.Run("IncrementalImport", func(t *testing.T) {
		testIncrementalImport(t, importMaildir, testEmail, rdb, mockS3)
	})

	t.Log("✅ Complete import/export/cache cycle test passed!")
}

func testInitialImport(t *testing.T, maildirPath, email string, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage) {
	t.Helper()

	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  false,
		ForceReimport: false,
		CleanupDB:     false, // Keep DB for inspection
		TestMode:      true,  // Skip actual S3 uploads
	}

	importer, err := NewImporter(context.Background(), maildirPath, email, 1, rdb, s3, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	startTime := time.Now()
	err = importer.Run()
	duration := time.Since(startTime)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	t.Logf("Initial import took: %v", duration)
	t.Logf("Imported: %d, Skipped: %d, Failed: %d",
		importer.importedMessages, importer.skippedMessages, importer.failedMessages)

	if importer.importedMessages == 0 {
		t.Fatal("Expected some messages to be imported")
	}

	if importer.failedMessages > 0 {
		t.Errorf("Expected no failures, got %d", importer.failedMessages)
	}
}

func testReimportSkipsAll(t *testing.T, maildirPath, email string, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage) {
	t.Helper()

	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  false,
		ForceReimport: false,
		CleanupDB:     false,
		TestMode:      true,
	}

	importer, err := NewImporter(context.Background(), maildirPath, email, 1, rdb, s3, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	startTime := time.Now()
	err = importer.Run()
	duration := time.Since(startTime)
	if err != nil {
		t.Fatalf("Reimport failed: %v", err)
	}

	t.Logf("Reimport took: %v (should be fast)", duration)
	t.Logf("Imported: %d, Skipped: %d, Failed: %d",
		importer.importedMessages, importer.skippedMessages, importer.failedMessages)

	// All messages should be skipped (already on S3)
	if importer.importedMessages != 0 {
		t.Errorf("Expected 0 messages to be imported on reimport, got %d", importer.importedMessages)
	}

	// Should complete quickly (under 2 seconds for 10 messages)
	if duration > 2*time.Second {
		t.Errorf("Reimport took too long: %v (expected < 2s), cache may not be working", duration)
	}
}

func testIncrementalImport(t *testing.T, maildirPath, email string, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage) {
	t.Helper()

	// Copy 3 additional messages to the maildir
	additionalMessages := 3
	err := copyCacheTestMaildir(t, "../../testdata/Maildir", maildirPath, 10+additionalMessages)
	if err != nil {
		t.Fatalf("Failed to add new messages: %v", err)
	}

	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  false,
		ForceReimport: false,
		CleanupDB:     false,
		TestMode:      true,
	}

	importer, err := NewImporter(context.Background(), maildirPath, email, 1, rdb, s3, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	startTime := time.Now()
	err = importer.Run()
	duration := time.Since(startTime)
	if err != nil {
		t.Fatalf("Incremental import failed: %v", err)
	}

	t.Logf("Incremental import took: %v", duration)
	t.Logf("Imported: %d, Skipped: %d, Failed: %d",
		importer.importedMessages, importer.skippedMessages, importer.failedMessages)

	// Should import only the new messages
	if importer.importedMessages != int64(additionalMessages) {
		t.Errorf("Expected %d messages to be imported incrementally, got %d",
			additionalMessages, importer.importedMessages)
	}

	// Should complete quickly
	if duration > 2*time.Second {
		t.Errorf("Incremental import took too long: %v (expected < 2s)", duration)
	}
}

func verifySQLiteCache(t *testing.T, maildirPath string, expectedTotal, expectedUploaded int) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite cache: %v", err)
	}
	defer db.Close()

	var totalCount, uploadedCount int
	err = db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&totalCount)
	if err != nil {
		t.Fatalf("Failed to count total messages: %v", err)
	}

	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1").Scan(&uploadedCount)
	if err != nil {
		t.Fatalf("Failed to count uploaded messages: %v", err)
	}

	t.Logf("SQLite cache state: %d total messages, %d marked as uploaded", totalCount, uploadedCount)

	if totalCount != expectedTotal {
		t.Errorf("Expected %d total messages in cache, got %d", expectedTotal, totalCount)
	}

	if uploadedCount != expectedUploaded {
		t.Errorf("Expected %d uploaded messages in cache, got %d", expectedUploaded, uploadedCount)
	}

	// Verify schema has s3_uploaded column
	rows, err := db.Query("PRAGMA table_info(messages)")
	if err != nil {
		t.Fatalf("Failed to get table info: %v", err)
	}
	defer rows.Close()

	hasS3UploadedColumn := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue sql.NullString
		err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan column info: %v", err)
		}
		if name == "s3_uploaded" {
			hasS3UploadedColumn = true
			t.Logf("Found s3_uploaded column: type=%s", ctype)
		}
	}

	if !hasS3UploadedColumn {
		t.Error("SQLite cache is missing s3_uploaded column")
	}
}

func setupCacheTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	// Reset database schema for clean test
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Skipf("Failed to connect to test database: %v", err)
	}

	ctx := context.Background()
	_, err = rdb.ExecWithRetry(ctx, `
		DROP SCHEMA public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO postgres;
		GRANT ALL ON SCHEMA public TO public;
	`)
	if err != nil {
		t.Fatalf("Failed to reset database schema: %v", err)
	}

	rdb.Close()

	// Recreate connection to trigger migrations
	rdb, err = resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatalf("Failed to recreate database connection: %v", err)
	}

	t.Log("Database setup completed with fresh schema")
	return rdb
}

func createCacheTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) {
	t.Helper()

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	err := rdb.CreateAccountWithRetry(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to create test account %s: %v", email, err)
	}

	t.Logf("Created test account: %s", email)
}

func copyCacheTestMaildir(t *testing.T, src, dst string, messageLimit int) error {
	t.Helper()

	// Create destination directory structure
	for _, subdir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dst, subdir), 0755); err != nil {
			return err
		}
	}

	// Copy dovecot files
	dovecotFiles := []string{"dovecot-uidlist", "dovecot-keywords", "subscriptions"}
	for _, file := range dovecotFiles {
		srcFile := filepath.Join(src, file)
		dstFile := filepath.Join(dst, file)
		if _, err := os.Stat(srcFile); err == nil {
			data, err := os.ReadFile(srcFile)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dstFile, data, 0644); err != nil {
				return err
			}
		}
	}

	// Copy messages from cur directory
	curDir := filepath.Join(src, "cur")
	entries, err := os.ReadDir(curDir)
	if err != nil {
		return err
	}

	copied := 0
	for _, entry := range entries {
		if copied >= messageLimit {
			break
		}
		if !entry.IsDir() {
			srcFile := filepath.Join(curDir, entry.Name())
			dstFile := filepath.Join(dst, "cur", entry.Name())
			data, err := os.ReadFile(srcFile)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dstFile, data, 0644); err != nil {
				return err
			}
			copied++
		}
	}

	t.Logf("Copied %d messages to %s", copied, dst)
	return nil
}
