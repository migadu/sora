//go:build integration

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
	_ "modernc.org/sqlite"
)

// TestSQLiteMigration tests that existing SQLite databases are migrated correctly
func TestSQLiteMigration(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupMigrationTestDatabase(t)
	defer rdb.Close()

	testEmail := "user@demo.com"
	testPassword := "testpassword123"
	createMigrationTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary directory
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Create an OLD-STYLE SQLite database (without s3_uploaded columns)
	createOldStyleDatabase(t, maildirPath)

	// Verify old database doesn't have s3_uploaded column
	t.Run("VerifyOldSchema", func(t *testing.T) {
		verifyColumnDoesNotExist(t, maildirPath, "s3_uploaded")
	})

	// Setup S3 storage
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	// Create importer - this should trigger migration
	t.Run("MigrateOnImporterCreation", func(t *testing.T) {
		options := ImporterOptions{
			DryRun:    true,
			CleanupDB: false,
		}

		importer, err := NewImporter(maildirPath, testEmail, 1, rdb, mockS3, options)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}
		defer importer.Close()

		t.Log("Importer created successfully, migration should have occurred")
	})

	// Verify new columns exist after migration
	t.Run("VerifyNewSchema", func(t *testing.T) {
		verifyColumnExists(t, maildirPath, "s3_uploaded")
		verifyColumnExists(t, maildirPath, "s3_uploaded_at")
	})

	// Verify existing data is preserved
	t.Run("VerifyDataPreserved", func(t *testing.T) {
		verifyOldDataPreserved(t, maildirPath)
	})

	// Verify existing messages are marked as uploaded (s3_uploaded = 1)
	t.Run("VerifyExistingMarkedAsUploaded", func(t *testing.T) {
		verifyExistingMarkedAsUploaded(t, maildirPath)
	})

	t.Log("✅ SQLite migration test passed!")
}

func createOldStyleDatabase(t *testing.T, maildirPath string) {
	t.Helper()

	// Create maildir structure
	if err := os.MkdirAll(filepath.Join(maildirPath, "cur"), 0755); err != nil {
		t.Fatalf("Failed to create maildir: %v", err)
	}

	// Create old-style SQLite database
	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite db: %v", err)
	}
	defer db.Close()

	// Create OLD schema (without s3_uploaded columns)
	_, err = db.Exec(`
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
		CREATE INDEX idx_mailbox ON messages(mailbox);
		CREATE INDEX idx_hash ON messages(hash);
	`)
	if err != nil {
		t.Fatalf("Failed to create old-style table: %v", err)
	}

	// Insert some test data
	_, err = db.Exec(`
		INSERT INTO messages (path, filename, hash, size, mailbox)
		VALUES
			('/test/path1', 'msg1.eml', 'hash1', 1000, 'INBOX'),
			('/test/path2', 'msg2.eml', 'hash2', 2000, 'INBOX'),
			('/test/path3', 'msg3.eml', 'hash3', 3000, 'Sent')
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	t.Log("Created old-style SQLite database with 3 test messages")
}

func verifyColumnExists(t *testing.T, maildirPath, columnName string) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite db: %v", err)
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow(`
		SELECT COUNT(*) > 0
		FROM pragma_table_info('messages')
		WHERE name=?
	`, columnName).Scan(&exists)
	if err != nil {
		t.Fatalf("Failed to check for column %s: %v", columnName, err)
	}

	if !exists {
		t.Errorf("Column %s does not exist after migration", columnName)
	} else {
		t.Logf("✓ Column %s exists", columnName)
	}
}

func verifyColumnDoesNotExist(t *testing.T, maildirPath, columnName string) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite db: %v", err)
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow(`
		SELECT COUNT(*) > 0
		FROM pragma_table_info('messages')
		WHERE name=?
	`, columnName).Scan(&exists)
	if err != nil {
		t.Fatalf("Failed to check for column %s: %v", columnName, err)
	}

	if exists {
		t.Errorf("Column %s should not exist in old database", columnName)
	} else {
		t.Logf("✓ Column %s correctly does not exist in old schema", columnName)
	}
}

func verifyOldDataPreserved(t *testing.T, maildirPath string) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite db: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count messages: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 messages after migration, got %d", count)
	} else {
		t.Logf("✓ All 3 messages preserved after migration")
	}

	// Verify specific data
	var hash string
	err = db.QueryRow("SELECT hash FROM messages WHERE filename = 'msg1.eml'").Scan(&hash)
	if err != nil {
		t.Fatalf("Failed to query specific message: %v", err)
	}

	if hash != "hash1" {
		t.Errorf("Expected hash 'hash1', got '%s'", hash)
	} else {
		t.Logf("✓ Specific message data preserved correctly")
	}
}

func verifyExistingMarkedAsUploaded(t *testing.T, maildirPath string) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite db: %v", err)
	}
	defer db.Close()

	// Check that all existing messages have s3_uploaded = 1 (already on S3)
	var allUploaded bool
	err = db.QueryRow(`
		SELECT COUNT(*) = (SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1)
		FROM messages
	`).Scan(&allUploaded)
	if err != nil {
		t.Fatalf("Failed to check uploaded status: %v", err)
	}

	if !allUploaded {
		t.Error("Not all migrated messages have s3_uploaded = 1")
	} else {
		t.Logf("✓ All migrated messages have s3_uploaded = 1 (already on S3)")
	}

	// Check that s3_uploaded_at is NOT NULL for existing messages
	var allHaveTimestamp bool
	err = db.QueryRow(`
		SELECT COUNT(*) = (SELECT COUNT(*) FROM messages WHERE s3_uploaded_at IS NOT NULL)
		FROM messages
	`).Scan(&allHaveTimestamp)
	if err != nil {
		t.Fatalf("Failed to check timestamp values: %v", err)
	}

	if !allHaveTimestamp {
		t.Error("Not all migrated messages have s3_uploaded_at timestamp")
	} else {
		t.Logf("✓ All migrated messages have s3_uploaded_at timestamp")
	}
}

func setupMigrationTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	cfg := &config.DatabaseConfig{
		LogQueries: false,
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Skipf("Failed to connect to test database: %v", err)
	}

	return rdb
}

func createMigrationTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) {
	t.Helper()

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	err := rdb.CreateAccountWithRetry(context.Background(), req)
	if err != nil {
		// Account might already exist from previous test
		t.Logf("Note: Account creation returned: %v", err)
	}
}
