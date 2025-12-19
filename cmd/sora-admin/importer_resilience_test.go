//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/storage"
)

func TestImporter_Resilience(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database with fresh schema
	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "resilience@demo.com"
	testPassword := "testpassword123"
	createSimpleTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary directory for test
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Create a minimal maildir structure
	err := os.MkdirAll(filepath.Join(maildirPath, "cur"), 0755)
	if err != nil {
		t.Fatalf("Failed to create maildir structure: %v", err)
	}
	err = os.MkdirAll(filepath.Join(maildirPath, "new"), 0755)
	if err != nil {
		t.Fatalf("Failed to create maildir structure: %v", err)
	}
	err = os.MkdirAll(filepath.Join(maildirPath, "tmp"), 0755)
	if err != nil {
		t.Fatalf("Failed to create maildir structure: %v", err)
	}

	// Create a dummy message file
	// Format: unique_id:2,flags
	originalFilename := "1234567890.M123P456.host:2,S"
	originalPath := filepath.Join(maildirPath, "cur", originalFilename)
	err = os.WriteFile(originalPath, []byte("Subject: Test Message\r\n\r\nBody"), 0644)
	if err != nil {
		t.Fatalf("Failed to create dummy message: %v", err)
	}

	// Create dovecot-uidlist
	uidListContent := "3 V123456 N100\n1 :1234567890.M123P456.host:2,S\n"
	err = os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create dovecot-uidlist: %v", err)
	}

	// Create mock S3 storage
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	// Configure importer
	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  false,
		ForceReimport: false,
		CleanupDB:     true,
		Dovecot:       true,
		PreserveUIDs:  true,
	}

	importer, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, mockS3, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	// Test findMovedFile
	t.Run("FindMovedFile", func(t *testing.T) {
		// Rename the file to simulate flag change (S -> SR)
		newFilename := "1234567890.M123P456.host:2,SR"
		newPath := filepath.Join(maildirPath, "cur", newFilename)
		err := os.Rename(originalPath, newPath)
		if err != nil {
			t.Fatalf("Failed to rename file: %v", err)
		}

		// Try to find the file using the original path
		foundPath, found := importer.findMovedFile(originalPath)
		if !found {
			t.Errorf("Expected to find moved file, but didn't")
		}
		if foundPath != newPath {
			t.Errorf("Expected found path to be %s, got %s", newPath, foundPath)
		}

		// Clean up: move it back
		err = os.Rename(newPath, originalPath)
		if err != nil {
			t.Fatalf("Failed to restore file: %v", err)
		}
	})

	// Test findMovedFile from new to cur
	t.Run("FindMovedFile_NewToCur", func(t *testing.T) {
		// Create file in new
		filename := "1234567891.M123P456.host"
		oldPath := filepath.Join(maildirPath, "new", filename)
		err := os.WriteFile(oldPath, []byte("body"), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		// Move to cur with flags
		newPath := filepath.Join(maildirPath, "cur", filename+":2,S")
		err = os.Rename(oldPath, newPath)
		if err != nil {
			t.Fatalf("Failed to rename: %v", err)
		}

		// findMovedFile only supports dovecot-style renames (flags-only changes)
		// where both the old and new filenames contain the ":2," separator.
		// new->cur moves don't have that separator in the original filename,
		// so this case is intentionally not supported.
		if _, found := importer.findMovedFile(oldPath); found {
			t.Errorf("Expected NOT to find moved file (new->cur) with findMovedFile")
		}
	})

	// Test syncMailboxState
	t.Run("SyncMailboxState", func(t *testing.T) {
		// Ensure mailbox exists
		err := importer.scanMaildir()
		if err != nil {
			t.Fatalf("scanMaildir failed: %v", err)
		}

		// Run syncMailboxState
		err = importer.syncMailboxState()
		if err != nil {
			t.Fatalf("syncMailboxState failed: %v", err)
		}

		// Verify UIDVALIDITY in database
		// We need to query the database directly
		db := rdb.GetOperationalDatabase()
		var uidValidity uint32
		err = db.WritePool.QueryRow(context.Background(),
			"SELECT uid_validity FROM mailboxes WHERE name = 'INBOX' AND account_id = (SELECT account_id FROM credentials WHERE LOWER(address) = LOWER($1) AND primary_identity = TRUE)",
			testEmail).Scan(&uidValidity)
		if err != nil {
			t.Fatalf("Failed to query UIDVALIDITY: %v", err)
		}

		if uidValidity != 123456 {
			t.Errorf("Expected UIDVALIDITY 123456, got %d", uidValidity)
		}
	})
}
