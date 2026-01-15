//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/server"
)

// TestImporter_DuplicateMessageHandling tests that the importer gracefully handles
// duplicate messages (unique constraint violations) without aborting the entire batch.
func TestImporter_DuplicateMessageHandling(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "duplicates@demo.com"
	testPassword := "testpassword123"
	createSimpleTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary maildir
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Create maildir structure
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

	// Create test messages with the SAME Message-ID (to trigger unique constraint)
	message1 := []byte("Message-ID: <duplicate@test.com>\r\nSubject: First\r\n\r\nBody 1")
	message2 := []byte("Message-ID: <duplicate@test.com>\r\nSubject: Second\r\n\r\nBody 2")
	message3 := []byte("Message-ID: <unique@test.com>\r\nSubject: Third\r\n\r\nBody 3")

	err = os.WriteFile(filepath.Join(maildirPath, "cur", "msg1:2,S"), message1, 0644)
	if err != nil {
		t.Fatalf("Failed to create message 1: %v", err)
	}
	err = os.WriteFile(filepath.Join(maildirPath, "cur", "msg2:2,S"), message2, 0644)
	if err != nil {
		t.Fatalf("Failed to create message 2: %v", err)
	}
	err = os.WriteFile(filepath.Join(maildirPath, "cur", "msg3:2,S"), message3, 0644)
	if err != nil {
		t.Fatalf("Failed to create message 3: %v", err)
	}

	// Configure importer with batch size of 10 to process all messages in one batch
	// Use TestMode to skip S3 uploads (messages only stored in DB)
	options := ImporterOptions{
		DryRun:               false,
		PreserveFlags:        true,
		ShowProgress:         false,
		ForceReimport:        false,
		CleanupDB:            true,
		Dovecot:              false,
		PreserveUIDs:         false,
		BatchSize:            10,
		BatchTransactionMode: false, // Use individual transactions
		TestMode:             true,  // Skip S3 uploads
	}

	importer, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	// Run import
	err = importer.Run()
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify results
	// Expected:
	// - message1 imported successfully
	// - message2 skipped (duplicate Message-ID)
	// - message3 imported successfully
	// Total imported: 2, skipped: 1

	if importer.importedMessages != 2 {
		t.Errorf("Expected 2 imported messages, got %d", importer.importedMessages)
	}
	if importer.skippedMessages != 1 {
		t.Errorf("Expected 1 skipped message, got %d", importer.skippedMessages)
	}
	if importer.failedMessages != 0 {
		t.Errorf("Expected 0 failed messages, got %d", importer.failedMessages)
	}

	// Verify messages exist in database
	address, _ := server.NewAddress(testEmail)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	db := rdb.GetOperationalDatabase()
	var count int
	err = db.ReadPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL",
		accountID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query message count: %v", err)
	}

	if count != 2 {
		t.Errorf("Expected 2 messages in database, got %d", count)
	}
}

// TestImporter_ReimportExistingMessages tests importing when messages already exist
// (simulates running import twice on the same maildir)
func TestImporter_ReimportExistingMessages(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "reimport@demo.com"
	testPassword := "testpassword123"
	createSimpleTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary maildir
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Create maildir structure
	for _, dir := range []string{"cur", "new", "tmp"} {
		err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
		if err != nil {
			t.Fatalf("Failed to create maildir structure: %v", err)
		}
	}

	// Create test messages
	for i := 1; i <= 3; i++ {
		content := bytes.NewBuffer(nil)
		content.WriteString("Message-ID: <msg")
		content.WriteString(string(rune('0' + i)))
		content.WriteString("@test.com>\r\nSubject: Message ")
		content.WriteString(string(rune('0' + i)))
		content.WriteString("\r\n\r\nBody ")
		content.WriteString(string(rune('0' + i)))

		err := os.WriteFile(filepath.Join(maildirPath, "cur", "msg"+string(rune('0'+i))+":2,S"), content.Bytes(), 0644)
		if err != nil {
			t.Fatalf("Failed to create message %d: %v", i, err)
		}
	}

	// First import
	options := ImporterOptions{
		DryRun:               false,
		PreserveFlags:        true,
		ShowProgress:         false,
		ForceReimport:        false,
		CleanupDB:            false, // Keep SQLite DB for second run
		Dovecot:              false,
		PreserveUIDs:         false,
		BatchSize:            10,
		BatchTransactionMode: false,
		TestMode:             true, // Skip S3 uploads
	}

	importer1, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create first importer: %v", err)
	}

	err = importer1.Run()
	importer1.Close() // Close to release SQLite DB
	if err != nil {
		t.Fatalf("First import failed: %v", err)
	}

	if importer1.importedMessages != 3 {
		t.Errorf("First import: Expected 3 imported messages, got %d", importer1.importedMessages)
	}

	// Second import (should skip all messages as they're already in SQLite cache)
	importer2, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create second importer: %v", err)
	}
	defer importer2.Close()

	err = importer2.Run()
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}

	// Second run should skip everything (already in SQLite cache)
	if importer2.importedMessages != 0 {
		t.Errorf("Second import: Expected 0 imported messages, got %d", importer2.importedMessages)
	}

	// Verify database still has only 3 messages
	address, _ := server.NewAddress(testEmail)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	db := rdb.GetOperationalDatabase()
	var count int
	err = db.ReadPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL",
		accountID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query message count: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 messages in database after second import, got %d", count)
	}
}
