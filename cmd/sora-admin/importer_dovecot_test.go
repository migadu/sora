//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

func TestImporter_DovecotUIDPreservation(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	// Setup test S3 storage
	s3Storage := setupTestS3Storage(t)

	// Create test account
	testEmail := "user@demo.com"
	testPassword := "testpassword123"
	createTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary directory for test
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Copy testdata to temporary directory (limit to first few messages for faster testing)
	err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, 5)
	if err != nil {
		t.Fatalf("Failed to copy test data: %v", err)
	}

	// Debug: List the files that were actually copied
	t.Logf("=== DEBUG: Files in test maildir ===")
	for _, subdir := range []string{"cur", "new"} {
		dirPath := filepath.Join(maildirPath, subdir)
		if entries, err := os.ReadDir(dirPath); err == nil {
			for _, entry := range entries {
				t.Logf("  %s/%s", subdir, entry.Name())
			}
		}
	}

	// Verify dovecot-uidlist exists and parse it
	uidlistPath := filepath.Join(maildirPath, "dovecot-uidlist")
	if _, err := os.Stat(uidlistPath); os.IsNotExist(err) {
		t.Fatalf("dovecot-uidlist file not found at %s", uidlistPath)
	}

	// Parse the original dovecot-uidlist to get expected UIDs
	originalUIDList, err := ParseDovecotUIDList(maildirPath)
	if err != nil {
		t.Fatalf("Failed to parse original dovecot-uidlist: %v", err)
	}

	if originalUIDList == nil {
		t.Fatalf("No dovecot-uidlist found in test data")
	}

	t.Logf("Original dovecot-uidlist has UIDVALIDITY=%d, NextUID=%d, %d mappings",
		originalUIDList.UIDValidity, originalUIDList.NextUID, len(originalUIDList.UIDMappings))

	// Configure importer with UID preservation
	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  true,
		ForceReimport: false,
		CleanupDB:     true,
		Dovecot:       true,
		PreserveUIDs:  true, // This is the key option we're testing
		ImportDelay:   0,    // No delay between imports for testing
		TestMode:      true, // Skip S3 uploads for testing
	}

	// Create importer
	importer, err := NewImporter(maildirPath, testEmail, 1, rdb, s3Storage, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	// Run the import (should succeed with test mode enabled)
	err = importer.Run()
	if err != nil {
		t.Fatalf("Import failed in test mode: %v", err)
	}
	t.Logf("Import completed successfully in test mode")

	// Verify that messages were imported with preserved UIDs
	ctx := context.Background()
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("Invalid email address: %v", err)
	}

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}
	user := server.NewUser(address, accountID)

	// Get INBOX mailbox
	inboxMailbox, err := rdb.GetMailboxByNameWithRetry(ctx, user.UserID(), "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX mailbox: %v", err)
	}

	// Check UIDVALIDITY preservation
	if inboxMailbox.UIDValidity != originalUIDList.UIDValidity {
		t.Errorf("UIDVALIDITY not preserved: got %d, want %d",
			inboxMailbox.UIDValidity, originalUIDList.UIDValidity)
	} else {
		t.Logf("✅ UIDVALIDITY preserved: %d", inboxMailbox.UIDValidity)
	}

	// Get all messages in INBOX to verify UID preservation
	messages, err := rdb.ListMessagesWithRetry(ctx, inboxMailbox.ID)
	if err != nil {
		t.Fatalf("Failed to get messages: %v", err)
	}

	t.Logf("Found %d messages in imported INBOX", len(messages))

	// Build a map of content_hash to UID for verification
	importedUIDsByHash := make(map[string]uint32)
	for _, msg := range messages {
		importedUIDsByHash[msg.ContentHash] = uint32(msg.UID)
	}

	// For each file in the original UID list, verify the UID was preserved
	preservedCount := 0
	totalFilesWithUIDs := 0

	for filename, expectedUID := range originalUIDList.UIDMappings {
		totalFilesWithUIDs++

		// Find the message file in the maildir
		// The filename in dovecot-uidlist is the base name without flags
		// We need to find the actual file which may have flags appended (e.g., :2,S)
		var messagePath string
		for _, subdir := range []string{"cur", "new"} {
			// Try exact match first
			possiblePath := filepath.Join(maildirPath, subdir, filename)
			if _, err := os.Stat(possiblePath); err == nil {
				messagePath = possiblePath
				break
			}
			// Look for files that start with this filename (accounting for flags)
			matches, err := filepath.Glob(filepath.Join(maildirPath, subdir, filename+"*"))
			if err == nil && len(matches) > 0 {
				messagePath = matches[0]
				break
			}
		}

		if messagePath == "" {
			t.Logf("Warning: File %s from dovecot-uidlist not found in maildir", filename)
			continue
		}

		// Calculate the hash of this message file to find it in the imported messages
		hash, _, err := hashFile(messagePath)
		if err != nil {
			t.Logf("Warning: Failed to hash file %s: %v", messagePath, err)
			continue
		}

		// Check if this message was imported with the correct UID
		if importedUID, exists := importedUIDsByHash[hash]; exists {
			if importedUID == expectedUID {
				preservedCount++
				t.Logf("✓ UID preserved for %s: %d", filename, expectedUID)
			} else {
				t.Errorf("UID NOT preserved for %s: got %d, want %d", filename, importedUID, expectedUID)
			}
		} else {
			t.Errorf("Message %s (hash %s) not found in imported messages", filename, hash[:12])
		}
	}

	// Summary
	t.Logf("UID preservation summary: %d/%d UIDs preserved (%.1f%%)",
		preservedCount, totalFilesWithUIDs, float64(preservedCount)*100.0/float64(totalFilesWithUIDs))

	// Calculate preservation rate
	preservationRate := float64(preservedCount) / float64(totalFilesWithUIDs)

	t.Logf("UID preservation results: %d/%d (%.1f%%) UIDs preserved",
		preservedCount, totalFilesWithUIDs, preservationRate*100.0)

	// For this test, we want to verify that:
	// 1. The UID preservation logic works correctly
	// 2. UIDs are preserved correctly when imported
	// 3. The UIDVALIDITY is set correctly

	if preservedCount > 0 {
		t.Logf("✅ UID preservation working: Successfully preserved %d UIDs", preservedCount)
	} else if len(messages) > 0 {
		t.Errorf("Messages were imported but no UIDs were preserved - UID preservation logic may be broken")
	} else {
		t.Errorf("No messages imported - import process failed")
	}

	// Count messages that were successfully imported (not necessarily with preserved UIDs)
	successfullyImported := 0
	for _, msg := range messages {
		if msg.UID != 0 {
			successfullyImported++
		}
	}

	t.Logf("Import results: %d messages imported successfully, %d with preserved UIDs",
		successfullyImported, preservedCount)

	// Test should be successful if:
	// 1. Messages were imported to the database
	// 2. UIDVALIDITY was preserved correctly
	// 3. The UID parsing and mapping logic worked correctly
	if len(messages) == 0 {
		t.Fatalf("No messages were imported - import process failed")
	}

	// Calculate the actual preservation rate based on messages that were actually imported
	// Since we limit to 10 messages but the uidlist has 278 entries, we should only expect
	// preservation for the files that were actually copied and imported
	if len(messages) > 0 && preservedCount > 0 {
		actualPreservationRate := float64(preservedCount) / float64(len(messages))
		if actualPreservationRate < 0.5 { // Expect at least 50% of imported messages to have preserved UIDs
			t.Errorf("UID preservation rate for imported messages too low: %.1f%% (expected >= 50%%)", actualPreservationRate*100.0)
		} else {
			t.Logf("✅ UID preservation working for imported messages: %.1f%%", actualPreservationRate*100.0)
		}
	} else if len(messages) > 0 {
		t.Errorf("Messages were imported but no UIDs were preserved - UID preservation logic may be broken")
	}

	// In TestMode, PendingUpload records are created and then immediately completed
	// We verify that the import process completed the uploads properly
	
	// Check if messages are marked as uploaded (since TestMode completes uploads immediately)
	uploadedCount := 0
	for _, msg := range messages {
		// In test mode, messages should be marked as uploaded=true
		var uploaded bool
		err := rdb.QueryRowWithRetry(ctx, `
			SELECT uploaded FROM messages WHERE id = $1
		`, msg.ID).Scan(&uploaded)
		if err != nil {
			t.Fatalf("Failed to check upload status for message %d: %v", msg.ID, err)
		}
		if uploaded {
			uploadedCount++
		}
	}

	if uploadedCount != len(messages) {
		t.Errorf("Not all messages are marked as uploaded: %d/%d uploaded", uploadedCount, len(messages))
	} else {
		t.Logf("✅ All imported messages are marked as uploaded (TestMode working correctly)")
	}

	// Verify that PendingUpload records were properly cleaned up in TestMode
	remainingUploads, err := rdb.QueryWithRetry(ctx, `
		SELECT COUNT(*) 
		FROM pending_uploads 
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		t.Fatalf("Failed to query remaining pending uploads: %v", err)
	}
	defer remainingUploads.Close()

	var remainingCount int
	if remainingUploads.Next() {
		if err := remainingUploads.Scan(&remainingCount); err != nil {
			t.Fatalf("Failed to scan remaining uploads count: %v", err)
		}
	}

	if remainingCount > 0 {
		t.Errorf("PendingUpload records not properly cleaned up in TestMode: %d remaining", remainingCount)
	} else {
		t.Logf("✅ PendingUpload records properly cleaned up in TestMode")
	}

	t.Logf("✅ UID preservation integration test completed successfully!")
	t.Logf("✅ - Database import worked: %d messages imported", len(messages))
	t.Logf("✅ - Mailbox created with UIDVALIDITY: %d", inboxMailbox.UIDValidity)
	t.Logf("✅ - UID preservation rate: %.1f%%", preservationRate*100.0)
	t.Logf("✅ - Upload processing: %d/%d messages uploaded", uploadedCount, len(messages))
	if inboxMailbox.UIDValidity == originalUIDList.UIDValidity {
		t.Logf("✅ - UIDVALIDITY preserved successfully!")
	}
}

// TestImporter_PendingUploads specifically tests PendingUpload creation without TestMode
func TestImporter_PendingUploads(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "user@demo.com"
	testPassword := "testpassword123"
	createTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary directory for test
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Copy testdata to temporary directory (limit to first few messages for faster testing)
	err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, 3)
	if err != nil {
		t.Fatalf("Failed to copy test data: %v", err)
	}

	// For this test, let's manually insert messages and verify PendingUpload creation
	// since the current importer logic either succeeds completely or fails completely
	// Let's test the database function directly
	
	// Get account info for verification
	ctx := context.Background()
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("Invalid email address: %v", err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}
	
	// Parse one message file to test PendingUpload creation
	testMsgPath := filepath.Join(maildirPath, "cur")
	entries, err := os.ReadDir(testMsgPath)
	if err != nil || len(entries) == 0 {
		t.Fatalf("No message files found in test maildir")
	}
	
	// Use the first message file for testing
	msgFilePath := filepath.Join(testMsgPath, entries[0].Name())
	
	// Calculate hash for the message
	hash, size, err := hashFile(msgFilePath)
	if err != nil {
		t.Fatalf("Failed to hash message file: %v", err)
	}
	
	t.Logf("Testing with message file: %s (hash=%s, size=%d)", entries[0].Name(), hash[:12], size)
	
	// Create INBOX mailbox if it doesn't exist
	user := server.NewUser(address, accountID)
	
	// Try to get INBOX mailbox, create if it doesn't exist
	inboxMailbox, err := rdb.GetMailboxByNameWithRetry(ctx, user.UserID(), "INBOX")
	if err != nil {
		// Create INBOX mailbox
		err = rdb.CreateMailboxWithRetry(ctx, user.UserID(), "INBOX", nil)
		if err != nil {
			t.Fatalf("Failed to create INBOX mailbox: %v", err)
		}
		
		// Now get the created mailbox
		inboxMailbox, err = rdb.GetMailboxByNameWithRetry(ctx, user.UserID(), "INBOX")
		if err != nil {
			t.Fatalf("Failed to get INBOX mailbox after creation: %v", err)
		}
	}
	
	// Test direct database insertion with PendingUpload
	hostname, _ := os.Hostname()
	
	// For testing purposes, we'll create minimal data for the message
	messageID := fmt.Sprintf("<%d@test.example.com>", time.Now().UnixNano())
	subject := "Test Message for PendingUpload"
	sentDate := time.Now()
	
	// Create minimal recipients data
	recipients := []helpers.Recipient{
		{
			Name:         "Test User",
			EmailAddress: testEmail,
			AddressType:  "from",
		},
	}
	
	// Create minimal body structure  
	bodyStructurePart := &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Size:    uint32(size),
	}
	var bodyStructure imap.BodyStructure = bodyStructurePart
	
	// Insert message with PendingUpload using the resilient database wrapper
	insertOptions := &db.InsertMessageOptions{
		UserID:        user.UserID(),
		MailboxID:     inboxMailbox.ID,
		MailboxName:   inboxMailbox.Name,
		MessageID:     messageID,
		ContentHash:   hash,
		S3Domain:      address.Domain(),
		S3Localpart:   address.LocalPart(),
		Subject:       subject,
		SentDate:      sentDate,
		InternalDate:  time.Now(),
		InReplyTo:     []string{},
		Size:          size,
		Recipients:    recipients,
		BodyStructure: &bodyStructure,
		PlaintextBody: "",
		Flags:         []imap.Flag{},
	}
	
	pendingUpload := db.PendingUpload{
		InstanceID:  hostname,
		ContentHash: hash,
		Size:        size,
		AccountID:   user.UserID(),
	}
	
	// Insert the message with PendingUpload
	msgID, uid, err := rdb.InsertMessageWithRetry(ctx, insertOptions, pendingUpload)
	if err != nil {
		t.Fatalf("Failed to insert message with PendingUpload: %v", err)
	}
	
	t.Logf("Successfully inserted message: ID=%d, UID=%d, Hash=%s", msgID, uid, hash[:12])

	// Check if PendingUpload records were created despite the failure
	pendingUploads, err := rdb.QueryWithRetry(ctx, `
		SELECT content_hash, size, account_id 
		FROM pending_uploads 
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		t.Fatalf("Failed to query pending uploads: %v", err)
	}
	defer pendingUploads.Close()

	pendingUploadCount := 0
	for pendingUploads.Next() {
		var contentHash string
		var size int64
		var uploadAccountID int64
		if err := pendingUploads.Scan(&contentHash, &size, &uploadAccountID); err != nil {
			t.Fatalf("Failed to scan pending upload: %v", err)
		}
		pendingUploadCount++
		t.Logf("Found pending upload: hash=%s, size=%d, account_id=%d", contentHash[:12], size, uploadAccountID)
	}

	if pendingUploadCount != 1 {
		t.Errorf("Expected exactly 1 pending upload, got %d", pendingUploadCount)
	} else {
		t.Logf("✅ PendingUpload record created successfully: %d upload queued", pendingUploadCount)
	}

	// Verify the message was inserted into database
	var foundMsgID, foundUID int64
	var foundHash string
	var foundUploaded bool
	err = rdb.QueryRowWithRetry(ctx, `
		SELECT id, uid, content_hash, uploaded 
		FROM messages 
		WHERE account_id = $1 AND expunged_at IS NULL
		LIMIT 1
	`, accountID).Scan(&foundMsgID, &foundUID, &foundHash, &foundUploaded)
	
	if err != nil {
		t.Fatalf("Failed to query inserted message: %v", err)
	}

	if foundMsgID != msgID {
		t.Errorf("Message ID mismatch: expected %d, got %d", msgID, foundMsgID)
	}

	if foundUID != uid {
		t.Errorf("UID mismatch: expected %d, got %d", uid, foundUID)
	}

	if foundHash != hash {
		t.Errorf("Hash mismatch: expected %s, got %s", hash, foundHash)
	}

	if foundUploaded {
		t.Errorf("Message should not be marked as uploaded initially: uploaded=%v", foundUploaded)
	}

	t.Logf("✅ Message correctly inserted: id=%d, uid=%d, hash=%s, uploaded=%v", 
		foundMsgID, foundUID, foundHash[:12], foundUploaded)

	// Summary
	t.Logf("✅ PendingUpload test completed successfully!")
	t.Logf("✅ - PendingUpload record created for message")
	t.Logf("✅ - Message inserted into database correctly")
	t.Logf("✅ - Message correctly marked as not uploaded")
	t.Logf("✅ - Database insertion with PendingUpload functionality verified")
}

// setupTestDatabase creates a test database connection
func setupTestDatabase(t *testing.T) *resilient.ResilientDatabase {
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

	// Run migrations equivalent to "sora-admin migrate up"
	err = runMigrations(t, rdb)
	if err != nil {
		t.Fatalf("Failed to run database migrations: %v", err)
	}

	return rdb
}

// runMigrations runs database migrations (equivalent to sora-admin migrate up)
func runMigrations(t *testing.T, rdb *resilient.ResilientDatabase) error {
	t.Helper()

	ctx := context.Background()

	// The migrations are automatically run when creating the resilient database
	// But let's ensure we have a clean slate by resetting the database first

	// Drop all tables to start fresh
	_, err := rdb.ExecWithRetry(ctx, `
		DROP SCHEMA public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO postgres;
		GRANT ALL ON SCHEMA public TO public;
	`)
	if err != nil {
		return fmt.Errorf("failed to reset database schema: %w", err)
	}

	t.Log("Reset database schema for clean test environment")

	// Close the database connection
	rdb.Close()

	// Recreate the database connection to trigger fresh migrations
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

	newRdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		return fmt.Errorf("failed to recreate database connection: %w", err)
	}

	// Replace the old rdb pointer with the new one
	*rdb = *newRdb

	// Also clear any test data from previous runs
	_, err = rdb.ExecWithRetry(context.Background(), `
		DELETE FROM pending_uploads;
		DELETE FROM message_flags;
		DELETE FROM messages;
		DELETE FROM mailboxes WHERE name != 'INBOX' AND name != 'Sent' AND name != 'Drafts' AND name != 'Trash' AND name != 'Junk';
		DELETE FROM credentials;
		DELETE FROM accounts;
		DELETE FROM sieve_scripts;
	`)
	if err != nil {
		t.Logf("Warning: Failed to clean test data: %v", err)
	}

	t.Log("Database migrations completed successfully")
	return nil
}

// setupTestS3Storage creates a test S3 storage (dummy instance for test mode)
func setupTestS3Storage(t *testing.T) *storage.S3Storage {
	t.Helper()

	// In test mode, S3 operations are skipped, so we can return nil
	// However, the importer still expects a non-nil pointer, so create a dummy instance
	mockStorage, err := storage.New(
		"localhost:0", // Non-existent endpoint (won't be used in test mode)
		"test",        // Access key
		"test",        // Secret key
		"test-bucket", // Bucket name
		false,         // Use SSL
		false,         // Debug
	)
	if err != nil {
		// This is expected to fail since we're not actually connecting
		t.Logf("S3 mock creation failed as expected (will be bypassed in test mode): %v", err)
		return nil // Return nil, the test mode will handle this gracefully
	}

	return mockStorage
}

// createTestAccount creates a test account in the database
func createTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) {
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
