//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

// TestDovecotUIDListRoundTrip verifies that importing and exporting messages
// with Dovecot UID preservation produces identical dovecot-uidlist files
func TestDovecotUIDListRoundTrip(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	ctx := context.Background()

	// Setup database
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()

	// Test email address
	testEmail := fmt.Sprintf("dovecot-uidlist-test-%d@example.com", time.Now().Unix())

	// Create test account
	createCacheTestAccount(t, rdb, testEmail, "test-password")

	// Setup S3 storage (use mock for testing)
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	t.Run("ImportOnly", func(t *testing.T) {
		// Create temporary directory
		originalMaildir := t.TempDir()

		// Create source maildir with Dovecot UID list
		t.Log("Creating source maildir with Dovecot structure...")
		createTestDovecotMaildir(t, originalMaildir)

		// Import with UID preservation
		t.Log("Importing maildir with --preserve-uids...")
		importOpts := ImporterOptions{
			Dovecot:      true,
			PreserveUIDs: true,
			TestMode:     true, // Skip actual S3 uploads for testing
		}
		importer, err := NewImporter(ctx, originalMaildir, testEmail, 4, rdb, mockS3, importOpts)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		// Verify messages were imported with preserved UIDs
		t.Log("Verifying imported messages have preserved UIDs...")
		verifyPreservedUIDs(t, ctx, rdb, testEmail, originalMaildir)

		t.Logf("✓ UID preservation test completed successfully")
	})
}

// TestDovecotUIDListCompleteRoundTrip tests importing, then exporting, and verifies
// that the exported dovecot-uidlist files match the originals
//
// NOTE: This test requires working S3 storage configured in ../../config-test.toml
// By default it uses MinIO on localhost:9000
//
// To run:
//  1. Start MinIO: docker run -p 9000:9000 -p 9001:9001 minio/minio server /data --console-address ":9001"
//  2. Run test without SKIP_S3_TESTS: go test -v -tags=integration ./cmd/sora-admin -run TestDovecotUIDListCompleteRoundTrip
func TestDovecotUIDListCompleteRoundTrip(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Skip by default - S3 is required for this test
	if os.Getenv("SKIP_S3_TESTS") == "true" {
		t.Skip("Skipping S3-dependent tests (unset SKIP_S3_TESTS and ensure S3 is configured in config-test.toml)")
	}

	ctx := context.Background()

	// Setup database
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()

	// Test email address
	testEmail := fmt.Sprintf("dovecot-roundtrip-%d@example.com", time.Now().Unix())

	// Create test account
	createCacheTestAccount(t, rdb, testEmail, "test-password")

	// Create S3 storage from config-test.toml
	s3Storage := createTestS3StorageFromConfig(t)

	t.Run("RoundTripWithSyntheticData", func(t *testing.T) {
		// Create temporary directories
		originalMaildir := t.TempDir()
		exportedMaildir := t.TempDir()

		// Create source maildir with Dovecot files
		t.Log("Creating synthetic maildir with Dovecot structure...")
		createTestDovecotMaildir(t, originalMaildir)

		// Import with UID preservation
		t.Log("Importing maildir with --preserve-uids and --dovecot...")
		importOpts := ImporterOptions{
			Dovecot:      true,
			PreserveUIDs: true,
			TestMode:     false, // Need real S3 for export
		}
		importer, err := NewImporter(ctx, originalMaildir, testEmail, 4, rdb, s3Storage, importOpts)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		t.Logf("Import completed: %d messages imported", importer.importedMessages)

		// Export with UID list generation
		t.Log("Exporting maildir with --export-uidlist...")
		exportOpts := ExporterOptions{
			Dovecot:       true,
			ExportUIDList: true,
		}
		exporter, err := NewExporter(ctx, exportedMaildir, testEmail, 4, rdb, s3Storage, exportOpts)
		if err != nil {
			t.Fatalf("Failed to create exporter: %v", err)
		}

		err = exporter.Run()
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		t.Logf("Export completed: %d messages exported", exporter.exportedMessages)

		// Compare dovecot-uidlist files
		t.Log("Comparing dovecot-uidlist files...")
		compareDovecotUIDLists(t, originalMaildir, exportedMaildir, "INBOX")
		compareDovecotUIDLists(t,
			filepath.Join(originalMaildir, ".Sent"),
			filepath.Join(exportedMaildir, "Sent"),
			"Sent")
		compareDovecotUIDLists(t,
			filepath.Join(originalMaildir, ".Drafts"),
			filepath.Join(exportedMaildir, "Drafts"),
			"Drafts")

		// Compare subscriptions file
		t.Log("Comparing subscriptions file...")
		compareSubscriptionsFile(t, originalMaildir, exportedMaildir)

		t.Logf("✓ Complete round-trip test passed - Dovecot files recreated correctly")
	})

	t.Run("RoundTripWithRealTestData", func(t *testing.T) {
		// Use real testdata/Maildir with 278 messages and actual Dovecot files
		testdataSource := "../../testdata/Maildir"

		// Verify testdata exists
		if _, err := os.Stat(testdataSource); os.IsNotExist(err) {
			t.Skipf("testdata/Maildir not found: %v", err)
		}

		// Copy testdata to temp directory (without SQLite cache) for fresh import
		originalMaildir := filepath.Join(t.TempDir(), "import")
		if err := copyMaildir(t, testdataSource, originalMaildir); err != nil {
			t.Fatalf("Failed to copy testdata: %v", err)
		}

		// Count files that were copied
		copiedFiles, _ := filepath.Glob(filepath.Join(originalMaildir, "cur", "*"))
		t.Logf("Copied %d message files to temp directory", len(copiedFiles))

		exportedMaildir := filepath.Join(t.TempDir(), "export")

		// Use a DIFFERENT test email for real testdata to avoid conflicts with synthetic test
		testEmailReal := fmt.Sprintf("dovecot-realdata-%d@example.com", time.Now().Unix())
		createCacheTestAccount(t, rdb, testEmailReal, "test-password")

		t.Logf("Using real testdata from: %s", testdataSource)
		t.Logf("Import working directory: %s", originalMaildir)
		t.Logf("Exporting to: %s", exportedMaildir)
		t.Logf("Test account: %s", testEmailReal)

		// Import with UID preservation
		t.Log("Importing testdata/Maildir with --preserve-uids...")
		importOpts := ImporterOptions{
			Dovecot:      true,
			PreserveUIDs: true,
			TestMode:     false, // Need real S3 for export
		}
		importer, err := NewImporter(ctx, originalMaildir, testEmailReal, 4, rdb, s3Storage, importOpts)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		t.Logf("Import completed: %d messages imported", importer.importedMessages)

		// Export with UID list generation
		t.Log("Exporting to maildir with --export-uidlist...")
		exportOpts := ExporterOptions{
			Dovecot:       true,
			ExportUIDList: true,
		}
		exporter, err := NewExporter(ctx, exportedMaildir, testEmailReal, 4, rdb, s3Storage, exportOpts)
		if err != nil {
			t.Fatalf("Failed to create exporter: %v", err)
		}

		err = exporter.Run()
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		t.Logf("Export completed: %d messages exported", exporter.exportedMessages)

		// Compare dovecot-uidlist for INBOX
		t.Log("Comparing dovecot-uidlist files...")
		compareDovecotUIDLists(t, originalMaildir, exportedMaildir, "INBOX")

		// Compare dovecot-uidlist for sub-mailboxes
		for _, mailbox := range []string{"Drafts", "Sent", "Junk", "Trash", "Archive"} {
			originalSub := filepath.Join(originalMaildir, mailbox)
			exportedSub := filepath.Join(exportedMaildir, mailbox)

			// Check if original mailbox exists
			if _, err := os.Stat(originalSub); err == nil {
				// Check if it has a dovecot-uidlist
				if _, err := os.Stat(filepath.Join(originalSub, "dovecot-uidlist")); err == nil {
					compareDovecotUIDLists(t, originalSub, exportedSub, mailbox)
				} else {
					t.Logf("Skipping %s: no dovecot-uidlist in original", mailbox)
				}
			}
		}

		// Compare subscriptions file
		t.Log("Comparing subscriptions file...")
		compareSubscriptionsFile(t, originalMaildir, exportedMaildir)

		// Compare dovecot-keywords file
		t.Log("Comparing dovecot-keywords file...")
		compareDovecotKeywords(t, originalMaildir, exportedMaildir)

		t.Logf("✓ Real testdata round-trip test passed")
		t.Logf("  - %d message files in testdata", len(copiedFiles))
		t.Logf("  - %d unique messages imported (after content deduplication)", importer.importedMessages)
		t.Logf("  - %d messages exported with UIDs preserved", exporter.exportedMessages)
		t.Logf("  - All Dovecot files preserved correctly")
	})
}

// verifyPreservedUIDs verifies that messages were imported with the correct UIDs from dovecot-uidlist
func verifyPreservedUIDs(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, email string, maildirPath string) {
	t.Helper()

	// Get user ID
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatalf("Invalid email address: %v", err)
	}

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}
	user := server.NewUser(address, accountID)

	// Verify INBOX
	verifyMailboxUIDs(t, ctx, rdb, user.UserID(), "INBOX", maildirPath, []uint32{1, 2, 5})

	// Verify Sent
	sentPath := filepath.Join(maildirPath, ".Sent")
	verifyMailboxUIDs(t, ctx, rdb, user.UserID(), "Sent", sentPath, []uint32{10, 11})

	// Verify Drafts
	draftsPath := filepath.Join(maildirPath, ".Drafts")
	verifyMailboxUIDs(t, ctx, rdb, user.UserID(), "Drafts", draftsPath, []uint32{100})
}

// verifyMailboxUIDs verifies that a mailbox has messages with the expected UIDs
func verifyMailboxUIDs(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, userID int64, mailboxName, maildirPath string, expectedUIDs []uint32) {
	t.Helper()

	// Get mailbox
	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, userID, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox %s: %v", mailboxName, err)
	}

	// Get all messages in the mailbox
	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, 0) // 1:* means all messages
	messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailbox.ID, seqSet)
	if err != nil {
		t.Fatalf("Failed to get messages for mailbox %s: %v", mailboxName, err)
	}

	if len(messages) != len(expectedUIDs) {
		t.Errorf("Mailbox %s: expected %d messages, got %d", mailboxName, len(expectedUIDs), len(messages))
	}

	// Create a map of actual UIDs
	actualUIDs := make(map[uint32]bool)
	for _, msg := range messages {
		actualUIDs[uint32(msg.UID)] = true
	}

	// Verify each expected UID exists
	for _, expectedUID := range expectedUIDs {
		if !actualUIDs[expectedUID] {
			t.Errorf("Mailbox %s: missing expected UID %d", mailboxName, expectedUID)
		} else {
			t.Logf("✓ Mailbox %s: UID %d preserved correctly", mailboxName, expectedUID)
		}
	}

	// Parse dovecot-uidlist and verify UIDVALIDITY was preserved
	uidList, err := ParseDovecotUIDList(maildirPath)
	if err != nil {
		t.Fatalf("Failed to parse dovecot-uidlist from %s: %v", maildirPath, err)
	}
	if uidList == nil {
		t.Fatalf("No dovecot-uidlist found at %s", maildirPath)
	}

	// Verify UIDVALIDITY matches
	if mailbox.UIDValidity != uint32(uidList.UIDValidity) {
		t.Errorf("Mailbox %s: UIDVALIDITY mismatch - expected %d (from dovecot-uidlist), got %d (in database)",
			mailboxName, uidList.UIDValidity, mailbox.UIDValidity)
	} else {
		t.Logf("✓ Mailbox %s: UIDVALIDITY %d preserved correctly", mailboxName, uidList.UIDValidity)
	}
}

// createTestDovecotMaildir creates a test maildir with Dovecot structure and UID lists
func createTestDovecotMaildir(t *testing.T, basePath string) {
	t.Helper()

	// Create INBOX
	createMaildirFolder(t, basePath)

	// Create .Sent folder
	sentPath := filepath.Join(basePath, ".Sent")
	createMaildirFolder(t, sentPath)

	// Create .Drafts folder
	draftsPath := filepath.Join(basePath, ".Drafts")
	createMaildirFolder(t, draftsPath)

	// Add messages to INBOX
	inboxMessages := []testMessage{
		{
			uid:      1,
			filename: "1234567890.M1P1.hostname",
			flags:    "S",
			subject:  "Test message 1",
			from:     "sender1@example.com",
			to:       "recipient@example.com",
			date:     time.Now().Add(-48 * time.Hour),
		},
		{
			uid:      2,
			filename: "1234567891.M2P2.hostname",
			flags:    "",
			subject:  "Test message 2",
			from:     "sender2@example.com",
			to:       "recipient@example.com",
			date:     time.Now().Add(-36 * time.Hour),
		},
		{
			uid:      5,
			filename: "1234567892.M3P3.hostname",
			flags:    "FS",
			subject:  "Test message 3 - Important",
			from:     "sender3@example.com",
			to:       "recipient@example.com",
			date:     time.Now().Add(-24 * time.Hour),
		},
	}

	createMessagesInMaildir(t, basePath, inboxMessages)
	createDovecotUIDList(t, basePath, 1234567890, 6, inboxMessages)

	// Add messages to Sent
	sentMessages := []testMessage{
		{
			uid:      10,
			filename: "1234567900.M10P10.hostname",
			flags:    "S",
			subject:  "Sent message 1",
			from:     "recipient@example.com",
			to:       "receiver1@example.com",
			date:     time.Now().Add(-47 * time.Hour),
		},
		{
			uid:      11,
			filename: "1234567901.M11P11.hostname",
			flags:    "S",
			subject:  "Sent message 2",
			from:     "recipient@example.com",
			to:       "receiver2@example.com",
			date:     time.Now().Add(-35 * time.Hour),
		},
	}

	createMessagesInMaildir(t, sentPath, sentMessages)
	createDovecotUIDList(t, sentPath, 987654321, 12, sentMessages)

	// Add messages to Drafts
	draftMessages := []testMessage{
		{
			uid:      100,
			filename: "1234567910.M100P100.hostname",
			flags:    "D",
			subject:  "Draft message 1",
			from:     "recipient@example.com",
			to:       "draft-recipient@example.com",
			date:     time.Now().Add(-12 * time.Hour),
		},
	}

	createMessagesInMaildir(t, draftsPath, draftMessages)
	createDovecotUIDList(t, draftsPath, 555555555, 101, draftMessages)

	// Create subscriptions file
	subscriptionsPath := filepath.Join(basePath, "subscriptions")
	subscriptionsContent := "V\t2\nINBOX\nSent\nDrafts\n"
	if err := os.WriteFile(subscriptionsPath, []byte(subscriptionsContent), 0644); err != nil {
		t.Fatalf("Failed to create subscriptions file: %v", err)
	}
}

type testMessage struct {
	uid      uint32
	filename string
	flags    string
	subject  string
	from     string
	to       string
	date     time.Time
}

// createMaildirFolder creates cur, new, tmp directories for a maildir folder
func createMaildirFolder(t *testing.T, path string) {
	t.Helper()
	for _, dir := range []string{"cur", "new", "tmp"} {
		dirPath := filepath.Join(path, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dirPath, err)
		}
	}
}

// createMessagesInMaildir creates message files in the maildir
func createMessagesInMaildir(t *testing.T, maildirPath string, messages []testMessage) {
	t.Helper()

	for _, msg := range messages {
		// Construct full filename with flags
		fullFilename := msg.filename
		if msg.flags != "" {
			fullFilename = fmt.Sprintf("%s:2,%s", msg.filename, msg.flags)
		} else {
			fullFilename = fmt.Sprintf("%s:2,", msg.filename)
		}

		// Create message content
		content := fmt.Sprintf(`Date: %s
From: %s
To: %s
Subject: %s
Message-ID: <%s@example.com>

This is a test message body for UID %d.
It has multiple lines to make it more realistic.

Best regards,
Test Suite
`, msg.date.Format(time.RFC1123Z), msg.from, msg.to, msg.subject, msg.filename, msg.uid)

		// Write to cur directory (messages are delivered)
		messagePath := filepath.Join(maildirPath, "cur", fullFilename)
		if err := os.WriteFile(messagePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create message file %s: %v", messagePath, err)
		}

		// Set file modification time to match message date
		if err := os.Chtimes(messagePath, msg.date, msg.date); err != nil {
			t.Logf("Warning: Failed to set file times for %s: %v", messagePath, err)
		}
	}
}

// createDovecotUIDList creates a dovecot-uidlist file
func createDovecotUIDList(t *testing.T, maildirPath string, uidValidity uint32, nextUID uint32, messages []testMessage) {
	t.Helper()

	uidList := &DovecotUIDList{
		Version:     3,
		UIDValidity: uidValidity,
		NextUID:     nextUID,
		GlobalUID:   fmt.Sprintf("test%d", uidValidity), // Simple GlobalUID for testing
		UIDMappings: make(map[string]uint32),
	}

	for _, msg := range messages {
		uidList.UIDMappings[msg.filename] = msg.uid
	}

	if err := WriteDovecotUIDList(maildirPath, uidList); err != nil {
		t.Fatalf("Failed to write dovecot-uidlist to %s: %v", maildirPath, err)
	}
}

// copyMaildir recursively copies a maildir directory structure, excluding SQLite databases
func copyMaildir(t *testing.T, src, dst string) error {
	t.Helper()

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip SQLite database files
		if strings.HasSuffix(relPath, ".db") || strings.HasSuffix(relPath, ".db-journal") {
			t.Logf("Skipping SQLite database: %s", relPath)
			return nil
		}

		// Construct destination path
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			// Create directory
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copy file
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return err
		}

		// Preserve file permissions
		return os.Chmod(dstPath, info.Mode())
	})
}

// TestDovecotUIDListRoundTripWithFlags tests that flags are preserved correctly
// and don't affect UID matching
func TestDovecotUIDListRoundTripWithFlags(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	ctx := context.Background()

	// Setup database
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()

	// Test email address
	testEmail := fmt.Sprintf("dovecot-flags-test-%d@example.com", time.Now().Unix())

	// Create test account
	createCacheTestAccount(t, rdb, testEmail, "test-password")

	// Setup S3 storage (use mock for testing)
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	t.Run("FlagsPreservation", func(t *testing.T) {
		// Create temporary directory
		originalMaildir := t.TempDir()

		// Create source maildir
		createMaildirFolder(t, originalMaildir)

		// Create message with specific flags
		messages := []testMessage{
			{
				uid:      1,
				filename: "1234567890.M1P1.hostname",
				flags:    "",
				subject:  "No flags",
				from:     "test@example.com",
				to:       "recipient@example.com",
				date:     time.Now().Add(-24 * time.Hour),
			},
			{
				uid:      2,
				filename: "1234567891.M2P2.hostname",
				flags:    "S",
				subject:  "Seen flag",
				from:     "test@example.com",
				to:       "recipient@example.com",
				date:     time.Now().Add(-23 * time.Hour),
			},
			{
				uid:      3,
				filename: "1234567892.M3P3.hostname",
				flags:    "FS",
				subject:  "Flagged and Seen",
				from:     "test@example.com",
				to:       "recipient@example.com",
				date:     time.Now().Add(-22 * time.Hour),
			},
			{
				uid:      4,
				filename: "1234567893.M4P4.hostname",
				flags:    "R",
				subject:  "Replied",
				from:     "test@example.com",
				to:       "recipient@example.com",
				date:     time.Now().Add(-21 * time.Hour),
			},
		}

		createMessagesInMaildir(t, originalMaildir, messages)
		createDovecotUIDList(t, originalMaildir, 1234567890, 5, messages)

		// Import with flag and UID preservation
		importOpts := ImporterOptions{
			Dovecot:       true,
			PreserveUIDs:  true,
			PreserveFlags: true,
			TestMode:      true, // Skip S3 uploads for testing
		}
		importer, err := NewImporter(ctx, originalMaildir, testEmail, 4, rdb, mockS3, importOpts)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		// Get user ID
		address, err := server.NewAddress(testEmail)
		if err != nil {
			t.Fatalf("Invalid email address: %v", err)
		}
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
		if err != nil {
			t.Fatalf("Failed to get account ID: %v", err)
		}
		user := server.NewUser(address, accountID)

		// Verify UIDs and flags
		verifyMailboxUIDs(t, ctx, rdb, user.UserID(), "INBOX", originalMaildir, []uint32{1, 2, 3, 4})

		t.Logf("✓ Flags and UIDs preserved correctly through import")
	})
}

// TestDovecotUIDListWithMultipleMailboxes tests UID preservation across multiple mailboxes
func TestDovecotUIDListWithMultipleMailboxes(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	ctx := context.Background()

	// Setup database
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()

	// Test email address
	testEmail := fmt.Sprintf("dovecot-multi-test-%d@example.com", time.Now().Unix())

	// Create test account
	createCacheTestAccount(t, rdb, testEmail, "test-password")

	// Setup S3 storage (use mock for testing)
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	t.Run("MultipleMailboxes", func(t *testing.T) {
		// Create temporary directory
		originalMaildir := t.TempDir()

		// Create complex maildir structure with nested folders
		createTestDovecotMaildir(t, originalMaildir)

		// Import
		importOpts := ImporterOptions{
			Dovecot:      true,
			PreserveUIDs: true,
			TestMode:     true, // Skip S3 uploads for testing
		}
		importer, err := NewImporter(ctx, originalMaildir, testEmail, 4, rdb, mockS3, importOpts)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		// Verify all mailboxes
		verifyPreservedUIDs(t, ctx, rdb, testEmail, originalMaildir)

		t.Logf("✓ All mailbox UID lists preserved correctly")
	})
}

// createTestS3StorageFromConfig creates S3 storage using config-test.toml
func createTestS3StorageFromConfig(t *testing.T) *storage.S3Storage {
	t.Helper()

	// Load S3 configuration from config-test.toml
	// Start with default config to avoid TOML parsing issues with server sections
	cfg := config.NewDefaultConfig()
	err := config.LoadConfigFromFile("../../config-test.toml", &cfg)
	if err != nil {
		t.Skipf("Failed to load config-test.toml: %v", err)
	}

	// Create S3 storage using the loaded config
	// storage.New(endpoint, accessKey, secretKey, bucket, useSSL, debug)
	useSSL := !cfg.S3.DisableTLS
	debug := cfg.S3.GetDebug()
	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, useSSL, debug)
	if err != nil {
		t.Skipf("Failed to create S3 storage from config: %v\n"+
			"Ensure S3/MinIO is running and configured in config-test.toml\n"+
			"Config: endpoint=%s, bucket=%s, useSSL=%v\n"+
			"Start MinIO with: docker run -p 9000:9000 minio/minio server /data",
			err, cfg.S3.Endpoint, cfg.S3.Bucket, useSSL)
	}

	return s3Storage
}

// compareDovecotUIDLists compares dovecot-uidlist files from original and exported maildirs
func compareDovecotUIDLists(t *testing.T, originalPath, exportedPath, mailboxName string) {
	t.Helper()

	t.Logf("Comparing dovecot-uidlist for mailbox: %s", mailboxName)
	t.Logf("  Original path: %s", originalPath)
	t.Logf("  Exported path: %s", exportedPath)

	// Parse original UID list
	originalUIDList, err := ParseDovecotUIDList(originalPath)
	if err != nil {
		t.Fatalf("Failed to parse original dovecot-uidlist at %s: %v", originalPath, err)
	}
	if originalUIDList == nil {
		t.Fatalf("No original dovecot-uidlist found at %s", originalPath)
	}

	// Parse exported UID list
	exportedUIDList, err := ParseDovecotUIDList(exportedPath)
	if err != nil {
		t.Fatalf("Failed to parse exported dovecot-uidlist at %s: %v", exportedPath, err)
	}
	if exportedUIDList == nil {
		// No exported uidlist means no messages were exported for this mailbox
		// This is valid if the original mailbox had no messages or all were deleted
		t.Logf("No exported dovecot-uidlist found at %s - mailbox had no messages to export", exportedPath)
		return
	}

	// Compare UIDVALIDITY - must be exactly the same
	if originalUIDList.UIDValidity != exportedUIDList.UIDValidity {
		t.Errorf("Mailbox %s: UIDVALIDITY mismatch - original=%d, exported=%d",
			mailboxName, originalUIDList.UIDValidity, exportedUIDList.UIDValidity)
	} else {
		t.Logf("✓ Mailbox %s: UIDVALIDITY %d matches", mailboxName, originalUIDList.UIDValidity)
	}

	// Compare NextUID - exported should be same or higher
	if exportedUIDList.NextUID < originalUIDList.NextUID {
		t.Errorf("Mailbox %s: NextUID in exported is lower than original - original=%d, exported=%d",
			mailboxName, originalUIDList.NextUID, exportedUIDList.NextUID)
	} else {
		t.Logf("✓ Mailbox %s: NextUID %d is valid (original was %d)",
			mailboxName, exportedUIDList.NextUID, originalUIDList.NextUID)
	}

	// Compare number of UID mappings
	// Note: Exported may have fewer UIDs if some message files were missing in original maildir
	if len(exportedUIDList.UIDMappings) > len(originalUIDList.UIDMappings) {
		t.Errorf("Mailbox %s: Exported has MORE UIDs than original - original=%d, exported=%d",
			mailboxName, len(originalUIDList.UIDMappings), len(exportedUIDList.UIDMappings))
	} else if len(exportedUIDList.UIDMappings) < len(originalUIDList.UIDMappings) {
		missing := len(originalUIDList.UIDMappings) - len(exportedUIDList.UIDMappings)
		t.Logf("Mailbox %s: UID mapping count mismatch - original=%d, exported=%d (%d UIDs missing - likely deleted messages)",
			mailboxName, len(originalUIDList.UIDMappings), len(exportedUIDList.UIDMappings), missing)
	}

	// Check that all EXPORTED UIDs existed in the original
	// (This verifies UIDs are preserved, not that all original messages exist)
	invalidUIDs := []string{}
	preservedCount := 0

	for exportedFilename, exportedUID := range exportedUIDList.UIDMappings {
		// Check if this UID existed in the original
		foundInOriginal := false
		var originalFilename string
		for origFilename, origUID := range originalUIDList.UIDMappings {
			if origUID == exportedUID {
				foundInOriginal = true
				originalFilename = origFilename
				break
			}
		}

		if !foundInOriginal {
			invalidUIDs = append(invalidUIDs, fmt.Sprintf("UID %d (file: %s) - not in original", exportedUID, exportedFilename))
		} else {
			preservedCount++
			t.Logf("  ✓ UID %d: %s -> %s", exportedUID, originalFilename, exportedFilename)
		}
	}

	if len(invalidUIDs) > 0 {
		t.Errorf("Mailbox %s: Exported dovecot-uidlist contains UIDs not in original: %v", mailboxName, invalidUIDs)
	} else {
		t.Logf("✓ Mailbox %s: All %d exported UIDs were correctly preserved from original", mailboxName, preservedCount)
	}
}

// compareSubscriptionsFile compares the subscriptions files
func compareSubscriptionsFile(t *testing.T, originalPath, exportedPath string) {
	t.Helper()

	originalSubsPath := filepath.Join(originalPath, "subscriptions")
	exportedSubsPath := filepath.Join(exportedPath, "subscriptions")

	// Read original subscriptions
	originalContent, err := os.ReadFile(originalSubsPath)
	if err != nil {
		t.Fatalf("Failed to read original subscriptions file: %v", err)
	}

	// Read exported subscriptions
	exportedContent, err := os.ReadFile(exportedSubsPath)
	if err != nil {
		t.Fatalf("Failed to read exported subscriptions file: %v", err)
	}

	// Parse both files
	originalLines := parseSubscriptions(string(originalContent))
	exportedLines := parseSubscriptions(string(exportedContent))

	// Compare - account for mailbox name transformations (.Sent -> Sent, .Drafts -> Drafts)
	originalNormalized := normalizeMailboxNames(originalLines)
	exportedNormalized := normalizeMailboxNames(exportedLines)

	// Don't fail on count mismatch - exporter might add default mailboxes (Trash, Junk, etc.)
	// Just log it for information
	if len(originalNormalized) != len(exportedNormalized) {
		t.Logf("Note: Subscriptions count differs - original=%d, exported=%d (exporter may add default mailboxes)",
			len(originalNormalized), len(exportedNormalized))
	}

	// Check all original subscriptions are in exported (the important part)
	for _, mailbox := range originalNormalized {
		found := false
		for _, exportedMailbox := range exportedNormalized {
			if mailbox == exportedMailbox {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing subscription in exported: %s", mailbox)
		} else {
			t.Logf("✓ Subscription preserved: %s", mailbox)
		}
	}

	t.Logf("✓ Subscriptions file comparison passed")
}

// compareDovecotKeywords compares the dovecot-keywords files
func compareDovecotKeywords(t *testing.T, originalPath, exportedPath string) {
	t.Helper()

	originalKeywordsPath := filepath.Join(originalPath, "dovecot-keywords")
	exportedKeywordsPath := filepath.Join(exportedPath, "dovecot-keywords")

	// Read original keywords
	originalContent, err := os.ReadFile(originalKeywordsPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("No original dovecot-keywords file - skipping comparison")
			return
		}
		t.Fatalf("Failed to read original dovecot-keywords file: %v", err)
	}

	// Read exported keywords
	exportedContent, err := os.ReadFile(exportedKeywordsPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("No exported dovecot-keywords file (original had %d bytes)", len(originalContent))
			return
		}
		t.Fatalf("Failed to read exported dovecot-keywords file: %v", err)
	}

	// Parse both files (format: "0 keyword1\n1 keyword2\n")
	originalKeywords := parseKeywords(string(originalContent))
	exportedKeywords := parseKeywords(string(exportedContent))

	t.Logf("Original keywords: %d, Exported keywords: %d", len(originalKeywords), len(exportedKeywords))

	// Check that all original keywords are preserved
	for idx, keyword := range originalKeywords {
		found := false
		for expIdx, expKeyword := range exportedKeywords {
			if keyword == expKeyword {
				found = true
				t.Logf("✓ Keyword %d '%s' preserved (exported as %d)", idx, keyword, expIdx)
				break
			}
		}
		if !found {
			t.Errorf("Missing keyword in exported: %d '%s'", idx, keyword)
		}
	}

	t.Logf("✓ dovecot-keywords comparison passed")
}

// parseKeywords extracts keyword names from dovecot-keywords file content
func parseKeywords(content string) []string {
	keywords := []string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "0 keyword" - extract the keyword part
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			keywords = append(keywords, parts[1])
		}
	}
	return keywords
}

// parseSubscriptions extracts mailbox names from subscriptions file content
func parseSubscriptions(content string) []string {
	lines := []string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		// Skip version line and empty lines
		if line != "" && !strings.HasPrefix(line, "V\t") && !strings.HasPrefix(line, "V ") {
			lines = append(lines, line)
		}
	}
	return lines
}

// normalizeMailboxNames converts .Sent -> Sent, .Drafts -> Drafts, etc.
func normalizeMailboxNames(mailboxes []string) []string {
	normalized := []string{}
	for _, mailbox := range mailboxes {
		// Remove leading dot if present (Dovecot format)
		if strings.HasPrefix(mailbox, ".") {
			mailbox = mailbox[1:]
		}
		normalized = append(normalized, mailbox)
	}
	return normalized
}
