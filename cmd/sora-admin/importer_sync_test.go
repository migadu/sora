//go:build integration
// +build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/testutils"
)

// TestImporter_SynchronousUploadFlow tests that the importer:
// 1. Does NOT create pending_uploads entries
// 2. Marks messages as uploaded=TRUE immediately
// 3. Stores every body in S3, under the key its row references, as part of the
// import (TestImporter_S3FailurePreventsDBInsert covers an upload that fails)
func TestImporter_SynchronousUploadFlow(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := fmt.Sprintf("sync-test-%d@example.com", time.Now().Unix())
	testPassword := "testpassword123"
	createTestAccount(t, rdb, testEmail, testPassword)

	ctx := context.Background()

	// Get account ID
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("Invalid email address: %v", err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	t.Run("ImportWithS3CreatesNoQueueEntries", func(t *testing.T) {
		// Setup temporary directory for test
		tempDir := t.TempDir()
		maildirPath := filepath.Join(tempDir, "testmaildir")

		// Copy limited test data
		const messageCount = 3
		err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, messageCount)
		if err != nil {
			t.Fatalf("Failed to copy test data: %v", err)
		}

		// The importer uploads for real (no TestMode), into a file-based S3 mock.
		s3Mock, err := testutils.NewFileBasedS3Mock(filepath.Join(tempDir, "s3"))
		if err != nil {
			t.Fatalf("Failed to create S3 mock: %v", err)
		}

		importer, err := NewImporter(ctx, maildirPath, testEmail, 4, rdb, s3Mock, ImporterOptions{})
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}

		// Run import
		err = importer.Run()
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}

		// Verify NO pending_uploads were created
		var pendingCount int
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT COUNT(*) FROM pending_uploads WHERE account_id = $1
		`, accountID).Scan(&pendingCount)
		if err != nil {
			t.Fatalf("Failed to query pending_uploads: %v", err)
		}

		if pendingCount > 0 {
			t.Errorf("❌ Expected 0 pending_uploads entries, got %d (importer should NOT use queue)", pendingCount)
		} else {
			t.Logf("✅ No pending_uploads entries created (correct behavior)")
		}

		// Verify all messages are marked as uploaded=TRUE
		var uploadedCount, totalCount int
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT
				COUNT(*) FILTER (WHERE uploaded = TRUE) as uploaded_count,
				COUNT(*) as total_count
			FROM messages
			WHERE account_id = $1 AND expunged_at IS NULL
		`, accountID).Scan(&uploadedCount, &totalCount)
		if err != nil {
			t.Fatalf("Failed to query message upload status: %v", err)
		}

		if totalCount != messageCount {
			t.Fatalf("Expected %d imported messages, got %d", messageCount, totalCount)
		}
		if uploadedCount != totalCount {
			t.Errorf("❌ Expected all %d messages to be marked uploaded=TRUE, got %d", totalCount, uploadedCount)
		} else {
			t.Logf("✅ All %d messages marked as uploaded=TRUE immediately", totalCount)
		}

		// Every row's body is in S3, under the key the row names, with the content
		// its content_hash names.
		rows, err := rdb.QueryWithRetry(ctx, `
			SELECT s3_domain, s3_localpart, content_hash
			FROM messages
			WHERE account_id = $1 AND expunged_at IS NULL
		`, accountID)
		if err != nil {
			t.Fatalf("Failed to query message S3 keys: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var domain, localpart, hash string
			if err := rows.Scan(&domain, &localpart, &hash); err != nil {
				t.Fatalf("Failed to scan message S3 key: %v", err)
			}
			key := helpers.NewS3Key(domain, localpart, hash)
			data, ok := s3Mock.GetStoredData(key)
			if !ok {
				t.Errorf("❌ Message body %s was not uploaded to S3", key)
				continue
			}
			if got := helpers.HashContent(data); got != hash {
				t.Errorf("❌ S3 object %s holds content hashing to %s", key, got)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("Failed to read message S3 keys: %v", err)
		}
		if got := s3Mock.ObjectCount(); got != messageCount {
			t.Errorf("❌ Expected %d S3 objects, got %d", messageCount, got)
		}

		t.Logf("✅ Synchronous upload flow verified: no queue entries, all uploaded")
	})

	t.Run("CompareWithAsyncAppendFlow", func(t *testing.T) {
		// This test demonstrates the difference between:
		// - Importer flow (sync, no queue, uploaded=TRUE)
		// - APPEND/LMTP flow (async, queue, uploaded=FALSE initially)

		// Create default mailboxes
		user := server.NewUser(address, accountID)
		err := rdb.CreateDefaultMailboxesWithRetry(ctx, user.AccountID())
		if err != nil {
			t.Fatalf("Failed to create default mailboxes: %v", err)
		}

		// Get INBOX mailbox
		inbox, err := rdb.GetMailboxByNameWithRetry(ctx, user.AccountID(), "INBOX")
		if err != nil {
			t.Fatalf("Failed to get INBOX: %v", err)
		}

		// Simulate APPEND flow using InsertMessageWithRetry (creates queue entry)
		hostname, _ := os.Hostname()
		testHash := fmt.Sprintf("test-hash-%d", time.Now().UnixNano())

		// Create minimal body structure
		bodyStructurePart := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    1000,
		}
		var bodyStructure imap.BodyStructure = bodyStructurePart

		msgID, uid, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     user.AccountID(),
			MailboxID:     inbox.ID,
			MailboxName:   inbox.Name,
			S3Domain:      address.Domain(),
			S3Localpart:   address.LocalPart(),
			ContentHash:   testHash,
			MessageID:     fmt.Sprintf("<%d@test>", time.Now().UnixNano()),
			Size:          1000,
			Subject:       "Test APPEND message",
			SentDate:      time.Now(),
			InternalDate:  time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: &bodyStructure,
			Flags:         []imap.Flag{},
		}, db.PendingUpload{
			InstanceID:  hostname,
			ContentHash: testHash,
			Size:        1000,
			AccountID:   user.AccountID(),
		})
		if err != nil {
			t.Fatalf("Failed to insert with APPEND flow: %v", err)
		}

		t.Logf("Created message via APPEND flow: msgID=%d, uid=%d", msgID, uid)

		// Verify this APPEND message created a queue entry
		var appendQueueCount int
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT COUNT(*) FROM pending_uploads
			WHERE account_id = $1 AND content_hash = $2
		`, accountID, testHash).Scan(&appendQueueCount)
		if err != nil {
			t.Fatalf("Failed to query APPEND queue entry: %v", err)
		}

		if appendQueueCount != 1 {
			t.Errorf("❌ Expected APPEND to create 1 queue entry, got %d", appendQueueCount)
		} else {
			t.Logf("✅ APPEND flow correctly created queue entry")
		}

		// Verify APPEND message is uploaded=FALSE initially
		var appendUploaded bool
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT uploaded FROM messages WHERE id = $1
		`, msgID).Scan(&appendUploaded)
		if err != nil {
			t.Fatalf("Failed to query APPEND upload status: %v", err)
		}

		if appendUploaded {
			t.Errorf("❌ Expected APPEND message uploaded=FALSE initially, got TRUE")
		} else {
			t.Logf("✅ APPEND message correctly marked uploaded=FALSE (async flow)")
		}

		// Count total queue entries - should only be from APPEND, not from import
		var totalQueueCount int
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT COUNT(*) FROM pending_uploads WHERE account_id = $1
		`, accountID).Scan(&totalQueueCount)
		if err != nil {
			t.Fatalf("Failed to count total queue entries: %v", err)
		}

		t.Logf("Total queue entries: %d (should only include APPEND, not import)", totalQueueCount)
		t.Logf("✅ Flow comparison verified: APPEND uses queue, Importer does not")
	})
}

// TestImporter_S3FailurePreventsDBInsert: a message whose body could not be stored
// in S3 must not be inserted into the database at all. The importer inserts its rows
// as uploaded, with no pending upload to retry, so such a row would name a body S3
// does not have. The message is reported as failed instead, and left pending in the
// maildir database for the next run, while the messages whose upload succeeded are
// imported.
func TestImporter_S3FailurePreventsDBInsert(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const messageCount = 3

	// importWithStorage imports messageCount messages for a new account, with TestMode
	// off so the importer does upload. newStorage returns the storage to upload to and
	// the content hashes of the messages it refuses. The run must fail, report only the
	// refused messages as failed (each with its S3 error) and leave them pending, and
	// insert rows for exactly the other messages.
	importWithStorage := func(t *testing.T, newStorage func(email, maildirPath string) (objectStorage, map[string]bool), options ImporterOptions) {
		t.Helper()
		testEmail := fmt.Sprintf("s3-failure-test-%d@example.com", time.Now().UnixNano())
		createTestAccount(t, rdb, testEmail, "testpassword123")
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, testEmail)
		if err != nil {
			t.Fatalf("Failed to get account ID: %v", err)
		}

		maildirPath := filepath.Join(t.TempDir(), "testmaildir")
		if err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, messageCount); err != nil {
			t.Fatalf("Failed to copy test data: %v", err)
		}
		s3, rejected := newStorage(testEmail, maildirPath)

		importer, err := NewImporter(ctx, maildirPath, testEmail, 4, rdb, s3, options)
		if err != nil {
			t.Fatalf("Failed to create importer: %v", err)
		}
		defer importer.Close()

		if err := importer.Run(); err == nil {
			t.Fatal("Import reported success although S3 refused an upload")
		}

		// Rows: exactly the messages whose upload succeeded.
		rows, err := rdb.QueryWithRetry(ctx, `SELECT content_hash, uploaded FROM messages WHERE account_id = $1`, accountID)
		if err != nil {
			t.Fatalf("Failed to query messages: %v", err)
		}
		defer rows.Close()
		inserted := 0
		for rows.Next() {
			var hash string
			var uploaded bool
			if err := rows.Scan(&hash, &uploaded); err != nil {
				t.Fatalf("Failed to scan message: %v", err)
			}
			inserted++
			if rejected[hash] {
				t.Errorf("Message %s was inserted although its S3 upload failed (uploaded=%v)", hash, uploaded)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("Failed to read messages: %v", err)
		}
		if want := messageCount - len(rejected); inserted != want {
			t.Errorf("Expected %d message rows, got %d", want, inserted)
		}

		var pendingRows int
		if err := rdb.QueryRowWithRetry(ctx, `SELECT COUNT(*) FROM pending_uploads WHERE account_id = $1`, accountID).Scan(&pendingRows); err != nil {
			t.Fatalf("Failed to count pending_uploads: %v", err)
		}
		if pendingRows != 0 {
			t.Errorf("Expected no pending_uploads rows, got %d", pendingRows)
		}

		importer.failedPathsMutex.Lock()
		failed := append([]failedImport(nil), importer.failedPaths...)
		importer.failedPathsMutex.Unlock()
		if len(failed) != len(rejected) {
			t.Errorf("Expected %d failed paths, got %d: %v", len(rejected), len(failed), failed)
		}
		for _, f := range failed {
			if !strings.HasPrefix(f.reason, "s3 upload error: ") {
				t.Errorf("Failed path %s has reason %q, want an S3 upload error", f.path, f.reason)
			}
		}
		if importer.failedMessages != int64(len(rejected)) || importer.importedMessages != int64(messageCount-len(rejected)) {
			t.Errorf("Expected %d failed and %d imported messages, got %d failed and %d imported",
				len(rejected), messageCount-len(rejected), importer.failedMessages, importer.importedMessages)
		}

		imported, pending := uploadedCounts(t, maildirPath)
		if imported != messageCount-len(rejected) || pending != len(rejected) {
			t.Errorf("Expected the maildir database to hold %d imported and %d pending messages, got %d and %d",
				messageCount-len(rejected), len(rejected), imported, pending)
		}
	}

	// Every upload fails: the insert phase never runs.
	t.Run("every upload fails", func(t *testing.T) {
		importWithStorage(t, func(email, maildirPath string) (objectStorage, map[string]bool) {
			rejected := make(map[string]bool)
			for _, content := range maildirContents(t, maildirPath) {
				rejected[helpers.HashContent(content)] = true
			}
			return &rejectingStorage{}, rejected
		}, ImporterOptions{})
	})

	// One upload fails: the batch's insert phase runs for the other messages only, in
	// either transaction mode.
	for _, batchTx := range []bool{false, true} {
		t.Run(fmt.Sprintf("one upload fails/batch_transaction=%v", batchTx), func(t *testing.T) {
			importWithStorage(t, func(email, maildirPath string) (objectStorage, map[string]bool) {
				mock, err := testutils.NewFileBasedS3Mock(filepath.Join(t.TempDir(), "s3"))
				if err != nil {
					t.Fatalf("Failed to create S3 mock: %v", err)
				}
				address, err := server.NewAddress(email)
				if err != nil {
					t.Fatalf("Invalid email address: %v", err)
				}
				hash := helpers.HashContent(maildirContents(t, maildirPath)[0])
				mock.SetError(helpers.NewS3Key(address.Domain(), address.LocalPart(), hash), errors.New("simulated S3 rejection"))
				return mock, map[string]bool{hash: true}
			}, ImporterOptions{BatchTransactionMode: batchTx})
		})
	}
}

// maildirContents returns the content of each message in maildirPath/cur.
func maildirContents(t *testing.T, maildirPath string) [][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(maildirPath, "cur"))
	if err != nil {
		t.Fatalf("Failed to read maildir: %v", err)
	}
	var contents [][]byte
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(maildirPath, "cur", entry.Name()))
		if err != nil {
			t.Fatalf("Failed to read message: %v", err)
		}
		contents = append(contents, content)
	}
	return contents
}
