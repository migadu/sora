package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCleanerTestDatabase creates a test database and returns it along with test data
func setupCleanerTestDatabase(t *testing.T) (*Database, string, int64, int64) {
	db := setupTestDatabase(t)

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	ctx := context.Background()

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create INBOX mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox ID
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	return db, testEmail, accountID, mailboxID
}

// TestPruneOldMessageBodies tests the PruneOldMessageBodies function
func TestPruneOldMessageBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test setup: Create message contents with different ages
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	// Insert test message content with unique hashes based on test name and timestamp
	testTimestamp := time.Now().UnixNano()
	oldContentHash := fmt.Sprintf("old_%s_%d", t.Name(), testTimestamp)
	recentContentHash := fmt.Sprintf("recent_%s_%d", t.Name(), testTimestamp+1)
	expungedContentHash := fmt.Sprintf("expunged_%s_%d", t.Name(), testTimestamp+2)

	testBody := "This is a test message body that should be pruned or kept based on message age"

	// Insert message contents
	_, err = tx3.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, created_at, updated_at)
		VALUES 
		($1, $2, to_tsvector('english', $2), '', NOW(), NOW()),
		($3, $4, to_tsvector('english', $4), '', NOW(), NOW()),
		($5, $6, to_tsvector('english', $6), '', NOW(), NOW())
	`, oldContentHash, testBody,
		recentContentHash, testBody,
		expungedContentHash, testBody)
	require.NoError(t, err)

	// Insert old message (should be pruned)
	oldSentDate := time.Now().Add(-48 * time.Hour) // 2 days ago
	_, err = tx3.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 1, $3, $4, $4, $5, 0, NULL, TRUE, 'test-domain', 'test-localpart-1', 'msgid1', 'body', '[]', 1)
	`, accountID, mailboxID, oldContentHash, oldSentDate, len(testBody))
	require.NoError(t, err)

	// Insert recent message (should NOT be pruned)
	recentSentDate := time.Now().Add(-12 * time.Hour) // 12 hours ago
	_, err = tx3.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 2, $3, $4, $4, $5, 0, NULL, TRUE, 'test-domain', 'test-localpart-2', 'msgid2', 'body', '[]', 2)
	`, accountID, mailboxID, recentContentHash, recentSentDate, len(testBody))
	require.NoError(t, err)

	// Insert old expunged message (should be pruned since it's expunged)
	expungedSentDate := time.Now().Add(-12 * time.Hour) // 12 hours ago but expunged
	_, err = tx3.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 3, $3, $4, $4, $5, 0, NOW(), TRUE, 'test-domain', 'test-localpart-3', 'msgid3', 'body', '[]', 3)
	`, accountID, mailboxID, expungedContentHash, expungedSentDate, len(testBody))
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// Verify initial state - all message contents should have text_body
	var oldBodyBefore, recentBodyBefore, expungedBodyBefore string
	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", oldContentHash).Scan(&oldBodyBefore)
	require.NoError(t, err)
	assert.Equal(t, testBody, oldBodyBefore)

	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", recentContentHash).Scan(&recentBodyBefore)
	require.NoError(t, err)
	assert.Equal(t, testBody, recentBodyBefore)

	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", expungedContentHash).Scan(&expungedBodyBefore)
	require.NoError(t, err)
	assert.Equal(t, testBody, expungedBodyBefore)

	// Prune message bodies older than 24 hours.
	// The shared test database may have leftover data from other tests that fills
	// the 100-row batch before our test rows. Run in a loop until our old message
	// gets pruned (max 50 iterations to avoid infinite loop).
	retention := 24 * time.Hour
	var totalRowsAffected int64
	for i := 0; i < 50; i++ {
		tx4, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		rowsAffected, err := db.PruneOldMessageBodies(ctx, tx4, retention)
		require.NoError(t, err)

		err = tx4.Commit(ctx)
		require.NoError(t, err)

		totalRowsAffected += rowsAffected
		if rowsAffected == 0 {
			break // No more rows to prune
		}
	}
	t.Logf("PruneOldMessageBodies affected %d rows total", totalRowsAffected)

	// Test 2: Verify old message body was pruned
	var oldBodyAfter *string
	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", oldContentHash).Scan(&oldBodyAfter)
	require.NoError(t, err)
	assert.Nil(t, oldBodyAfter, "Old message body should be NULL after pruning")

	// Test 3: Verify recent message body was NOT pruned
	var recentBodyAfter string
	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", recentContentHash).Scan(&recentBodyAfter)
	require.NoError(t, err)
	assert.Equal(t, testBody, recentBodyAfter, "Recent message body should still be present")

	// Test 4: Verify expunged message body was pruned (since message is expunged)
	var expungedBodyAfter *string
	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", expungedContentHash).Scan(&expungedBodyAfter)
	require.NoError(t, err)
	assert.Nil(t, expungedBodyAfter, "Expunged message body should be NULL after pruning")

	// Test 5: Verify text_body_tsv (search vector) is still preserved for all
	var oldTsv, recentTsv, expungedTsv string
	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body_tsv::text FROM message_contents WHERE content_hash = $1", oldContentHash).Scan(&oldTsv)
	require.NoError(t, err)
	assert.NotEmpty(t, oldTsv, "Search vector should be preserved even after body pruning")

	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body_tsv::text FROM message_contents WHERE content_hash = $1", recentContentHash).Scan(&recentTsv)
	require.NoError(t, err)
	assert.NotEmpty(t, recentTsv, "Search vector should be preserved")

	err = db.GetReadPool().QueryRow(ctx, "SELECT text_body_tsv::text FROM message_contents WHERE content_hash = $1", expungedContentHash).Scan(&expungedTsv)
	require.NoError(t, err)
	assert.NotEmpty(t, expungedTsv, "Search vector should be preserved even after body pruning")

	// Test 6: Test with zero retention (should prune everything that has any expunged or old messages)
	tx5, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx5.Rollback(ctx)

	// Insert another recent message content to test zero retention
	zeroRetentionHash := fmt.Sprintf("zero_%s_%d", t.Name(), testTimestamp+3)
	_, err = tx5.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, created_at, updated_at)
		VALUES ($1, $2, to_tsvector('english', $2), '', NOW(), NOW())
	`, zeroRetentionHash, testBody)
	require.NoError(t, err)

	// Insert message with this content
	_, err = tx5.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 4, $3, $4, $4, $5, 0, NULL, TRUE, 'test-domain', 'test-localpart-4', 'msgid4', 'body', '[]', 4)
	`, accountID, mailboxID, zeroRetentionHash, time.Now().Add(-1*time.Minute), len(testBody))
	require.NoError(t, err)

	// Prune with zero retention - should prune the recent content that was not already pruned
	zeroRetention := time.Duration(0)
	rowsAffected2, err := db.PruneOldMessageBodies(ctx, tx5, zeroRetention)
	require.NoError(t, err)

	err = tx5.Commit(ctx)
	require.NoError(t, err)

	// Log how many rows were affected - we can't assert exact numbers due to shared test DB
	t.Logf("Zero retention prune affected %d rows total", rowsAffected2)

	t.Logf("Successfully tested PruneOldMessageBodies with email: %s", testEmail)
}

// TestPruneOldMessageBodiesEmptyDatabase tests pruning on empty database
func TestPruneOldMessageBodiesEmptyDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Test pruning - the shared test database may have leftover data from other tests,
	// so we just verify the function doesn't error, not the exact row count.
	retention := 24 * time.Hour
	_, err = db.PruneOldMessageBodies(ctx, tx, retention)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)
}

// TestPruneOldMessageBodiesBatching tests that pruning works correctly with batching
func TestPruneOldMessageBodiesBatching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create a small number of old message contents to test batching logic
	// We use 5 records to verify the batch loop works correctly
	const numRecords = 5
	testTimestamp := time.Now().UnixNano()
	testBody := "Test message body for batching test"
	oldSentDate := time.Now().Add(-48 * time.Hour)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Insert multiple old message contents
	for i := 0; i < numRecords; i++ {
		contentHash := fmt.Sprintf("batch_%s_%d_%d", t.Name(), testTimestamp, i)

		// Insert message content
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, created_at, updated_at)
			VALUES ($1, $2, to_tsvector('english', $2), '', NOW(), NOW())
		`, contentHash, testBody)
		require.NoError(t, err)

		// Insert old message
		_, err = tx.Exec(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, $5, $5, $6, 0, NULL, TRUE, 'test-domain', $7, $8, 'body', '[]', $3)
		`, accountID, mailboxID, 1000+i, contentHash, oldSentDate, len(testBody),
			fmt.Sprintf("test-localpart-batch-%d", i),
			fmt.Sprintf("msgid-batch-%d", i))
		require.NoError(t, err)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Prune with 24 hour retention - all test messages should be pruned
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	retention := 24 * time.Hour
	rowsAffected, err := db.PruneOldMessageBodies(ctx, tx2, retention)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, rowsAffected, int64(numRecords), "Should prune at least our test records")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify all our test messages were pruned
	for i := 0; i < numRecords; i++ {
		contentHash := fmt.Sprintf("batch_%s_%d_%d", t.Name(), testTimestamp, i)
		var body *string
		err = db.GetReadPool().QueryRow(ctx, "SELECT text_body FROM message_contents WHERE content_hash = $1", contentHash).Scan(&body)
		require.NoError(t, err)
		assert.Nil(t, body, "Message body %d should be NULL after pruning", i)
	}

	t.Logf("Successfully tested batching with %d records (email: %s)", numRecords, testEmail)
}

// TestCleanupLock tests the distributed locking mechanism for cleanup operations
func TestCleanupLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Clean up any existing locks first
	tx0, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	db.ReleaseCleanupLock(ctx, tx0) // Ignore error, might not exist
	tx0.Commit(ctx)

	// Test 1: Acquire lock successfully
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	acquired, err := db.AcquireCleanupLock(ctx, tx1)
	require.NoError(t, err)
	assert.True(t, acquired, "Should successfully acquire lock")

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Try to acquire lock again without releasing first (should fail)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	acquired2, err := db.AcquireCleanupLock(ctx, tx2)
	require.NoError(t, err)
	assert.False(t, acquired2, "Should not acquire lock when one is already active")

	tx2.Rollback(ctx)

	// Test 3: Release the first lock, then try to acquire again
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.ReleaseCleanupLock(ctx, tx3)
	require.NoError(t, err)

	// Now try to acquire after release
	acquired3, err := db.AcquireCleanupLock(ctx, tx3)
	require.NoError(t, err)
	assert.True(t, acquired3, "Should acquire lock after previous was released")

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Successfully tested cleanup locking mechanism")
}

// TestExpungeOldMessages tests automatic message expunging based on age
func TestExpungeOldMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create messages with different ages
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create old message (should be expunged)
	oldCreatedAt := time.Now().Add(-72 * time.Hour) // 3 days old
	oldHash := fmt.Sprintf("old_expunge_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'old message', to_tsvector('english', 'old message'), '')
	`, oldHash)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, created_at)
		VALUES ($1, $2, 100, $3, $4, $4, 100, 0, TRUE, 'domain', 'part', 'msgid100', 'body', '[]', 100, $5)
	`, accountID, mailboxID, oldHash, time.Now(), oldCreatedAt)
	require.NoError(t, err)

	// Create recent message (should NOT be expunged)
	recentCreatedAt := time.Now().Add(-12 * time.Hour) // 12 hours old
	recentHash := fmt.Sprintf("recent_expunge_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'recent message', to_tsvector('english', 'recent message'), '')
	`, recentHash)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, created_at)
		VALUES ($1, $2, 101, $3, $4, $4, 100, 0, TRUE, 'domain', 'part', 'msgid101', 'body', '[]', 101, $5)
	`, accountID, mailboxID, recentHash, time.Now(), recentCreatedAt)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Expunge messages older than 48 hours
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	expunged, err := db.ExpungeOldMessages(ctx, tx2, 48*time.Hour)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Expunged %d old messages", expunged)

	// Verify old message was expunged
	var oldExpungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx, "SELECT expunged_at FROM messages WHERE content_hash = $1", oldHash).Scan(&oldExpungedAt)
	require.NoError(t, err)
	assert.NotNil(t, oldExpungedAt, "Old message should be expunged")

	// Verify recent message was NOT expunged
	var recentExpungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx, "SELECT expunged_at FROM messages WHERE content_hash = $1", recentHash).Scan(&recentExpungedAt)
	require.NoError(t, err)
	assert.Nil(t, recentExpungedAt, "Recent message should not be expunged")

	t.Logf("Successfully tested ExpungeOldMessages with email: %s", testEmail)
}

// TestCleanupFailedUploads tests cleanup of messages that failed to upload to S3
func TestCleanupFailedUploads(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create failed upload scenarios
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create old failed upload (should be cleaned up)
	oldFailedHash := fmt.Sprintf("old_failed_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'failed upload content', to_tsvector('english', 'failed upload content'), '')
	`, oldFailedHash)
	require.NoError(t, err)

	oldCreatedAt := time.Now().Add(-25 * time.Hour) // 25 hours old
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, created_at)
		VALUES ($1, $2, 200, $3, $4, $4, 100, 0, FALSE, 'domain', 'part', 'msgid200', 'body', '[]', 200, $5)
	`, accountID, mailboxID, oldFailedHash, time.Now(), oldCreatedAt)
	require.NoError(t, err)

	// Add to pending uploads
	_, err = tx.Exec(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id)
		VALUES ($1, $2, 100, 'test-instance')
	`, accountID, oldFailedHash)
	require.NoError(t, err)

	// Create recent failed upload (should NOT be cleaned up)
	recentFailedHash := fmt.Sprintf("recent_failed_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'recent failed content', to_tsvector('english', 'recent failed content'), '')
	`, recentFailedHash)
	require.NoError(t, err)

	recentCreatedAt := time.Now().Add(-5 * time.Hour) // 5 hours old
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, created_at)
		VALUES ($1, $2, 201, $3, $4, $4, 100, 0, FALSE, 'domain', 'part', 'msgid201', 'body', '[]', 201, $5)
	`, accountID, mailboxID, recentFailedHash, time.Now(), recentCreatedAt)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id)
		VALUES ($1, $2, 100, 'test-instance')
	`, accountID, recentFailedHash)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Clean up failed uploads older than 24 hours
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	cleaned, err := db.CleanupFailedUploads(ctx, tx2, 24*time.Hour)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Cleaned up %d failed uploads", cleaned)

	// Verify old failed upload was removed
	var oldExists int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE content_hash = $1", oldFailedHash).Scan(&oldExists)
	require.NoError(t, err)
	assert.Equal(t, 0, oldExists, "Old failed upload should be removed")

	// Verify recent failed upload still exists
	var recentExists int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE content_hash = $1", recentFailedHash).Scan(&recentExists)
	require.NoError(t, err)
	assert.Equal(t, 1, recentExists, "Recent failed upload should still exist")

	t.Logf("Successfully tested CleanupFailedUploads with email: %s", testEmail)
}

// TestGetUserScopedObjectsForCleanup tests identifying objects for cleanup
func TestGetUserScopedObjectsForCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create expunged messages ready for cleanup
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	cleanupHash := fmt.Sprintf("cleanup_ready_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'cleanup ready content', to_tsvector('english', 'cleanup ready content'), '')
	`, cleanupHash)
	require.NoError(t, err)

	expungedAt := time.Now().Add(-25 * time.Hour) // 25 hours ago
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at)
		VALUES ($1, $2, 300, $3, $4, $4, 100, 0, TRUE, 'test-domain', 'test-localpart', 'msgid300', 'body', '[]', 300, $5)
	`, accountID, mailboxID, cleanupHash, time.Now(), expungedAt)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Get objects for cleanup (older than 24 hours)
	candidates, err := db.GetUserScopedObjectsForCleanup(ctx, 24*time.Hour, 10)
	require.NoError(t, err)

	t.Logf("Found %d candidates for cleanup", len(candidates))

	// Find our test candidate
	var found bool
	for _, candidate := range candidates {
		if candidate.ContentHash == cleanupHash && candidate.AccountID == accountID {
			found = true
			assert.Equal(t, "test-domain", candidate.S3Domain)
			assert.Equal(t, "test-localpart", candidate.S3Localpart)
			break
		}
	}
	assert.True(t, found, "Should find our test candidate in cleanup list")

	t.Logf("Successfully tested GetUserScopedObjectsForCleanup with email: %s", testEmail)
}

// TestDeleteExpungedMessagesByS3KeyPartsBatch tests batch deletion of expunged messages
func TestDeleteExpungedMessagesByS3KeyPartsBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create expunged messages for batch deletion
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var candidates []UserScopedObjectForCleanup
	for i := 0; i < 3; i++ {
		hash := fmt.Sprintf("batch_delete_%d_%d", testTimestamp, i)
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
			VALUES ($1, $2, to_tsvector('english', $2), '')
		`, hash, fmt.Sprintf("batch delete content %d", i))
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at)
			VALUES ($1, $2, $3, $4, $5, $5, 100, 0, TRUE, 'batch-domain', 'batch-part', $6, 'body', '[]', $7, NOW())
		`, accountID, mailboxID, 400+i, hash, time.Now(), fmt.Sprintf("batchmsg%d", i), 400+i)
		require.NoError(t, err)

		candidates = append(candidates, UserScopedObjectForCleanup{
			AccountID:   accountID,
			ContentHash: hash,
			S3Domain:    "batch-domain",
			S3Localpart: "batch-part",
		})
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Batch delete expunged messages
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	deleted, err := db.DeleteExpungedMessagesByS3KeyPartsBatch(ctx, tx2, candidates)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted, "Should delete all 3 messages")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify messages were deleted
	for i, candidate := range candidates {
		var count int
		err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE content_hash = $1", candidate.ContentHash).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, fmt.Sprintf("Message %d should be deleted", i))
	}

	t.Logf("Successfully tested DeleteExpungedMessagesByS3KeyPartsBatch with email: %s", testEmail)
}

// TestGetUnusedContentHashes tests finding orphaned content hashes
func TestGetUnusedContentHashes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create orphaned content
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orphanedHash := fmt.Sprintf("orphaned_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'orphaned content', to_tsvector('english', 'orphaned content'), '')
	`, orphanedHash)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Get unused content hashes (use larger limit to handle test database with leftover data)
	unused, err := db.GetUnusedContentHashes(ctx, 1000)
	require.NoError(t, err)

	t.Logf("Found %d unused content hashes", len(unused))

	// Verify our orphaned hash is in the list
	var found bool
	for _, hash := range unused {
		if hash == orphanedHash {
			found = true
			break
		}
	}
	assert.True(t, found, "Should find our orphaned hash in unused list")

	t.Logf("Successfully tested GetUnusedContentHashes")
}

// TestDeleteMessageContentsByHashBatch tests batch deletion of message contents
func TestDeleteMessageContentsByHashBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create content hashes to delete
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var hashesToDelete []string
	for i := 0; i < 3; i++ {
		hash := fmt.Sprintf("delete_content_%d_%d", testTimestamp, i)
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
			VALUES ($1, $2, to_tsvector('english', $2), '')
		`, hash, fmt.Sprintf("content to delete %d", i))
		require.NoError(t, err)
		hashesToDelete = append(hashesToDelete, hash)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Batch delete message contents
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	deleted, err := db.DeleteMessageContentsByHashBatch(ctx, tx2, hashesToDelete)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted, "Should delete all 3 content entries")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify contents were deleted
	for i, hash := range hashesToDelete {
		var count int
		err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM message_contents WHERE content_hash = $1", hash).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, fmt.Sprintf("Content %d should be deleted", i))
	}

	t.Logf("Successfully tested DeleteMessageContentsByHashBatch")
}

// TestDeleteMessageByHashAndMailbox tests targeted message deletion for re-import scenarios
func TestDeleteMessageByHashAndMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create a message for deletion
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	deleteHash := fmt.Sprintf("delete_msg_%d", testTimestamp)
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers)
		VALUES ($1, 'message to delete', to_tsvector('english', 'message to delete'), '')
	`, deleteHash)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 500, $3, $4, $4, 100, 0, TRUE, 'delete-domain', 'delete-part', 'delete-msg-id', 'body', '[]', 500)
	`, accountID, mailboxID, deleteHash, time.Now())
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Delete specific message by hash and mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	deleted, err := db.DeleteMessageByHashAndMailbox(ctx, tx2, accountID, mailboxID, deleteHash)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "Should delete exactly 1 message")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify message was deleted
	var count int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE content_hash = $1 AND account_id = $2 AND mailbox_id = $3", deleteHash, accountID, mailboxID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Message should be deleted")

	t.Logf("Successfully tested DeleteMessageByHashAndMailbox with email: %s", testEmail)
}
