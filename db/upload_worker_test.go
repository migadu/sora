package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupUploadWorkerTest creates a database connection and truncates all tables
// to ensure a clean state for tests that query global data.
func setupUploadWorkerTest(t *testing.T) *Database {
	db := setupTestDatabase(t)
	t.Cleanup(func() {
		db.Close()
	})

	// Clean up all relevant tables before each test to ensure isolation.
	// This is necessary because some tests query global state (e.g., GetUploaderStats).
	tables := []string{
		"cache_metrics",
		"health_status",
		"locks",
		"vacation_responses",
		"sieve_scripts",
		"pending_uploads",
		"message_contents",
		"message_sequences",
		"mailbox_stats",
		"messages",
		"mailboxes",
		"credentials",
		"accounts",
	}

	_, err := db.GetWritePool().Exec(context.Background(), "TRUNCATE TABLE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE")
	require.NoError(t, err, "failed to truncate tables for test isolation")

	return db
}

// createTestAccount is a helper to create an account for testing.
func createTestAccount(t *testing.T, db *Database, email, password string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     email,
		Password:  password,
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	accountID, err := db.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)
	return accountID
}

// createTestMailbox is a helper to create a mailbox for testing.
func createTestMailbox(t *testing.T, db *Database, accountID int64, name string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, name, nil)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	mailbox, err := db.GetMailboxByName(ctx, accountID, name)
	require.NoError(t, err)
	return mailbox.ID
}

// Helper to create a pending upload for testing
func createPendingUpload(t *testing.T, db *Database, accountID int64, instanceID, contentHash string, attempts int, lastAttempt time.Time, size int64) int64 {
	t.Helper()
	var id int64
	var lastAttemptArg any = lastAttempt
	if lastAttempt.IsZero() {
		lastAttemptArg = nil
	}

	err := db.GetWritePool().QueryRow(context.Background(), `
		INSERT INTO pending_uploads (account_id, instance_id, content_hash, size, attempts, last_attempt)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, accountID, instanceID, contentHash, size, attempts, lastAttemptArg).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestAcquireAndLeasePendingUploads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_acquire_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	instanceID := "test-instance-1"
	otherInstanceID := "test-instance-2"

	retryInterval := 5 * time.Minute
	maxAttempts := 3
	limit := 10

	// 1. Should be acquired: new upload
	createPendingUpload(t, db, accountID, instanceID, "hash1", 0, time.Time{}, 1024)
	// 2. Should be acquired: old attempt
	createPendingUpload(t, db, accountID, instanceID, "hash2", 1, time.Now().Add(-2*retryInterval), 1024)
	// 3. Should NOT be acquired: recent attempt
	createPendingUpload(t, db, accountID, instanceID, "hash3", 1, time.Now().Add(-1*time.Minute), 1024)
	// 4. Should NOT be acquired: max attempts reached
	createPendingUpload(t, db, accountID, instanceID, "hash4", maxAttempts, time.Now().Add(-2*retryInterval), 1024)
	// 5. Should NOT be acquired: different instance
	createPendingUpload(t, db, accountID, otherInstanceID, "hash5", 0, time.Time{}, 1024)
	// 6. Should be acquired: another new upload
	createPendingUpload(t, db, accountID, instanceID, "hash6", 0, time.Time{}, 1024)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	uploads, err := db.AcquireAndLeasePendingUploads(ctx, tx, instanceID, limit, retryInterval, maxAttempts)
	require.NoError(t, err)
	require.NotNil(t, uploads)

	assert.Len(t, uploads, 3, "should acquire 3 uploads")

	acquiredHashes := make(map[string]bool)
	for _, u := range uploads {
		acquiredHashes[u.ContentHash] = true
		assert.Equal(t, instanceID, u.InstanceID)
		// The returned struct has the values from before the lease update.
		if u.ContentHash == "hash2" {
			assert.True(t, u.LastAttempt.Valid)
			assert.True(t, u.LastAttempt.Time.Before(time.Now().Add(-retryInterval)))
		} else {
			assert.False(t, u.LastAttempt.Valid)
		}
	}

	assert.Contains(t, acquiredHashes, "hash1")
	assert.Contains(t, acquiredHashes, "hash2")
	assert.Contains(t, acquiredHashes, "hash6")

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify in DB that last_attempt is updated for the acquired uploads
	for _, u := range uploads {
		var lastAttempt sql.NullTime
		err := db.GetReadPool().QueryRow(ctx, "SELECT last_attempt FROM pending_uploads WHERE id = $1", u.ID).Scan(&lastAttempt)
		require.NoError(t, err)
		require.True(t, lastAttempt.Valid)
		assert.WithinDuration(t, time.Now(), lastAttempt.Time, 10*time.Second)
	}
}

func TestMarkUploadAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_mark_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	contentHash := "test-hash"

	uploadID := createPendingUpload(t, db, accountID, "instance", contentHash, 1, time.Now().Add(-1*time.Hour), 1024)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.MarkUploadAttempt(ctx, tx, contentHash, accountID)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	var attempts int
	var lastAttempt time.Time
	err = db.GetReadPool().QueryRow(ctx, "SELECT attempts, last_attempt FROM pending_uploads WHERE id = $1", uploadID).Scan(&attempts, &lastAttempt)
	require.NoError(t, err)

	assert.Equal(t, 2, attempts)
	assert.WithinDuration(t, time.Now(), lastAttempt, 5*time.Second)
}

func TestCompleteS3Upload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_complete_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	mailboxID := createTestMailbox(t, db, accountID, "INBOX")
	contentHash := "test-hash-complete"

	// Create a pending upload
	uploadID := createPendingUpload(t, db, accountID, "instance", contentHash, 0, time.Time{}, 1024)

	// Create a corresponding message
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, content_hash, uploaded, s3_domain, s3_localpart, message_id, sent_date, internal_date, flags, size, body_structure, recipients_json, created_modseq, uid)
		VALUES ($1, $2, $3, FALSE, 'domain', 'localpart', 'msgid', now(), now(), 0, 1024, 'body', '[]', 1, 1)
	`, accountID, mailboxID, contentHash)
	require.NoError(t, err)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CompleteS3Upload(ctx, tx, contentHash, accountID)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify pending_upload is deleted
	var count int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM pending_uploads WHERE id = $1", uploadID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "pending_uploads record should be deleted")

	// Verify message is marked as uploaded
	var uploaded bool
	err = db.GetReadPool().QueryRow(ctx, "SELECT uploaded FROM messages WHERE content_hash = $1 AND account_id = $2", contentHash, accountID).Scan(&uploaded)
	require.NoError(t, err)
	assert.True(t, uploaded, "message should be marked as uploaded")
}

func TestIsContentHashUploaded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)
	defer db.Close()

	ctx := context.Background()

	testEmail := fmt.Sprintf("test_isuploaded_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	mailboxID := createTestMailbox(t, db, accountID, "INBOX")
	hashUploaded := "hash-is-uploaded"
	hashNotUploaded := "hash-is-not-uploaded"
	hashNonExistent := "hash-does-not-exist"

	// Create messages
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, content_hash, uploaded, s3_domain, s3_localpart, message_id, sent_date, internal_date, flags, size, body_structure, recipients_json, created_modseq, uid)
		VALUES ($1, $2, $3, TRUE, 'd', 'l', 'm1', now(), now(), 0, 1, 'b', '[]', 1, 1), 
		       ($1, $2, $4, FALSE, 'd', 'l', 'm2', now(), now(), 0, 1, 'b', '[]', 2, 2)
	`, accountID, mailboxID, hashUploaded, hashNotUploaded)
	require.NoError(t, err)

	t.Run("is uploaded", func(t *testing.T) {
		uploaded, err := db.IsContentHashUploaded(ctx, hashUploaded, accountID)
		require.NoError(t, err)
		assert.True(t, uploaded)
	})

	t.Run("is not uploaded", func(t *testing.T) {
		uploaded, err := db.IsContentHashUploaded(ctx, hashNotUploaded, accountID)
		require.NoError(t, err)
		assert.False(t, uploaded)
	})

	t.Run("does not exist", func(t *testing.T) {
		uploaded, err := db.IsContentHashUploaded(ctx, hashNonExistent, accountID)
		require.NoError(t, err)
		assert.False(t, uploaded)
	})

	t.Run("wrong account", func(t *testing.T) {
		otherTestEmail := fmt.Sprintf("test_isuploaded_other_%d@example.com", time.Now().UnixNano())
		otherAccountID := createTestAccount(t, db, otherTestEmail, "password")
		uploaded, err := db.IsContentHashUploaded(ctx, hashUploaded, otherAccountID)
		require.NoError(t, err)
		assert.False(t, uploaded)
	})
}

func TestGetUploaderStats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_stats_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	maxAttempts := 5

	// Create some "newer" pending uploads. Their created_at will be around time.Now().
	createPendingUpload(t, db, accountID, "i1", "h1", 0, time.Time{}, 1024)
	createPendingUpload(t, db, accountID, "i1", "h2", 2, time.Time{}, 2048)

	// Create some "failed" uploads that should be ignored by the pending stats query.
	createPendingUpload(t, db, accountID, "i1", "h3", maxAttempts, time.Time{}, 4096)
	createPendingUpload(t, db, accountID, "i1", "h4", maxAttempts+1, time.Time{}, 8192)

	// Create the record that will be the oldest.
	oldestTime := time.Now().Add(-10 * time.Minute)
	createPendingUpload(t, db, accountID, "i1", "h5", 1, time.Time{}, 512)

	// Manually update its created_at to a known, distinct past time.
	_, err := db.GetWritePool().Exec(ctx, "UPDATE pending_uploads SET created_at = $1 WHERE content_hash = 'h5'", oldestTime)
	require.NoError(t, err)

	// Get the stats
	stats, err := db.GetUploaderStats(ctx, maxAttempts)
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, int64(3), stats.TotalPending, "h1, h2, and h5 should be pending")
	assert.Equal(t, int64(1024+2048+512), stats.TotalPendingSize)
	assert.Equal(t, int64(2), stats.FailedUploads, "h3 and h4 should be failed")
	require.True(t, stats.OldestPending.Valid)
	// Use a larger delta to account for database time precision differences.
	// PostgreSQL stores TIMESTAMPTZ with microsecond precision, while Go's time.Time has nanosecond precision.
	// This can lead to small discrepancies. 15ms is a safe margin.
	assert.WithinDuration(t, oldestTime, stats.OldestPending.Time, 15*time.Millisecond)
}

func TestGetFailedUploads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_failed_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	maxAttempts := 3

	// Create uploads
	createPendingUpload(t, db, accountID, "i1", "h1", 0, time.Time{}, 1024)             // pending
	createPendingUpload(t, db, accountID, "i1", "h2", maxAttempts, time.Time{}, 1024)   // failed
	createPendingUpload(t, db, accountID, "i1", "h3", maxAttempts+1, time.Time{}, 1024) // failed
	createPendingUpload(t, db, accountID, "i1", "h4", 2, time.Time{}, 1024)             // pending

	// Make h3 older than h2
	_, err := db.GetWritePool().Exec(ctx, "UPDATE pending_uploads SET created_at = created_at - '1 minute'::interval WHERE content_hash = 'h3'")
	require.NoError(t, err)

	t.Run("get all failed", func(t *testing.T) {
		uploads, err := db.GetFailedUploads(ctx, maxAttempts, 10)
		require.NoError(t, err)
		assert.Len(t, uploads, 2)
		// Should be ordered by created_at DESC, so h2 comes before h3
		assert.Equal(t, "h2", uploads[0].ContentHash)
		assert.Equal(t, "h3", uploads[1].ContentHash)
	})

	t.Run("limit failed", func(t *testing.T) {
		uploads, err := db.GetFailedUploads(ctx, maxAttempts, 1)
		require.NoError(t, err)
		assert.Len(t, uploads, 1)
		assert.Equal(t, "h2", uploads[0].ContentHash)
	})

	t.Run("no failed", func(t *testing.T) {
		uploads, err := db.GetFailedUploads(ctx, 10, 10) // maxAttempts is high
		require.NoError(t, err)
		assert.Len(t, uploads, 0)
	})
}

func TestAcquireAndLeasePendingUploads_Concurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := setupUploadWorkerTest(t)

	ctx := context.Background()
	testEmail := fmt.Sprintf("test_concurrency_%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, testEmail, "password")
	instanceID := "concurrent-instance"

	// --- Setup ---
	// Create a pool of uploads for workers to compete for.
	numUploads := 100
	for i := 0; i < numUploads; i++ {
		hash := fmt.Sprintf("concurrent_hash_%d", i)
		createPendingUpload(t, db, accountID, instanceID, hash, 0, time.Time{}, 1024)
	}

	// --- Concurrency Test ---
	numWorkers := 5
	batchSize := 10
	retryInterval := 5 * time.Minute
	maxAttempts := 3

	var wg sync.WaitGroup
	acquiredIDs := make(map[int64]bool)
	var mu sync.Mutex
	resultsCh := make(chan []PendingUpload, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Each worker gets its own transaction, simulating concurrent processes.
			tx, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				t.Errorf("worker %d failed to begin transaction: %v", workerID, err)
				return
			}
			defer tx.Rollback(ctx) // Rollback if not committed

			uploads, err := db.AcquireAndLeasePendingUploads(ctx, tx, instanceID, batchSize, retryInterval, maxAttempts)
			if err != nil {
				t.Errorf("worker %d failed to acquire uploads: %v", workerID, err)
				return
			}

			// Commit the transaction to finalize the lease.
			if err := tx.Commit(ctx); err != nil {
				t.Errorf("worker %d failed to commit transaction: %v", workerID, err)
				return
			}

			resultsCh <- uploads
		}(i)
	}

	wg.Wait()
	close(resultsCh)

	// --- Verification ---
	totalAcquired := 0
	for batch := range resultsCh {
		totalAcquired += len(batch)
		for _, upload := range batch {
			mu.Lock()
			if _, exists := acquiredIDs[upload.ID]; exists {
				t.Errorf("Duplicate upload ID %d acquired by multiple workers. FOR UPDATE SKIP LOCKED failed.", upload.ID)
			}
			acquiredIDs[upload.ID] = true
			mu.Unlock()
		}
	}

	assert.Equal(t, numWorkers*batchSize, totalAcquired, "Total number of acquired uploads should match expected")
	assert.Len(t, acquiredIDs, numWorkers*batchSize, "Number of unique acquired IDs should match expected")

	t.Logf("Successfully acquired %d unique uploads across %d concurrent workers.", totalAcquired, numWorkers)
}
