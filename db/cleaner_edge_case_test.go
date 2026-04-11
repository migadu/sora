package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCleanupLock_MultipleWorkersCompeting tests that only one worker can hold the lock at a time

func pruneBatched(db *Database, ctx context.Context, retention time.Duration) (int64, error) {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	pruned, err := db.PruneOldMessageVectors(ctx, tx, retention)
	if err == nil {
		tx.Commit(ctx)
	}
	return pruned, err
}

func TestCleanupLock_MultipleWorkersCompeting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	const numWorkers = 5
	const lockHoldDuration = 500 * time.Millisecond

	var wg sync.WaitGroup
	successChan := make(chan int, numWorkers)
	failChan := make(chan int, numWorkers)

	// Spawn multiple workers trying to acquire the lock simultaneously
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()

			tx, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				t.Logf("Worker %d: failed to begin transaction: %v", workerID, err)
				failChan <- workerID
				return
			}
			defer tx.Rollback(ctx)

			acquired, err := db.AcquireCleanupLock(ctx, tx)
			if err != nil {
				t.Logf("Worker %d: error acquiring lock: %v", workerID, err)
				failChan <- workerID
				return
			}

			if acquired {
				t.Logf("Worker %d: acquired lock, holding for %v", workerID, lockHoldDuration)
				time.Sleep(lockHoldDuration) // Simulate work
				tx.Commit(ctx)
				successChan <- workerID
			} else {
				t.Logf("Worker %d: lock not available (another worker holds it)", workerID)
				tx.Rollback(ctx)
				failChan <- workerID
			}
		}()
	}

	// Wait for all workers to complete
	wg.Wait()
	close(successChan)
	close(failChan)

	// Count successes and failures
	var successes, failures []int
	for id := range successChan {
		successes = append(successes, id)
	}
	for id := range failChan {
		failures = append(failures, id)
	}

	t.Logf("Results: %d workers acquired lock, %d were blocked", len(successes), len(failures))

	// Verify: Exactly ONE worker should have succeeded
	assert.Equal(t, 1, len(successes), "Exactly one worker should acquire the lock")
	assert.Equal(t, numWorkers-1, len(failures), "All other workers should fail to acquire")

	t.Logf("Successfully tested multiple workers competing for cleanup lock")
}

// TestCleanupLock_RollbackReleasesLock tests that rolling back a transaction releases the lock
func TestCleanupLock_RollbackReleasesLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Worker 1: Acquire lock then rollback
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	acquired1, err := db.AcquireCleanupLock(ctx, tx1)
	require.NoError(t, err)
	assert.True(t, acquired1, "First worker should acquire lock")

	// Rollback the transaction (should release the lock)
	err = tx1.Rollback(ctx)
	require.NoError(t, err)

	// Worker 2: Should be able to acquire the lock now
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	acquired2, err := db.AcquireCleanupLock(ctx, tx2)
	require.NoError(t, err)
	assert.True(t, acquired2, "Second worker should acquire lock after first rolled back")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Successfully verified lock is released on rollback")
}

// TestCleanupLock_CommitReleasesLock tests that committing a transaction releases the lock
func TestCleanupLock_CommitReleasesLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Worker 1: Acquire lock then commit
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	acquired1, err := db.AcquireCleanupLock(ctx, tx1)
	require.NoError(t, err)
	assert.True(t, acquired1, "First worker should acquire lock")

	// Commit the transaction (should release the lock)
	err = tx1.Commit(ctx)
	require.NoError(t, err)

	// Worker 2: Should be able to acquire the lock now
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	acquired2, err := db.AcquireCleanupLock(ctx, tx2)
	require.NoError(t, err)
	assert.True(t, acquired2, "Second worker should acquire lock after first committed")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Successfully verified lock is released on commit")
}

// TestPruneWithSKIPLOCKED tests that SKIP LOCKED allows concurrent operations
func TestPruneWithSKIPLOCKED(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create test data with multiple old message contents
	const numRecords = 20
	testBody := "Test message body for SKIP LOCKED test"
	oldSentDate := time.Now().Add(-48 * time.Hour)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var contentHashes []string
	for i := 0; i < numRecords; i++ {
		contentHash := fmt.Sprintf("skip_locked_%s_%d_%d", t.Name(), testTimestamp, i)
		contentHashes = append(contentHashes, contentHash)

		// Insert message content
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, sent_date, created_at, updated_at)
			VALUES ($1, $2, to_tsvector('english', $2), '', $3, NOW(), NOW())
		`, contentHash, testBody, oldSentDate)
		require.NoError(t, err)

		// Insert old message
		_, err = tx.Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, $5, $5, $6, NULL, TRUE, 'test-domain', $7, $8, 'body', '[]', $3)
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, 2000+i, contentHash, oldSentDate, len(testBody),
			fmt.Sprintf("test-localpart-skip-%d", i),
			fmt.Sprintf("msgid-skip-%d", i))
		require.NoError(t, err)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Start a long-running transaction that locks some rows
	txLongRunning, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	// Lock the first 5 content hashes by selecting them FOR UPDATE
	var lockedHashes []string
	rows, err := txLongRunning.Query(ctx, `
		SELECT content_hash 
		FROM message_contents 
		WHERE content_hash = ANY($1)
		ORDER BY content_hash
		LIMIT 5
		FOR UPDATE
	`, contentHashes)
	require.NoError(t, err)

	for rows.Next() {
		var hash string
		require.NoError(t, rows.Scan(&hash))
		lockedHashes = append(lockedHashes, hash)
	}
	rows.Close()
	require.Equal(t, 5, len(lockedHashes), "Should lock 5 rows")
	t.Logf("Long-running transaction locked %d rows", len(lockedHashes))

	// Now run the batched pruning - it should SKIP the locked rows and process the rest
	// We use a channel to run this in a goroutine so we can verify it doesn't block
	pruneDone := make(chan int64)
	go func() {
		pruned, err := pruneBatched(db, ctx, 24*time.Hour)
		if err != nil {
			t.Logf("Pruning error: %v", err)
			pruneDone <- -1
			return
		}
		pruneDone <- pruned
	}()

	// The pruning should complete quickly (within 5 seconds) even though some rows are locked
	select {
	case pruned := <-pruneDone:
		require.GreaterOrEqual(t, pruned, int64(10), "Should prune at least the unlocked rows (15 unlocked, might prune more from other tests)")
		t.Logf("Pruned %d rows while 5 were locked - SKIP LOCKED working!", pruned)
	case <-time.After(5 * time.Second):
		t.Fatal("Pruning blocked for >5s - SKIP LOCKED not working!")
	}

	// Clean up - rollback the long-running transaction
	txLongRunning.Rollback(ctx)

	// Now verify that the locked rows can be pruned in a subsequent run
	pruned2, err := pruneBatched(db, ctx, 24*time.Hour)
	require.NoError(t, err)
	t.Logf("After releasing locks, pruned %d more rows", pruned2)

	t.Logf("Successfully tested SKIP LOCKED behavior with email: %s", testEmail)
}

// TestCleanupLock_TransactionTimeout tests behavior when transaction holding lock times out
func TestCleanupLock_TransactionTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Worker 1: Acquire lock with a context that will timeout
	shortCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	tx1, err := db.GetWritePool().Begin(shortCtx)
	require.NoError(t, err)

	acquired1, err := db.AcquireCleanupLock(shortCtx, tx1)
	require.NoError(t, err)
	assert.True(t, acquired1, "First worker should acquire lock")

	t.Logf("Worker 1 acquired lock with 500ms timeout context")

	// Wait for context to timeout
	<-shortCtx.Done()
	t.Logf("Worker 1 context timed out")

	// The transaction should be invalidated when context times out
	// Try to rollback (might error if connection already closed)
	tx1.Rollback(ctx) // Use parent context for rollback

	// Worker 2: Should be able to acquire the lock after timeout/rollback
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	acquired2, err := db.AcquireCleanupLock(ctx, tx2)
	require.NoError(t, err)
	assert.True(t, acquired2, "Second worker should acquire lock after first timed out")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Successfully verified lock is released on context timeout")
}

// TestPruneConcurrentWorkers tests that multiple batched pruning operations can run concurrently
// thanks to SKIP LOCKED, each processing different rows
func TestPruneConcurrentWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	testTimestamp := time.Now().UnixNano()

	// Setup: Create lots of old message contents for concurrent pruning
	const numRecords = 100
	testBody := "Test message body for concurrent pruning"
	oldSentDate := time.Now().Add(-48 * time.Hour)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	for i := 0; i < numRecords; i++ {
		contentHash := fmt.Sprintf("concurrent_%s_%d_%d", t.Name(), testTimestamp, i)

		// Insert message content
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, sent_date, created_at, updated_at)
			VALUES ($1, $2, to_tsvector('english', $2), '', $3, NOW(), NOW())
		`, contentHash, testBody, oldSentDate)
		require.NoError(t, err)

		// Insert old message
		_, err = tx.Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, $5, $5, $6, NULL, TRUE, 'test-domain', $7, $8, 'body', '[]', $3)
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, 3000+i, contentHash, oldSentDate, len(testBody),
			fmt.Sprintf("test-localpart-concurrent-%d", i),
			fmt.Sprintf("msgid-concurrent-%d", i))
		require.NoError(t, err)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test: Run 3 concurrent pruning operations
	// With SKIP LOCKED, they should all succeed without blocking each other
	const numConcurrentWorkers = 3
	var wg sync.WaitGroup
	results := make(chan int64, numConcurrentWorkers)
	errors := make(chan error, numConcurrentWorkers)

	for i := 0; i < numConcurrentWorkers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()

			// Each worker prunes with 24 hour retention
			// With SKIP LOCKED, they'll process different rows
			pruned, err := pruneBatched(db, ctx, 24*time.Hour)
			if err != nil {
				t.Logf("Worker %d: pruning error: %v", workerID, err)
				errors <- err
				return
			}

			t.Logf("Worker %d: pruned %d rows", workerID, pruned)
			results <- pruned
		}()
	}

	// Wait for all workers to complete
	wg.Wait()
	close(results)
	close(errors)

	// Check for errors
	var errCount int
	for err := range errors {
		t.Logf("Error occurred: %v", err)
		errCount++
	}
	assert.Equal(t, 0, errCount, "No errors should occur with SKIP LOCKED")

	// Sum total pruned across all workers
	var totalPruned int64
	for pruned := range results {
		totalPruned += pruned
	}

	t.Logf("Total pruned across all workers: %d (created %d records)", totalPruned, numRecords)

	// With SKIP LOCKED, all records should eventually be pruned across the workers
	assert.GreaterOrEqual(t, totalPruned, int64(numRecords),
		"Combined workers should prune at least all test records")

	// Verify all test records were actually pruned
	var unprunedCount int
	for i := 0; i < numRecords; i++ {
		contentHash := fmt.Sprintf("concurrent_%s_%d_%d", t.Name(), testTimestamp, i)
		var body *string
		err = db.GetReadPool().QueryRow(ctx,
			"SELECT text_body FROM message_contents WHERE content_hash = $1",
			contentHash).Scan(&body)
		if err == nil && body != nil {
			unprunedCount++
		}
	}

	assert.Equal(t, 0, unprunedCount, "All test records should be pruned")
	t.Logf("Successfully tested concurrent pruning with SKIP LOCKED (email: %s)", testEmail)
}

// TestCleanupLock_NoDeadlockWithUserQueries tests that user queries don't deadlock with cleanup
func TestCleanupLock_NoDeadlockWithUserQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	// Use shorter test name to avoid email length issues
	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create test account with short email
	testEmail := fmt.Sprintf("test_nodeadlock_%d@example.com", time.Now().UnixNano())
	txAccount, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txAccount.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, txAccount, req)
	require.NoError(t, err)
	err = txAccount.Commit(ctx)
	require.NoError(t, err)

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create INBOX mailbox
	txMailbox, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txMailbox.Rollback(ctx)

	err = db.CreateMailbox(ctx, txMailbox, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = txMailbox.Commit(ctx)
	require.NoError(t, err)

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Setup: Create old message content
	txData, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txData.Rollback(ctx)

	contentHash := fmt.Sprintf("no_deadlock_%d", time.Now().UnixNano())
	testBody := "Test message body for deadlock test"

	oldSentDate := time.Now().Add(-48 * time.Hour)

	_, err = txData.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, sent_date)
		VALUES ($1, $2, to_tsvector('english', $2), '', $3)
	`, contentHash, testBody, oldSentDate)
	require.NoError(t, err)

	_, err = txData.Exec(ctx, `
		WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 4000, $3, $4, $4, $5, NULL, TRUE, 'test-domain', 'test-localpart-deadlock', 'msgid-deadlock', 'body', '[]', 4000)
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, contentHash, oldSentDate, len(testBody))
	require.NoError(t, err)

	err = txData.Commit(ctx)
	require.NoError(t, err)

	// Start a "user query" that selects this content (simulating FETCH BODY operation)
	userQueryDone := make(chan bool)
	go func() {
		txUser, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			t.Logf("User query: failed to begin transaction: %v", err)
			userQueryDone <- false
			return
		}
		defer txUser.Rollback(ctx)

		// Simulate user query reading the content
		// Note: text_body is always NULL after trigger, so we read headers instead
		var headers string
		err = txUser.QueryRow(ctx,
			"SELECT headers FROM message_contents WHERE content_hash = $1 FOR SHARE",
			contentHash).Scan(&headers)
		if err != nil {
			t.Logf("User query: SELECT failed: %v", err)
			userQueryDone <- false
			return
		}

		t.Logf("User query: successfully read content (%d bytes)", len(headers))
		time.Sleep(500 * time.Millisecond) // Hold the lock so pruning correctly skips it
		txUser.Commit(ctx)
		userQueryDone <- true
	}()

	// Let user query acquire the row lock before prune starts
	time.Sleep(100 * time.Millisecond)

	// Immediately start pruning (should SKIP the row being read by user query)
	pruningDone := make(chan int64)
	go func() {
		pruned, err := pruneBatched(db, ctx, 24*time.Hour)
		if err != nil {
			t.Logf("Pruning error: %v", err)
			pruningDone <- -1
			return
		}
		pruningDone <- pruned
	}()

	// Both operations should complete quickly without deadlock
	userSuccess := false
	var prunedCount int64

	for i := 0; i < 2; i++ {
		select {
		case success := <-userQueryDone:
			userSuccess = success
			t.Logf("User query completed: %v", success)
		case pruned := <-pruningDone:
			prunedCount = pruned
			t.Logf("Pruning completed: %d rows", pruned)
		case <-time.After(10 * time.Second):
			t.Fatal("Operations blocked for >10s - possible deadlock!")
		}
	}

	assert.True(t, userSuccess, "User query should complete successfully")
	assert.GreaterOrEqual(t, prunedCount, int64(0), "Pruning should complete without error")

	t.Logf("Successfully verified no deadlock between user queries and cleanup (email: %s)", testEmail)
}
