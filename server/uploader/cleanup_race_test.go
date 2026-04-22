package uploader

// This file contains a test that reproduces the race condition where
// cleanupOrphanedFiles() deletes a local upload file whose corresponding
// pending_upload DB record hasn't committed yet.
//
// Scenario:
//  1. A message is delivered: StoreLocally() writes the file to disk.
//  2. The DB transaction (InsertMessage + pending_uploads INSERT) is still in-flight.
//  3. cleanupOrphanedFiles() fires (e.g., on the 5-minute tick).
//  4. The file is old enough to pass the grace-period check (or clock skew bypassed it).
//  5. PendingUploadExistsWithRetry() returns false — the record isn't visible yet.
//  6. The file is deleted by cleanupOrphanedFiles().
//  7. The DB transaction commits: pending_upload record now exists, but the file is gone.
//  8. Every subsequent upload attempt fails with "no such file or directory".
//     The upload reaches maxAttempts and stays stuck forever. S3 shows MISSING.
//
// The test below is intentionally written to FAIL against the current code,
// proving that the safety invariant is violated.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- minimal mock for UploaderDB ---

type mockUploaderDB struct {
	mock.Mock
}

func (m *mockUploaderDB) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	args := m.Called(ctx, instanceID, batchSize, retryInterval, maxAttempts)
	return args.Get(0).([]db.PendingUpload), args.Error(1)
}
func (m *mockUploaderDB) ExhaustUploadAttemptsWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error {
	return nil
}

func (m *mockUploaderDB) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	args := m.Called(ctx, contentHash, accountID)
	return args.Error(0)
}
func (m *mockUploaderDB) GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error) {
	args := m.Called(ctx, accountID)
	return args.Get(0).(server.Address), args.Error(1)
}
func (m *mockUploaderDB) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	args := m.Called(ctx, contentHash, accountID)
	return args.Bool(0), args.Error(1)
}
func (m *mockUploaderDB) ExecuteWithS3ObjectSessionLock(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error {
	args := m.Called(ctx, contentHash, accountID, executionFunc)
	if args.Bool(0) {
		err := executionFunc()
		if err != nil {
			return err
		}
	}
	return args.Error(1)
}
func (m *mockUploaderDB) CompleteS3UploadWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	args := m.Called(ctx, contentHash, accountID)
	return args.Error(0)
}
func (m *mockUploaderDB) PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	args := m.Called(ctx, contentHash, accountID)
	return args.Bool(0), args.Error(1)
}
func (m *mockUploaderDB) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	args := m.Called(ctx, maxAttempts)
	return args.Get(0).(*db.UploaderStats), args.Error(1)
}
func (m *mockUploaderDB) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error) {
	args := m.Called(ctx, maxAttempts, limit)
	return args.Get(0).([]db.PendingUpload), args.Error(1)
}

// --- mock S3 (not used by cleanupOrphanedFiles, but needed to construct UploadWorker) ---

type mockUploaderS3 struct{ mock.Mock }

func (m *mockUploaderS3) PutWithRetry(ctx context.Context, key string, reader io.Reader, size int64) error {
	return m.Called(ctx, key, reader, size).Error(0)
}

func (m *mockUploaderS3) ExistsWithRetry(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

// --- mock cache (not used by cleanupOrphanedFiles) ---

type mockUploaderCache struct{ mock.Mock }

func (m *mockUploaderCache) MoveIn(srcPath, contentHash string) error {
	return m.Called(srcPath, contentHash).Error(0)
}

// TestCleanupOrphanedFiles_RaceCondition_DeletesFileThatHasNoPendingUploadYet
// is the reproducer for the stuck-upload bug.
//
// It FAILS on the current code because cleanupOrphanedFiles() deletes the upload
// file when PendingUploadExistsWithRetry() returns false, even though the DB
// record may simply not have been committed yet at the time of the check.
//
// Expected (correct) behaviour: the file MUST NOT be deleted solely because the
// DB query returned false — that query can race with a concurrent INSERT transaction.
func TestCleanupOrphanedFiles_RaceCondition_DeletesFileThatHasNoPendingUploadYet(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	// Use the real content hash from the incident report.
	const contentHash = "66e220f43502b70618aa883c92a63ce46daf366e9b7d81e52c76698ee6137945"
	const accountID = int64(22385)

	// Write the file exactly as StoreLocally() would.
	filePath := worker.FilePath(contentHash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, []byte("large message body — 8.4 MB in production"), 0644))

	// Back-date the file's mtime so it appears older than the 10-minute grace
	// period. This is the condition that lets the cleanup code consider it.
	//
	// In production this can happen due to:
	//   • clock skew between the process and the filesystem
	//   • the file surviving a server crash and being re-examined on restart
	//     with its original (old) mtime
	//   • the grace period simply being too short
	backdated := time.Now().Add(-15 * time.Minute)
	require.NoError(t, os.Chtimes(filePath, backdated, backdated))

	// Simulate the race window: the DB transaction has not committed yet, so
	// PendingUploadExists returns false.  In production this happened because
	// the large (8.4 MB) InsertMessage transaction took long enough for the
	// cleanup ticker to fire in between StoreLocally() and the COMMIT.
	mockDB.On("PendingUploadExistsWithRetry", mock.Anything, contentHash, accountID).
		Return(false, nil)

	ctx := context.Background()
	err := worker.cleanupOrphanedFiles(ctx)
	require.NoError(t, err)

	// SAFETY INVARIANT: the file must still be present.
	//
	// Even though the DB returned false, we cannot know whether that is because:
	//   (a) the file is truly orphaned and can be safely deleted, OR
	//   (b) the INSERT transaction simply hasn't committed yet.
	//
	// Deleting the file in case (b) causes permanent, unrecoverable message loss:
	// the pending_upload record will commit moments later, the uploader will find
	// "no such file or directory" on every attempt, exhaust maxAttempts, and the
	// message will be stuck forever — exactly what we observed in production.
	//
	// This assertion FAILS with the current code, demonstrating the bug.
	if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
		t.Fatal(
			"BUG REPRODUCED: cleanupOrphanedFiles() deleted the upload file because " +
				"PendingUploadExistsWithRetry() returned false, but that false result " +
				"can be caused by a DB transaction that hasn't committed yet.\n\n" +
				"Consequence in production: the pending_upload record commits moments " +
				"later, the uploader retries 5 times with 'no such file or directory', " +
				"exhausts maxAttempts, and the 8.4 MB message (id=6197517) is stuck " +
				"forever with S3 status MISSING.\n\n" +
				"Fix: increase the grace period significantly (e.g. 1 hour) so that " +
				"no in-flight transaction can still be open when the cleanup runs, or " +
				"perform a second existence check after a delay before deleting.",
		)
	}
}

// TestCleanupOrphanedFiles_SafelyDeletesTrulyOrphanedFile verifies the happy
// path: a file that is old AND has no pending_upload record AND the DB has had
// plenty of time to commit should be removed.
//
// This test passes both before and after any fix.
func TestCleanupOrphanedFiles_SafelyDeletesTrulyOrphanedFile(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	const contentHash = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
	const accountID = int64(99999)

	filePath := worker.FilePath(contentHash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, []byte("orphaned file — no DB record"), 0644))

	// File is 2 hours old — well past any reasonable grace period.
	veryOld := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(filePath, veryOld, veryOld))

	// No pending_upload record exists (truly orphaned).
	mockDB.On("PendingUploadExistsWithRetry", mock.Anything, contentHash, accountID).
		Return(false, nil)

	ctx := context.Background()
	err := worker.cleanupOrphanedFiles(ctx)
	require.NoError(t, err)

	// File should have been removed — it is genuinely orphaned.
	_, statErr := os.Stat(filePath)
	require.True(t, os.IsNotExist(statErr),
		"Expected truly orphaned file (2h old, no DB record) to be deleted by cleanup")
}

// TestProcessSingleUpload_S3ExistsButLocalFileMissing_SelfHeals is the reproducer
// for the second category of stuck uploads visible in `sora admin uploader status`:
// those where S3 Status = "✓ EXISTS" but the upload is stuck at maxAttempts.
//
// Scenario (from the incident report, e.g. upload id=6257780, account=23410):
//  1. A message is delivered: StoreLocally() writes the file, DB transaction commits.
//  2. The uploader picks up the pending_upload, reads the file, PUT to S3 succeeds.
//  3. CompleteS3UploadWithRetry() fails (DB error / crash) — messages stay uploaded=FALSE
//     and the pending_upload record is NOT deleted.
//  4. The local file is moved to cache or deleted (normal post-upload cleanup), OR
//     cleanupOrphanedFiles deletes it on a subsequent tick now that the file is
//     considered processed.
//  5. On every subsequent uploader cycle:
//     a) IsContentHashUploadedWithRetry → false (messages.uploaded still FALSE)
//     b) os.ReadFile(filePath) → "no such file or directory"
//     c) [OLD CODE] MarkUploadAttemptWithRetry is called → attempts++
//     d) After 5 attempts the record is "failed" with S3 status = ✓ EXISTS
//  6. [DANGER] CleanupFailedUploads() eventually runs and executes:
//     DELETE FROM messages WHERE uploaded = FALSE AND created_at < threshold
//     This deletes the user's messages from their mailbox even though the content
//     is safely stored in S3.  The messages are gone.
//
// The fix: when os.ReadFile fails with ENOENT, check S3 first.
// If the object is already in S3, call CompleteS3UploadWithRetry() directly —
// self-healing the record without incrementing attempts.
//
// This test FAILS on old code (MarkUploadAttemptWithRetry is called instead of
// CompleteS3UploadWithRetry) and PASSES on the fixed code.
func TestProcessSingleUpload_S3ExistsButLocalFileMissing_SelfHeals(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)
	mockS3 := new(mockUploaderS3)

	worker := &UploadWorker{
		rdb:         mockDB,
		s3:          mockS3,
		path:        uploadDir,
		maxAttempts: 5,
	}

	// Use real content hash and account from the incident report (✓ EXISTS records).
	const contentHash = "74cde70321a488a473eba745666968b326bc32725dc0989f9bfd433cacc19c48"
	const accountID = int64(23410)

	// Deliberately do NOT create the local file — it was deleted after the first
	// successful S3 PUT, or by cleanupOrphanedFiles, or by the cache move.
	// The file is gone; S3 still has the content.

	// DB: messages are NOT yet marked as uploaded (CompleteS3Upload never ran).
	mockDB.On("GetPrimaryEmailForAccountWithRetry", mock.Anything, accountID).
		Return(serverAddress(t, "user@somedomain.com"), nil)
	mockDB.On("IsContentHashUploadedWithRetry", mock.Anything, contentHash, accountID).
		Return(false, nil)

	// Since we mock S3 existence as true, ExistsWithRetry returns true, but we actually
	// DO need to simulate the execution of ExecuteWithS3ObjectSessionLock since the uploader runs it.
	mockDB.On("ExecuteWithS3ObjectSessionLock", mock.Anything, contentHash, accountID, mock.Anything).
		Return(true, nil)

	// S3: object already exists (the first uploader attempt PUT it there).
	mockS3.On("ExistsWithRetry", mock.Anything, mock.AnythingOfType("string")).
		Return(true, nil)

	// We expect the self-heal path to call CompleteS3UploadWithRetry, NOT MarkUploadAttemptWithRetry.
	var completeCalled bool
	mockDB.On("CompleteS3UploadWithRetry", mock.Anything, contentHash, accountID).
		Run(func(args mock.Arguments) { completeCalled = true }).
		Return(nil)

	ctx := context.Background()
	worker.processSingleUpload(ctx, db.PendingUpload{
		ID:          6257780,
		AccountID:   accountID,
		ContentHash: contentHash,
		Size:        26700,
		Attempts:    4, // one more would reach maxAttempts and trigger CleanupFailedUploads
	})

	// SAFETY INVARIANT: MarkUploadAttemptWithRetry must NOT have been called.
	//
	// Old code called it here, which would:
	//   • push attempts to 5 (== maxAttempts)
	//   • leave the record as "failed" with S3 status ✓ EXISTS
	//   • allow CleanupFailedUploads to later execute:
	//       DELETE FROM messages WHERE uploaded = FALSE AND created_at < threshold
	//   • permanently deleting the user's messages even though their content is
	//     safely stored in S3 and could have been recovered with a single DB call.
	mockDB.AssertNotCalled(t, "MarkUploadAttemptWithRetry",
		mock.Anything, mock.Anything, mock.Anything)

	if !completeCalled {
		t.Fatal(
			"BUG REPRODUCED: processSingleUpload() did not call CompleteS3UploadWithRetry " +
				"when the local file was missing but S3 already had the content.\n\n" +
				"Old code consequence: MarkUploadAttemptWithRetry was called instead, " +
				"incrementing attempts toward maxAttempts. Once maxAttempts is reached, " +
				"CleanupFailedUploads deletes the user's messages (uploaded=FALSE) even " +
				"though their content exists in S3 — silent, permanent data loss.\n\n" +
				"Fix: add an S3 existence check when os.ReadFile fails with ENOENT. " +
				"If the object is already in S3, call CompleteS3UploadWithRetry directly " +
				"to mark messages as uploaded and remove the pending_upload record.",
		)
	}
}

// serverAddress is a small helper to parse an email address for use in tests.
func serverAddress(t *testing.T, addr string) server.Address {
	t.Helper()
	a, err := server.NewAddress(addr)
	if err != nil {
		t.Fatalf("serverAddress(%q): %v", addr, err)
	}
	return a
}

// TestCleanupOrphanedFiles_LargeBacklog_DoesNotDeleteQueuedUploads answers the question:
// "could this happen when there are many upload entries so the cleanup runs before
// they finish?"
//
// Architecture note: the run() goroutine uses a single-goroutine select loop:
//
//	for {
//	    select {
//	    case <-ticker.C:          processQueue(ctx)          // blocks until all batches done
//	    case <-cleanupTicker.C:   cleanupOrphanedFiles(ctx)  // only runs after processQueue returns
//	    }
//	}
//
// This means cleanup and processQueue are STRICTLY SEQUENTIAL — cleanup cannot
// fire while a batch is in-flight inside the same run() goroutine.
//
// The only true concurrency is between StoreLocally() (called from LMTP handler
// goroutines) and the cleanup ticker. But for files whose pending_upload records
// are already committed in the database, cleanup will see them via
// PendingUploadExistsWithRetry and leave them untouched regardless of how large
// the backlog is or how long the uploader takes.
//
// The dangerous window is ONLY: file written on disk → DB transaction not yet
// committed. That window is eliminated by the 1-hour grace period.
func TestCleanupOrphanedFiles_LargeBacklog_DoesNotDeleteQueuedUploads(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	// Simulate a burst of 6 messages for account 23410 (exactly as in the incident
	// report), all written by LMTP handlers, with their pending_upload records
	// already committed to the database. The uploader has a large backlog and
	// hasn't processed these files yet — but cleanup must not delete them.
	type pendingFile struct {
		hash       string
		accountID  int64
		ageMinutes int
	}

	files := []pendingFile{
		{"74cde70321a488a473eba745666968b326bc32725dc0989f9bfd433cacc19c48", 23410, 90},
		{"142f24aa9ea6bca62e9b7dae534d642150ff76c6cbc4962a1bcfd8ba4cd5142f", 23410, 89},
		{"fce22e75834a1c0ddde1da06f6b029244d463e61475cfa7063111d0973283db5", 23410, 88},
		{"e43c9ac6261d6a740eb999c60ab31cafb6b12978307e42d55d90b03ef59757fb", 23410, 87},
		{"4b229df84481f22ebdfc09e7c3d483c79f795afbce39cb76e8a90c38b217e4f7", 23410, 86},
		{"d98b2379fb5df905b50447e3357cd02242c60176e18f35e3c941addc95c8278f", 23410, 85},
	}

	// Write all files and back-date them so they are past the 1-hour grace period
	// (simulating a large backlog where uploads haven't been processed for >1 hour).
	// In this scenario the uploader is busy; cleanup runs first.
	for _, f := range files {
		fp := worker.FilePath(f.hash, f.accountID)
		require.NoError(t, os.MkdirAll(filepath.Dir(fp), 0755))
		require.NoError(t, os.WriteFile(fp, []byte("message body"), 0644))
		old := time.Now().Add(-time.Duration(f.ageMinutes) * time.Minute)
		require.NoError(t, os.Chtimes(fp, old, old))

		// CRITICAL: each file has its pending_upload record committed in the DB.
		// This is the normal case — LMTP committed the transaction successfully.
		// The uploader just hasn't gotten to these uploads yet (large backlog).
		mockDB.On("PendingUploadExistsWithRetry", mock.Anything, f.hash, f.accountID).
			Return(true, nil)
	}

	ctx := context.Background()
	err := worker.cleanupOrphanedFiles(ctx)
	require.NoError(t, err)

	// ALL files must still be present — they have committed pending_upload records
	// and are waiting to be processed by the uploader.
	// A large backlog does NOT cause cleanup to delete queued uploads.
	for _, f := range files {
		fp := worker.FilePath(f.hash, f.accountID)
		_, statErr := os.Stat(fp)
		require.NoError(t, statErr,
			"File with committed pending_upload must NOT be deleted by cleanup, "+
				"even if it is >1 hour old and the uploader has a large backlog. "+
				"hash=%s account=%d", f.hash[:16], f.accountID)
	}

	// Every file should have been checked against the database.
	mockDB.AssertNumberOfCalls(t, "PendingUploadExistsWithRetry", len(files))
}

// TestCleanupOrphanedFiles_SkipsFilesWithinGracePeriod verifies that files
// newer than the grace period are never touched, regardless of DB state.
func TestCleanupOrphanedFiles_SkipsFilesWithinGracePeriod(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	const contentHash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	const accountID = int64(12345)

	filePath := worker.FilePath(contentHash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, []byte("fresh file"), 0644))
	// mtime is NOW — definitely within any grace period

	// DB should never even be consulted for recent files.
	// If PendingUploadExistsWithRetry is called for a file this fresh, that itself
	// is a bug (unnecessary DB round-trip, and may return a false negative).

	ctx := context.Background()
	err := worker.cleanupOrphanedFiles(ctx)
	require.NoError(t, err)

	_, statErr := os.Stat(filePath)
	require.NoError(t, statErr, "File within grace period must not be deleted")

	mockDB.AssertNotCalled(t, "PendingUploadExistsWithRetry",
		mock.Anything, mock.Anything, mock.Anything)
}
