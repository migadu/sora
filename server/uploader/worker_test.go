package uploader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks & Test Helpers ---

type mockDB struct {
	AcquireAndLeasePendingUploadsWithRetryFunc func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error)
	MarkUploadAttemptWithRetryFunc             func(ctx context.Context, contentHash string, accountID int64) error
	PendingUploadKeysFunc                      func(ctx context.Context, contentHash string, accountID int64) ([]string, error)
	ExecuteWithS3ObjectSessionLockFunc         func(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error
	CompleteS3UploadWithRetryFunc              func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error
	ExistingPendingUploadsFunc                 func(ctx context.Context, accountID int64, contentHashes []string) (map[string]struct{}, error)
	GetFailedUploadsWithRetryFunc              func(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error)
	GetUploaderStatsWithRetryFunc              func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error)
	PendingUploadBacklogFunc                   func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error)
}

func (m *mockDB) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	return m.AcquireAndLeasePendingUploadsWithRetryFunc(ctx, instanceID, batchSize, retryInterval, maxAttempts)
}

func (m *mockDB) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	if m.MarkUploadAttemptWithRetryFunc != nil {
		return m.MarkUploadAttemptWithRetryFunc(ctx, contentHash, accountID)
	}
	return nil
}

func (m *mockDB) PendingUploadKeys(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
	if m.PendingUploadKeysFunc != nil {
		return m.PendingUploadKeysFunc(ctx, contentHash, accountID)
	}
	return []string{helpers.NewS3Key("example.com", "user", contentHash)}, nil
}

func (m *mockDB) CompleteS3UploadWithRetry(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
	return m.CompleteS3UploadWithRetryFunc(ctx, contentHash, accountID, writtenKeys)
}

func (m *mockDB) ExecuteWithS3ObjectSessionLock(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error {
	if m.ExecuteWithS3ObjectSessionLockFunc != nil {
		return m.ExecuteWithS3ObjectSessionLockFunc(ctx, contentHash, accountID, executionFunc)
	}
	// Fallback behavior: just execute the operation
	err := executionFunc()
	if err != nil {
		return err
	}
	// Note: We leave CompleteS3UploadWithRetry up to the test to verify usually.
	// We do NOT explicitly call it here because `executionFunc` inside UploaderWorker
	// calls CompleteS3UploadWithRetry internally now.
	return nil
}

func (m *mockDB) ExistingPendingUploads(ctx context.Context, accountID int64, contentHashes []string) (map[string]struct{}, error) {
	if m.ExistingPendingUploadsFunc != nil {
		return m.ExistingPendingUploadsFunc(ctx, accountID, contentHashes)
	}
	return nil, nil
}

func (m *mockDB) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error) {
	return nil, nil
}

func (m *mockDB) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	if m.GetUploaderStatsWithRetryFunc != nil {
		return m.GetUploaderStatsWithRetryFunc(ctx, maxAttempts)
	}
	return &db.UploaderStats{}, nil
}

func (m *mockDB) PendingUploadBacklog(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
	if m.PendingUploadBacklogFunc != nil {
		return m.PendingUploadBacklogFunc(ctx, instanceID, maxAttempts)
	}
	return UploadBacklog{}, nil
}

func (m *mockDB) RecordInstanceHeartbeatWithRetry(ctx context.Context, instanceID string) error {
	return nil
}

type mockS3 struct {
	PutWithRetryFunc    func(ctx context.Context, key string, reader io.Reader, size int64) error
	ExistsWithRetryFunc func(ctx context.Context, key string) (bool, error)
}

func (m *mockS3) PutWithRetry(ctx context.Context, key string, reader io.Reader, size int64) error {
	return m.PutWithRetryFunc(ctx, key, reader, size)
}

func (m *mockS3) ExistsWithRetry(ctx context.Context, key string) (bool, error) {
	if m.ExistsWithRetryFunc != nil {
		return m.ExistsWithRetryFunc(ctx, key)
	}
	return false, nil
}

type mockCache struct {
	MoveInFunc func(srcPath, contentHash string) error
}

func (m *mockCache) MoveIn(srcPath, contentHash string) error {
	return m.MoveInFunc(srcPath, contentHash)
}

func setupTestWorker(t *testing.T) (*UploadWorker, *mockDB, *mockS3, *mockCache, string) {
	tempDir := t.TempDir()
	errCh := make(chan error, 1)

	rdb := &mockDB{}
	// Provide default implementations for mock functions to avoid nil panics
	rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
		return nil, nil
	}
	rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
		return nil
	}
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
		return nil
	}

	s3 := &mockS3{}
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		return nil
	}
	s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) {
		return false, nil
	}

	cache := &mockCache{}
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		return nil
	}

	worker := &UploadWorker{
		rdb:           rdb,
		s3:            s3,
		cache:         cache,
		path:          tempDir,
		batchSize:     10,
		concurrency:   5,
		maxAttempts:   3,
		retryInterval: 1 * time.Second,
		instanceID:    "test-instance",
		notifyCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		errCh:         errCh,
	}

	return worker, rdb, s3, cache, tempDir
}

// --- Tests ---

func TestIsValidContentHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"valid lowercase", "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01", true},
		{"valid uppercase", "B3A8E0E1F9AB1BFE3A36F231F676F7E08A43AC7F0B6A53873B52444D67707D01", true},
		{"valid mixed case", "b3a8e0e1f9ab1bfe3A36F231F676F7E08a43ac7f0b6a53873b52444d67707d01", true},
		{"invalid length short", "b3a8e0e1f9ab1bfe3a36f231f676f7e0", false},
		{"invalid length long", "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01aa", false},
		{"invalid character", "g3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01", false},
		{"empty string", "", false},
		{"contains space", "b3a8e0e1f9ab1bfe3a36f231f676f7e0 8a43ac7f0b6a53873b52444d67707d01", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidContentHash(tt.hash))
		})
	}
}

func TestFilePath(t *testing.T) {
	w := &UploadWorker{path: "/tmp/uploads"}

	t.Run("valid hash", func(t *testing.T) {
		hash := "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
		accountID := int64(123)
		expected := filepath.Join("/tmp/uploads", "123", hash)
		assert.Equal(t, expected, w.FilePath(hash, accountID))
	})

	t.Run("invalid hash", func(t *testing.T) {
		hash := "../../../etc/passwd"
		accountID := int64(123)
		expected := filepath.Join("/tmp/uploads", "invalid", "invalid")
		assert.Equal(t, expected, w.FilePath(hash, accountID))
	})
}

func TestStoreLocally(t *testing.T) {
	worker, _, _, _, tempDir := setupTestWorker(t)
	hash := "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
	accountID := int64(456)
	data := []byte("test content")

	path, err := worker.StoreLocally(hash, accountID, data)
	require.NoError(t, err)
	require.NotNil(t, path)

	expectedPath := filepath.Join(tempDir, "456", hash)
	assert.Equal(t, expectedPath, *path)

	readData, err := os.ReadFile(*path)
	require.NoError(t, err)
	assert.Equal(t, data, readData)
}

func TestRemoveLocalFile(t *testing.T) {
	baseDir := t.TempDir()
	worker := &UploadWorker{path: baseDir}

	t.Run("removes file and empty parents", func(t *testing.T) {
		dir := filepath.Join(baseDir, "123", "subdir")
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)

		filePath := filepath.Join(dir, "testfile")
		err = os.WriteFile(filePath, []byte("data"), 0644)
		require.NoError(t, err)

		err = worker.RemoveLocalFile(filePath)
		require.NoError(t, err)

		_, err = os.Stat(filePath)
		assert.True(t, os.IsNotExist(err), "file should be removed")
		_, err = os.Stat(dir)
		assert.True(t, os.IsNotExist(err), "parent dir should be removed")
		_, err = os.Stat(filepath.Dir(dir))
		assert.True(t, os.IsNotExist(err), "grandparent dir should be removed")
		_, err = os.Stat(baseDir)
		assert.NoError(t, err, "base dir should not be removed")
	})

	t.Run("does not remove non-empty parent", func(t *testing.T) {
		dir := filepath.Join(baseDir, "456")
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)

		filePath1 := filepath.Join(dir, "file1")
		require.NoError(t, os.WriteFile(filePath1, []byte("data"), 0644))
		filePath2 := filepath.Join(dir, "file2")
		require.NoError(t, os.WriteFile(filePath2, []byte("data"), 0644))

		err = worker.RemoveLocalFile(filePath1)
		require.NoError(t, err)

		_, err = os.Stat(filePath1)
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(filePath2)
		assert.NoError(t, err)
		_, err = os.Stat(dir)
		assert.NoError(t, err)
	})
}

func TestNotifyUploadQueued(t *testing.T) {
	worker, _, _, _, _ := setupTestWorker(t)

	// Should not block
	worker.NotifyUploadQueued()

	// Channel should have one item
	assert.Len(t, worker.notifyCh, 1)

	// Second notification should not block or add more
	worker.NotifyUploadQueued()
	assert.Len(t, worker.notifyCh, 1)

	// Drain the channel
	<-worker.notifyCh
	assert.Len(t, worker.notifyCh, 0)
}

func TestProcessSingleUpload(t *testing.T) {
	const (
		testHash      = "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
		testAccountID = int64(123)
	)

	baseUpload := db.PendingUpload{
		ID:          1,
		AccountID:   testAccountID,
		ContentHash: testHash,
		Size:        9, // len("test data")
		Attempts:    0,
	}

	createLocalFile := func(t *testing.T, worker *UploadWorker) string {
		filePath := worker.FilePath(testHash, testAccountID)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
		require.NoError(t, os.WriteFile(filePath, []byte("test data"), 0644))
		return filePath
	}

	t.Run("successful upload", func(t *testing.T) {
		worker, rdb, s3, cache, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		var completed, s3Put, cacheMoved atomic.Bool
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			s3Put.Store(true)
			expectedKey := fmt.Sprintf("example.com/user/%s", testHash)
			assert.Equal(t, expectedKey, key)
			return nil
		}
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
			completed.Store(true)
			return nil
		}
		cache.MoveInFunc = func(srcPath, contentHash string) error {
			cacheMoved.Store(true)
			assert.Equal(t, filePath, srcPath)
			// Simulate the file being moved by removing the source.
			return os.Remove(srcPath)
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.True(t, s3Put.Load(), "S3 Put should be called")
		assert.True(t, completed.Load(), "DB completion should be called")
		assert.True(t, cacheMoved.Load(), "Cache move-in should be called")
		_, err := os.Stat(filePath)
		assert.True(t, os.IsNotExist(err), "local file should be removed after successful upload and cache move")
	})

	t.Run("invalid content hash", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		upload := baseUpload
		upload.ContentHash = "invalid-hash"

		var markedAttempt atomic.Bool
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			assert.Equal(t, "invalid-hash", contentHash)
			return nil
		}

		worker.processSingleUpload(context.Background(), upload)
		assert.True(t, markedAttempt.Load())
	})

	t.Run("storage key lookup fails — retried, never counted", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		var markedAttempt atomic.Bool
		rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
			return nil, errors.New("db error")
		}
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}

		outcome := worker.processSingleUpload(context.Background(), baseUpload)
		assert.Equal(t, uploadRetryLater, outcome)
		assert.False(t, markedAttempt.Load(), "a database error says nothing about the content; the row must stay retryable")
	})

	t.Run("content already uploaded", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		var completed atomic.Bool
		var s3PutCalled atomic.Bool
		rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
			return nil, nil
		}
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
			completed.Store(true)
			return nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			s3PutCalled.Store(true)
			return nil
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.False(t, s3PutCalled.Load(), "S3 Put should not be called")
		assert.True(t, completed.Load(), "DB completion should be called")
		_, err := os.Stat(filePath)
		assert.True(t, os.IsNotExist(err), "local file should be removed even if already uploaded")
	})

	t.Run("local file missing and S3 also missing — counts one attempt per observation", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		// Don't create the local file; S3 says it does not have it either. That is the
		// only evidence of permanent loss the worker ever gets, and it comes from a
		// single HEAD answer — B2 is known to answer 404 during outages — so it counts
		// as ONE attempt. The row is parked only after max_attempts consecutive
		// observations, never on the strength of one answer.

		var marked atomic.Int32
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			marked.Add(1)
			return nil
		}
		s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) {
			return false, nil // S3 doesn't have it either
		}

		outcome := worker.processSingleUpload(context.Background(), baseUpload)
		assert.Equal(t, uploadContentProblem, outcome, "lost content is the row's problem, not storage's")
		assert.Equal(t, int32(1), marked.Load(), "exactly one attempt is counted per missing+absent observation")
	})

	t.Run("local file missing but S3 has content — self-heals without marking attempt", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		// Don't create the local file — simulates cleanupOrphanedFiles race or lost file.
		// S3 however already has the content (✓ EXISTS scenario from the incident report).

		var markedAttempt atomic.Bool
		var completed atomic.Bool
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
			completed.Store(true)
			return nil
		}
		s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) {
			return true, nil // Content is already in S3
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.False(t, markedAttempt.Load(), "attempt must NOT be counted — self-heal should not exhaust max_attempts")
		assert.True(t, completed.Load(), "CompleteS3Upload must be called to mark messages as uploaded and unblock the user")
	})

	t.Run("s3 upload fails — retried, never counted, file kept", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		// A 403 the provider answered for 40 minutes on 2026-08-21 parked 4161 uploads
		// whose files were intact. No provider answer is evidence about the content on
		// disk, so no PUT failure — transient or "permanent" — may count toward
		// max_attempts. The file stays and the row is leased again after retry_interval.
		var markedAttempt atomic.Bool
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			return errors.New("operation error S3: PutObject, https response error StatusCode: 403, api error AccessDenied: Storage class not supported on this cluster: STANDARD")
		}
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}

		outcome := worker.processSingleUpload(context.Background(), baseUpload)

		assert.Equal(t, uploadRetryLater, outcome)
		assert.False(t, markedAttempt.Load(), "a provider rejection must not park an intact file")
		_, err := os.Stat(filePath)
		assert.NoError(t, err, "local file should NOT be removed if S3 upload fails")
	})

	t.Run("db completion fails", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
			return errors.New("db is down")
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		_, err := os.Stat(filePath)
		assert.NoError(t, err, "local file should NOT be removed if DB completion fails")
	})

	t.Run("move to cache fails", func(t *testing.T) {
		worker, _, _, cache, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		cache.MoveInFunc = func(srcPath, contentHash string) error {
			return errors.New("cache is full")
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		_, err := os.Stat(filePath)
		assert.True(t, os.IsNotExist(err), "local file should be removed even if cache move fails")
	})

	t.Run("empty file refuses upload", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		// Write an empty file (simulating disk corruption or truncation)
		filePath := worker.FilePath(testHash, testAccountID)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
		require.NoError(t, os.WriteFile(filePath, []byte{}, 0644))

		var markedAttempt atomic.Bool
		var s3PutCalled atomic.Bool
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			s3PutCalled.Store(true)
			return nil
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.False(t, s3PutCalled.Load(), "S3 Put must NOT be called for empty file")
		assert.True(t, markedAttempt.Load(), "upload attempt should be marked as failed")
	})

	t.Run("size mismatch refuses upload", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		// Write a file with different size than expected
		filePath := worker.FilePath(testHash, testAccountID)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
		require.NoError(t, os.WriteFile(filePath, []byte("short"), 0644)) // 5 bytes, expected 9

		var markedAttempt atomic.Bool
		var s3PutCalled atomic.Bool
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			s3PutCalled.Store(true)
			return nil
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.False(t, s3PutCalled.Load(), "S3 Put must NOT be called for size-mismatched file")
		assert.True(t, markedAttempt.Load(), "upload attempt should be marked as failed")
	})
}

func TestProcessPendingUploads(t *testing.T) {
	t.Run("processes a batch and skips uploads exceeding max attempts", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		worker.maxAttempts = 3 // Set for clarity

		// This batch contains one valid upload and one that should be skipped.
		uploadBatch := []db.PendingUpload{
			{ID: 1, AccountID: 100, ContentHash: "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01", Attempts: 0},
			{ID: 2, AccountID: 101, ContentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Attempts: 3}, // Should be skipped
			{ID: 3, AccountID: 102, ContentHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Attempts: 1},
		}

		// Mock the DB to return our batch on the first call, and an empty slice on the second to stop the loop.
		callCount := 0
		rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
			callCount++
			if callCount == 1 {
				return uploadBatch, nil
			}
			return []db.PendingUpload{}, nil // Empty slice to terminate the loop
		}

		// We can't easily mock processSingleUpload, so we'll count calls to one of its dependencies.
		var processedCount atomic.Int32
		rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
			// This function is called for every valid upload that is processed.
			processedCount.Add(1)
			return []string{helpers.NewS3Key("example.com", "user", contentHash)}, nil
		}

		// Run the function under test
		err := worker.processPendingUploads(context.Background())
		require.NoError(t, err)

		// The loop was entered and, although neither processed upload has a local file
		// (content problems, one attempt each), the pass went on to lease again: lost
		// bodies must not stall the queue behind them.
		assert.Equal(t, 2, callCount, "AcquireAndLeasePendingUploadsWithRetry should be called twice")

		// We expect 2 uploads to be processed (the one with 3 attempts should be skipped).
		assert.Equal(t, int32(2), processedCount.Load(), "should have processed 2 out of 3 uploads")
	})

	t.Run("returns error when acquiring uploads fails", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		dbError := errors.New("database is down")

		rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
			return nil, dbError
		}

		err := worker.processPendingUploads(context.Background())
		require.Error(t, err)
		assert.ErrorIs(t, err, dbError)
		assert.Contains(t, err.Error(), "failed to list pending uploads")
	})

	// A cycle in which every upload fails means the path to storage (or the database
	// behind it) is broken for everyone, not that any one upload is bad. Retrying a
	// thousand rows every retry_interval against a provider that is rejecting all of
	// them only multiplies the outage; the worker backs off exponentially instead and
	// resumes at full speed on the first success.
	t.Run("backs off after a cycle where every upload fails", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		worker.retryInterval = 30 * time.Second
		hash := "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
		filePath := worker.FilePath(hash, 100)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
		require.NoError(t, os.WriteFile(filePath, []byte("test data"), 0644))

		// One batch per cycle: the mock hands out the row once per armed cycle.
		var acquires, batchesLeft atomic.Int32
		rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
			acquires.Add(1)
			if batchesLeft.Add(-1) >= 0 {
				return []db.PendingUpload{{ID: 1, AccountID: 100, ContentHash: hash, Size: 9}}, nil
			}
			return nil, nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			return errors.New("403 AccessDenied")
		}

		batchesLeft.Store(1)
		require.NoError(t, worker.processPendingUploads(context.Background()))
		assert.Equal(t, int32(1), acquires.Load(), "an all-failed batch ends the pass; the rest of the queue is not leased")

		until, failures := worker.backoffState()
		assert.Equal(t, 1, failures)
		assert.WithinDuration(t, time.Now().Add(30*time.Second), until, 5*time.Second, "first backoff is one retry_interval")

		// While backing off, a ticker-driven cycle does not even touch the database.
		batchesLeft.Store(1)
		require.NoError(t, worker.processQueue(context.Background()))
		assert.Equal(t, int32(1), acquires.Load(), "no lease while backing off")

		// A drain (sync-upload mode, DrainSync) is not gated: a test that asks for the
		// queue to be processed must see every row processed.
		require.NoError(t, worker.DrainSync(context.Background()))
		assert.Equal(t, int32(2), acquires.Load(), "DrainSync leases despite the backoff")

		// A second all-failed cycle doubles the delay.
		worker.setBackoffForTest(time.Time{}, 1)
		batchesLeft.Store(1)
		require.NoError(t, worker.processPendingUploads(context.Background()))
		assert.Equal(t, int32(3), acquires.Load())
		until, failures = worker.backoffState()
		assert.Equal(t, 2, failures)
		assert.WithinDuration(t, time.Now().Add(60*time.Second), until, 5*time.Second)
	})

	// The shared integration database keeps pending rows of finished tests whose spool
	// files are gone. Ordered oldest first and leased ten at a time, they fill the head
	// of every pass; a fresh APPEND behind them was left un-uploaded when such a batch
	// counted as "every upload failed". Lost content is not a storage failure.
	t.Run("rows with lost bodies neither end the pass nor arm the backoff", func(t *testing.T) {
		worker, rdb, s3, cache, _ := setupTestWorker(t)
		good := "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
		goodPath := worker.FilePath(good, 100)
		require.NoError(t, os.MkdirAll(filepath.Dir(goodPath), 0755))
		require.NoError(t, os.WriteFile(goodPath, []byte("test data"), 0644))

		var acquires atomic.Int32
		rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
			switch acquires.Add(1) {
			case 1: // stale rows: no spool file, and S3 (mock) reports absent
				return []db.PendingUpload{
					{ID: 1, AccountID: 200, ContentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 9},
					{ID: 2, AccountID: 201, ContentHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Size: 9},
				}, nil
			case 2: // the fresh row behind them
				return []db.PendingUpload{{ID: 3, AccountID: 100, ContentHash: good, Size: 9}}, nil
			}
			return nil, nil
		}
		var uploaded atomic.Bool
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			uploaded.Store(true)
			return nil
		}
		cache.MoveInFunc = func(srcPath, contentHash string) error { return os.Remove(srcPath) }

		require.NoError(t, worker.processPendingUploads(context.Background()))
		assert.Equal(t, int32(3), acquires.Load(), "the pass continued past the stale batch")
		assert.True(t, uploaded.Load(), "the fresh row was uploaded in the same pass")
		until, failures := worker.backoffState()
		assert.Equal(t, 0, failures)
		assert.True(t, until.IsZero(), "lost bodies do not arm the backoff")
	})

	t.Run("backoff is capped and cleared by the first success", func(t *testing.T) {
		worker, rdb, s3, cache, _ := setupTestWorker(t)
		worker.retryInterval = 30 * time.Second
		hash := "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
		filePath := worker.FilePath(hash, 100)
		require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
		require.NoError(t, os.WriteFile(filePath, []byte("test data"), 0644))

		var batchesLeft atomic.Int32
		rdb.AcquireAndLeasePendingUploadsWithRetryFunc = func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
			if batchesLeft.Add(-1) >= 0 {
				return []db.PendingUpload{{ID: 1, AccountID: 100, ContentHash: hash, Size: 9}}, nil
			}
			return nil, nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			return errors.New("403 AccessDenied")
		}

		// Many consecutive failed cycles: the delay never exceeds the cap.
		worker.setBackoffForTest(time.Time{}, 20)
		batchesLeft.Store(1)
		require.NoError(t, worker.processPendingUploads(context.Background()))
		until, failures := worker.backoffState()
		assert.Equal(t, 21, failures)
		assert.WithinDuration(t, time.Now().Add(uploadBackoffMax), until, 5*time.Second, "delay is capped")

		// The provider recovers: one successful upload clears the backoff entirely.
		var uploaded atomic.Bool
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			uploaded.Store(true)
			return nil
		}
		cache.MoveInFunc = func(srcPath, contentHash string) error { return os.Remove(srcPath) }
		worker.setBackoffForTest(time.Time{}, 21)
		batchesLeft.Store(1)
		require.NoError(t, worker.processPendingUploads(context.Background()))
		assert.True(t, uploaded.Load(), "the recovered provider took the upload")
		until, failures = worker.backoffState()
		assert.Equal(t, 0, failures)
		assert.True(t, until.IsZero(), "backoff cleared after a success")
	})
}

// TestProcessSingleUpload_ShutdownDuringFinalization tests that when shutdown is requested
// after S3 upload completes but before DB finalization, the worker uses a background context
// to complete the DB update instead of failing with "context canceled".
func TestProcessSingleUpload_ShutdownDuringFinalization(t *testing.T) {
	worker, rdb, s3, cache, _ := setupTestWorker(t)

	// Create test upload
	upload := db.PendingUpload{
		ID:          1,
		AccountID:   100,
		ContentHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		Size:        9, // len("test data")
		CreatedAt:   time.Now(),
		Attempts:    0,
	}

	// Write local file
	filePath := worker.FilePath(upload.ContentHash, upload.AccountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, []byte("test data"), 0644))

	// Create a context that will be canceled
	ctx, cancel := context.WithCancel(context.Background())

	// Track S3 upload completion
	s3UploadCompleted := false
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		s3UploadCompleted = true
		// Simulate shutdown happening right after S3 upload
		cancel()
		return nil
	}

	// Track if DB finalization was attempted and succeeded
	dbFinalizationAttempted := false
	dbFinalizationSucceeded := false
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, writtenKeys []string) error {
		dbFinalizationAttempted = true
		// Verify we're using a background context (not canceled)
		select {
		case <-ctx.Done():
			return fmt.Errorf("DB finalization context is canceled")
		default:
			dbFinalizationSucceeded = true
			return nil
		}
	}

	cache.MoveInFunc = func(srcPath, contentHash string) error {
		return nil
	}

	// Process the upload
	worker.processSingleUpload(ctx, upload)

	// Verify expectations
	assert.True(t, s3UploadCompleted, "S3 upload should have completed")
	assert.True(t, dbFinalizationAttempted, "DB finalization should have been attempted")
	assert.True(t, dbFinalizationSucceeded, "DB finalization should have succeeded with background context")
}
