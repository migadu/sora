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
	"github.com/migadu/sora/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks & Test Helpers ---

type mockDB struct {
	AcquireAndLeasePendingUploadsWithRetryFunc func(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error)
	MarkUploadAttemptWithRetryFunc             func(ctx context.Context, contentHash string, accountID int64) error
	ExhaustUploadAttemptsWithRetryFunc         func(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error
	GetPrimaryEmailForAccountWithRetryFunc     func(ctx context.Context, accountID int64) (server.Address, error)
	IsContentHashUploadedWithRetryFunc         func(ctx context.Context, contentHash string, accountID int64) (bool, error)
	ExecuteWithS3ObjectSessionLockFunc         func(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error
	CompleteS3UploadWithRetryFunc              func(ctx context.Context, contentHash string, accountID int64) error
	PendingUploadExistsWithRetryFunc           func(ctx context.Context, contentHash string, accountID int64) (bool, error)
	GetFailedUploadsWithRetryFunc              func(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error)
}

func (m *mockDB) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	return m.AcquireAndLeasePendingUploadsWithRetryFunc(ctx, instanceID, batchSize, retryInterval, maxAttempts)
}

func (m *mockDB) ExhaustUploadAttemptsWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error {
	if m.ExhaustUploadAttemptsWithRetryFunc != nil {
		return m.ExhaustUploadAttemptsWithRetryFunc(ctx, contentHash, accountID, maxAttempts)
	}
	return nil
}

func (m *mockDB) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	if m.MarkUploadAttemptWithRetryFunc != nil {
		return m.MarkUploadAttemptWithRetryFunc(ctx, contentHash, accountID)
	}
	return nil
}

func (m *mockDB) GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error) {
	if m.GetPrimaryEmailForAccountWithRetryFunc != nil {
		return m.GetPrimaryEmailForAccountWithRetryFunc(ctx, accountID)
	}
	return server.NewAddress("user@example.com")
}

func (m *mockDB) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	return m.IsContentHashUploadedWithRetryFunc(ctx, contentHash, accountID)
}

func (m *mockDB) CompleteS3UploadWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	return m.CompleteS3UploadWithRetryFunc(ctx, contentHash, accountID)
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

func (m *mockDB) PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	if m.PendingUploadExistsWithRetryFunc != nil {
		return m.PendingUploadExistsWithRetryFunc(ctx, contentHash, accountID)
	}
	return false, nil
}

func (m *mockDB) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error) {
	return nil, nil
}

func (m *mockDB) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	return nil, nil
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
	rdb.GetPrimaryEmailForAccountWithRetryFunc = func(ctx context.Context, accountID int64) (server.Address, error) {
		return server.NewAddress("user@example.com")
	}
	rdb.IsContentHashUploadedWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) (bool, error) {
		return false, nil
	}
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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
		rdb.IsContentHashUploadedWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) (bool, error) {
			return false, nil
		}
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			s3Put.Store(true)
			expectedKey := fmt.Sprintf("example.com/user/%s", testHash)
			assert.Equal(t, expectedKey, key)
			return nil
		}
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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

	t.Run("get primary email fails", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		var markedAttempt atomic.Bool
		rdb.GetPrimaryEmailForAccountWithRetryFunc = func(ctx context.Context, accountID int64) (server.Address, error) {
			return server.Address{}, errors.New("db error")
		}
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}

		worker.processSingleUpload(context.Background(), baseUpload)
		assert.True(t, markedAttempt.Load())
	})

	t.Run("content already uploaded", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		var completed atomic.Bool
		var s3PutCalled atomic.Bool
		rdb.IsContentHashUploadedWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) (bool, error) {
			return true, nil
		}
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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

	t.Run("local file missing and S3 also missing — exhausts attempts immediately", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		// Don't create the local file; S3 also does not have it.
		// The worker should immediately exhaust all remaining attempts so the record
		// moves to the "failed" list on the very next monitor tick rather than cycling
		// through every remaining retry slot (wasting maxAttempts × retryInterval).

		var exhausted atomic.Bool
		var markedAttempt atomic.Bool
		rdb.ExhaustUploadAttemptsWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error {
			exhausted.Store(true)
			assert.Equal(t, worker.maxAttempts, maxAttempts)
			return nil
		}
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}
		s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) {
			return false, nil // S3 doesn't have it either
		}

		worker.processSingleUpload(context.Background(), baseUpload)
		assert.True(t, exhausted.Load(), "ExhaustUploadAttempts should be called when content is permanently lost")
		assert.False(t, markedAttempt.Load(), "MarkUploadAttempt must NOT be called — ExhaustUploadAttempts supersedes it")
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
		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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

	t.Run("s3 upload fails", func(t *testing.T) {
		worker, rdb, s3, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		var markedAttempt atomic.Bool
		s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
			return errors.New("s3 is down")
		}
		rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
			markedAttempt.Store(true)
			return nil
		}

		worker.processSingleUpload(context.Background(), baseUpload)

		assert.True(t, markedAttempt.Load())
		_, err := os.Stat(filePath)
		assert.NoError(t, err, "local file should NOT be removed if S3 upload fails")
	})

	t.Run("db completion fails", func(t *testing.T) {
		worker, rdb, _, _, _ := setupTestWorker(t)
		filePath := createLocalFile(t, worker)

		rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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
		rdb.GetPrimaryEmailForAccountWithRetryFunc = func(ctx context.Context, accountID int64) (server.Address, error) {
			// This function is called for every valid upload that is processed.
			processedCount.Add(1)
			return server.NewAddress("user@example.com")
		}

		// Run the function under test
		err := worker.processPendingUploads(context.Background())
		require.NoError(t, err)

		// Assert that the loop was entered.
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
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
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

	rdb.IsContentHashUploadedWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) (bool, error) {
		return false, nil
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
