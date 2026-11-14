package uploader

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// TestConcurrentStoreLocallyDoesNotInflateStagingSize verifies that concurrent
// StoreLocally calls for the same (contentHash, accountID) count the staged body's
// bytes once in currentStagingSize rather than once per writer, so removing the
// staged file returns currentStagingSize to 0 and does not trip max_staging_size
// with phantom bytes.
func TestConcurrentStoreLocallyDoesNotInflateStagingSize(t *testing.T) {
	const (
		accountID = int64(814)
		writers   = 8
		rounds    = 5
	)

	body := bytes.Repeat([]byte("concurrent identical message body\r\n"), 2048)
	bodySize := int64(len(body))

	w := &UploadWorker{
		path:           t.TempDir(),
		maxStagingSize: 2 * bodySize,
	}

	for round := 1; round <= rounds; round++ {
		hash := fmt.Sprintf("%064x", round)

		var ready sync.WaitGroup
		var done sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, writers)
		var stagedPath string
		var pathOnce sync.Once

		ready.Add(writers)
		done.Add(writers)
		for range writers {
			go func() {
				defer done.Done()
				ready.Done()
				<-start
				p, err := w.StoreLocally(hash, accountID, body)
				if err == nil && p != nil {
					pathOnce.Do(func() { stagedPath = *p })
				}
				errs <- err
			}()
		}

		ready.Wait()
		close(start)
		done.Wait()
		close(errs)

		for err := range errs {
			require.NoError(t, err, "round %d: concurrent StoreLocally must succeed", round)
		}
		require.NotEmpty(t, stagedPath)

		require.Equal(t, bodySize, atomic.LoadInt64(&w.currentStagingSize),
			"round %d: %d concurrent stagings of one %d-byte body must count %d staged bytes, not a multiple",
			round, writers, bodySize, bodySize)
		require.False(t, w.IsStagingLimitExceeded(bodySize),
			"round %d: one %d-byte body staged under a %d-byte limit must leave room for a second body",
			round, bodySize, w.maxStagingSize)

		require.NoError(t, w.RemoveLocalFile(stagedPath))
		require.Equal(t, int64(0), atomic.LoadInt64(&w.currentStagingSize),
			"round %d: removing the single staged file must return currentStagingSize to 0", round)
		require.False(t, w.IsStagingLimitExceeded(bodySize),
			"round %d: an empty spool must not refuse new deliveries due to phantom staged bytes", round)
	}
}

// TestConcurrentStoreLocallyAndRemovalKeepStagingSizeExact exercises StoreLocally
// racing with both RemoveLocalFile and post-upload cache.MoveIn on the same path,
// ensuring currentStagingSize always matches what remains on disk.
func TestConcurrentStoreLocallyAndRemovalKeepStagingSizeExact(t *testing.T) {
	body := bytes.Repeat([]byte("interleaved stage and remove\r\n"), 1024)
	bodySize := int64(len(body))
	const (
		accountID = int64(815)
		hash      = "8150000000000000000000000000000000000000000000000000000000000815"
	)

	t.Run("StoreLocally with RemoveLocalFile", func(t *testing.T) {
		w := &UploadWorker{
			path:           t.TempDir(),
			maxStagingSize: 2 * bodySize,
		}
		path := w.FilePath(hash, accountID)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 10 {
					_, err := w.StoreLocally(hash, accountID, body)
					require.NoError(t, err)
				}
			}()
		}
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 10 {
					require.NoError(t, w.RemoveLocalFile(path))
				}
			}()
		}
		close(start)
		wg.Wait()

		expected := fileSize(path)
		require.Equal(t, expected, atomic.LoadInt64(&w.currentStagingSize),
			"currentStagingSize must match actual bytes on disk after concurrent StoreLocally and RemoveLocalFile")
		if expected > 0 {
			require.NoError(t, w.RemoveLocalFile(path))
		}
		require.Equal(t, int64(0), atomic.LoadInt64(&w.currentStagingSize))
	})

	t.Run("StoreLocally with cache MoveIn", func(t *testing.T) {
		worker, _, _, cacheMock, _ := setupTestWorker(t)
		worker.maxStagingSize = 2 * bodySize
		cacheMock.MoveInFunc = func(srcPath, contentHash string) error {
			return os.Remove(srcPath)
		}

		path := worker.FilePath(hash, accountID)
		upload := db.PendingUpload{
			ID:          1,
			AccountID:   accountID,
			ContentHash: hash,
			Size:        bodySize,
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 8 {
					_, err := worker.StoreLocally(hash, accountID, body)
					require.NoError(t, err)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 8 {
				worker.processSingleUpload(context.Background(), upload)
			}
		}()
		close(start)
		wg.Wait()

		expected := fileSize(path)
		require.Equal(t, expected, atomic.LoadInt64(&worker.currentStagingSize),
			"currentStagingSize must match actual bytes on disk after concurrent StoreLocally and cache.MoveIn")
	})
}

// TestCleanupTempLeftoverDoesNotSubtractUnstagedBytes verifies that sweeping an
// aged <hash>.<hex>.tmp crash leftover in cleanupOrphanedFiles does not subtract
// its uncounted bytes from currentStagingSize, which would under-count live staged
// data and allow new deliveries to overshoot max_staging_size.
func TestCleanupTempLeftoverDoesNotSubtractUnstagedBytes(t *testing.T) {
	const (
		accountID = int64(814)
		liveHash  = "f76ce87800000000000000000000000000000000000000000000000000000001"
		crashHash = "f76ce87800000000000000000000000000000000000000000000000000000002"
	)

	body := bytes.Repeat([]byte("live staged message body\r\n"), 256)
	bodySize := int64(len(body))

	mockDB := new(mockUploaderDB)
	mockDB.setPendingUpload(accountID, liveHash)

	w := &UploadWorker{
		rdb:            mockDB,
		path:           t.TempDir(),
		maxStagingSize: 2*bodySize - 1,
	}

	livePath, err := w.StoreLocally(liveHash, accountID, body)
	require.NoError(t, err)
	require.Equal(t, bodySize, atomic.LoadInt64(&w.currentStagingSize))
	require.True(t, w.IsStagingLimitExceeded(bodySize),
		"before cleanup, staging a second %d-byte body must exceed max_staging_size (%d)",
		bodySize, w.maxStagingSize)

	// Simulate a <hash>.<16hex>.tmp file left behind by a crash before os.Rename:
	// StoreLocally never renamed it and never added its bytes to currentStagingSize.
	tempLeftover := w.FilePath(crashHash, accountID) + ".deadbeef01234567.tmp"
	require.NoError(t, os.WriteFile(tempLeftover, body, 0644))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(tempLeftover, old, old))

	require.NoError(t, w.cleanupOrphanedFiles(context.Background()))

	_, err = os.Stat(tempLeftover)
	require.True(t, os.IsNotExist(err), "aged .tmp crash leftover must be removed by cleanupOrphanedFiles")

	_, err = os.Stat(*livePath)
	require.NoError(t, err, "valid staged file must remain on disk")

	require.Equal(t, bodySize, atomic.LoadInt64(&w.currentStagingSize),
		"sweeping an uncounted .tmp leftover must not subtract bytes from live currentStagingSize")
	require.True(t, w.IsStagingLimitExceeded(bodySize),
		"max_staging_size guard must still account for the live staged body after .tmp cleanup")
}
