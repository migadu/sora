package uploader

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// stagingHash returns a syntactically valid content hash for tests.
func stagingHash(seed string) string {
	return strings.Repeat(seed, 64/len(seed))
}

// stageFile writes a staged file directly, bypassing StoreLocally's accounting, so
// a test can model a file that was already on disk at the last database refresh.
func stageFile(t *testing.T, w *UploadWorker, contentHash string, accountID int64, size int) string {
	t.Helper()
	path := w.FilePath(contentHash, accountID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("Failed to create staging directory: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0644); err != nil {
		t.Fatalf("Failed to write staged file: %v", err)
	}
	return path
}

// TestStagingLimitCountsFilesWrittenSinceLastRefresh drives the guard that IMAP
// APPEND, LMTP delivery and the delivery API consult before writing a message to
// the local spool. The cached staging size is refreshed from the database only on
// the 5-minute monitor tick, so unless the write path accounts for its own bytes
// the guard answers "room available" for a full tick of intake and the spool
// overshoots max_staging_size by whatever the node can accept in five minutes.
func TestStagingLimitCountsFilesWrittenSinceLastRefresh(t *testing.T) {
	worker, _, _, _, _ := setupTestWorker(t)
	worker.maxStagingSize = 1000

	body := make([]byte, 700)
	if _, err := worker.StoreLocally(stagingHash("a"), 1, body); err != nil {
		t.Fatalf("StoreLocally failed: %v", err)
	}

	if !worker.IsStagingLimitExceeded(400) {
		t.Fatalf("IsStagingLimitExceeded(400) = false after staging 700 bytes against a 1000 byte limit: "+
			"the guard still reads the last database refresh (%d bytes) and admits writes the spool has no room for",
			atomic.LoadInt64(&worker.currentStagingSize))
	}
}

// TestStagingLimitReleasesRemovedFiles is the other half of the accounting: bytes
// that left the spool must stop counting against the limit, otherwise the guard
// locks a healthy node out of accepting mail until the next refresh.
func TestStagingLimitReleasesRemovedFiles(t *testing.T) {
	worker, _, _, _, _ := setupTestWorker(t)
	worker.maxStagingSize = 1000

	// The file is on disk and already counted by the last database refresh.
	path := stageFile(t, worker, stagingHash("b"), 1, 700)
	atomic.StoreInt64(&worker.currentStagingSize, 700)

	if err := worker.RemoveLocalFile(path); err != nil {
		t.Fatalf("RemoveLocalFile failed: %v", err)
	}

	if worker.IsStagingLimitExceeded(400) {
		t.Fatalf("IsStagingLimitExceeded(400) = true after the staged file was removed: "+
			"the guard still counts %d bytes that are no longer on disk", atomic.LoadInt64(&worker.currentStagingSize))
	}
}

// TestStagingLimitReleasesFilesMovedIntoCache covers the normal end of a staged
// file's life: a successful upload hands the file to the cache with a rename, so
// it leaves the spool without going through RemoveLocalFile.
func TestStagingLimitReleasesFilesMovedIntoCache(t *testing.T) {
	worker, _, _, cache, _ := setupTestWorker(t)
	worker.maxStagingSize = 1000
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		return os.Remove(srcPath)
	}

	hash := stagingHash("c")
	stageFile(t, worker, hash, 1, 700)
	atomic.StoreInt64(&worker.currentStagingSize, 700)

	worker.processSingleUpload(context.Background(), db.PendingUpload{
		AccountID:   1,
		ContentHash: hash,
		Size:        700,
	})

	if worker.IsStagingLimitExceeded(400) {
		t.Fatalf("IsStagingLimitExceeded(400) = true after the staged file was moved into the cache: "+
			"the guard still counts %d bytes that are no longer on disk", atomic.LoadInt64(&worker.currentStagingSize))
	}
}

// TestStagingSizeRefreshKeepsConcurrentWrites covers the hand-off between the two
// halves of the accounting. The database snapshot is taken before the query returns,
// so re-basing the cached size on it must not discard the bytes a delivery staged in
// the meantime - on a busy node that is a steady leak of admitted-but-uncounted mail.
func TestStagingSizeRefreshKeepsConcurrentWrites(t *testing.T) {
	worker, rdb, _, _, _ := setupTestWorker(t)
	worker.maxStagingSize = 1000
	// The guard is rebased from this INSTANCE's backlog, not the cluster-wide stats:
	// max_staging_size guards this node's own staging directory.
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		// A delivery lands while the query is in flight; the returned snapshot
		// predates it.
		if _, err := worker.StoreLocally(stagingHash("d"), 1, make([]byte, 600)); err != nil {
			return UploadBacklog{}, err
		}
		return UploadBacklog{Count: 1, Bytes: 500}, nil
	}

	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads failed: %v", err)
	}

	if got := atomic.LoadInt64(&worker.currentStagingSize); got != 1100 {
		t.Fatalf("staging size = %d after refreshing a 500 byte snapshot with a 600 byte write in flight, want 1100: "+
			"the refresh dropped a message that is on disk and counts against the limit", got)
	}
}

// TestStagingSizeIsKnownAtStartup covers a restart with a backlog already on disk.
// The cached size starts at zero and the first monitor tick is five minutes away,
// so until then the limit is not enforced at all - on a node sized close to its
// disk capacity that turns an intended 4xx into a full filesystem.
func TestStagingSizeIsKnownAtStartup(t *testing.T) {
	worker, rdb, _, _, _ := setupTestWorker(t)
	worker.maxStagingSize = 1000
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return UploadBacklog{Count: 3, Bytes: 900}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer worker.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if worker.IsStagingLimitExceeded(200) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("IsStagingLimitExceeded(200) still false 2s after start with 900 bytes of pending uploads in the database: "+
		"the guard reads %d and stays unenforced until the first 5-minute monitor tick", atomic.LoadInt64(&worker.currentStagingSize))
}
