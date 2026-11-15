package uploader

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// existing answers the orphan sweep's lookup from the rows, as the database does.
func (p *pendingRows) existing(ctx context.Context, accountID int64, hashes []string) (map[string]struct{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	found := make(map[string]struct{})
	for _, hash := range hashes {
		if _, ok := p.rows[pendingRow{accountID, hash}]; ok {
			found[hash] = struct{}{}
		}
	}
	return found, nil
}

// stageOrphan stages a body whose pending row never commits: a delivery into a shared
// mailbox another account owns, a duplicate, or a cancelled one.
func stageOrphan(t *testing.T, w *UploadWorker, seed string, size int) string {
	t.Helper()
	path, err := w.StoreLocally(stagingHash(seed), 1, make([]byte, size))
	if err != nil {
		t.Fatalf("StoreLocally(%s): %v", seed, err)
	}
	return *path
}

// ageStaged puts a staged file past the orphan sweep's grace period.
func ageStaged(t *testing.T, paths ...string) {
	t.Helper()
	old := time.Now().Add(-2 * time.Hour)
	for _, path := range paths {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatalf("Chtimes(%s): %v", path, err)
		}
	}
}

func requireSwept(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("orphan %s is still staged after the sweep (stat: %v)", path, err)
		}
	}
}

// The refresh counts pending rows, so it drops an orphan staged before it from the
// count. Sweeping that orphan later took its bytes out a second time: with 600 bytes
// staged the count read 300, and the guard admitted 700 bytes under a 1000-byte limit
// until the next refresh (#1183).
func TestOrphanSweepDoesNotSubtractWhatTheRefreshDropped(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1000
	rows := newPendingRows()
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return rows.snapshot(), nil
	}
	rdb.ExistingPendingUploadsFunc = rows.existing

	a := deliver(t, w, rows, "a", 600)
	orphan := stageOrphan(t, w, "b", 300)
	if got := stagingSize(w); got != 900 {
		t.Fatalf("staging size = %d with 900 bytes staged, want 900", got)
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}
	if got := stagingSize(w); got != 600 {
		t.Fatalf("staging size = %d after a refresh whose backlog holds 600 bytes, want 600", got)
	}

	ageStaged(t, orphan)
	if err := w.cleanupOrphanedFiles(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedFiles: %v", err)
	}
	requireSwept(t, orphan)

	if got := stagingSize(w); got != 600 {
		t.Errorf("staging size = %d after sweeping an orphan the refresh did not count, want the 600 bytes still staged", got)
	}
	if !w.IsStagingLimitExceeded(700) {
		t.Errorf("a 700-byte delivery is admitted with 600 bytes staged under a 1000-byte limit (counted %d)", stagingSize(w))
	}

	finishUpload(t, w, rows, "a", a)
	if got := stagingSize(w); got != 0 {
		t.Errorf("staging size = %d with nothing left on the spool, want 0", got)
	}
}

// An orphan left on disk by an earlier run was never counted by this one. Sweeping it
// took its bytes out of what this run's deliveries staged.
func TestOrphanSweepDoesNotSubtractAFileThisRunNeverCounted(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1000
	rows := newPendingRows()
	rdb.ExistingPendingUploadsFunc = rows.existing

	leftover := stageFile(t, w, stagingHash("c"), 1, 300)
	ageStaged(t, leftover)
	deliver(t, w, rows, "a", 600)

	if err := w.cleanupOrphanedFiles(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedFiles: %v", err)
	}
	requireSwept(t, leftover)

	if got := stagingSize(w); got != 600 {
		t.Errorf("staging size = %d after sweeping a leftover this run never counted, want the 600 bytes it staged", got)
	}
}

// What the count does hold must still leave it: an orphan staged while the refresh
// measured the backlog, which the refresh counts as it is on disk, and one staged
// after it. (In production the sweep reaches these only when the refresh has not
// re-based the count for longer than the grace period.)
func TestOrphanSweepSubtractsOrphansStagedSinceTheRefreshBegan(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1000
	rows := newPendingRows()
	rdb.ExistingPendingUploadsFunc = rows.existing
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return rows.snapshot(), nil
	}

	deliver(t, w, rows, "a", 600)
	var during string
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		during = stageOrphan(t, w, "d", 200)
		return &db.UploaderStats{}, nil
	}
	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}
	if got := stagingSize(w); got != 800 {
		t.Fatalf("staging size = %d after a refresh with a 200-byte orphan staged during it, want 800", got)
	}
	after := stageOrphan(t, w, "e", 100)
	if got := stagingSize(w); got != 900 {
		t.Fatalf("staging size = %d after staging another 100 bytes, want 900", got)
	}

	ageStaged(t, during, after)
	if err := w.cleanupOrphanedFiles(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedFiles: %v", err)
	}
	requireSwept(t, during, after)

	if got := stagingSize(w); got != 600 {
		t.Errorf("staging size = %d after sweeping 300 counted orphan bytes, want 600", got)
	}
}
