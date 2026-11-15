package uploader

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/db"
)

// pendingRow names one pending_uploads row: the key the table is unique on.
type pendingRow struct {
	accountID   int64
	contentHash string
}

// pendingRows fakes this instance's pending_uploads rows for the monitor's backlog
// measurement. A test commits a row the way a delivery's transaction does after
// staging the body, and drops one the way an upload's finalize does before the body
// leaves the spool; snapshot answers what a measurement whose snapshot is taken at
// that moment reports, with Included for every row (the monitor looks up only the
// bodies it names).
type pendingRows struct {
	mu   sync.Mutex
	rows map[pendingRow]int64
}

func newPendingRows() *pendingRows {
	return &pendingRows{rows: make(map[pendingRow]int64)}
}

func (p *pendingRows) commit(accountID int64, contentHash string, size int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rows[pendingRow{accountID, contentHash}] = size
}

func (p *pendingRows) drop(accountID int64, contentHash string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.rows, pendingRow{accountID, contentHash})
}

func (p *pendingRows) snapshot() UploadBacklog {
	p.mu.Lock()
	defer p.mu.Unlock()
	backlog := UploadBacklog{Included: make(map[StagedBody]int64, len(p.rows))}
	for row, size := range p.rows {
		backlog.Count++
		backlog.Bytes += size
		backlog.Included[StagedBody{AccountID: row.accountID, ContentHash: row.contentHash}] = size
	}
	return backlog
}

// deliver stages a body and commits its pending row, in that order, as every delivery
// path does.
func deliver(t *testing.T, w *UploadWorker, rows *pendingRows, seed string, size int) string {
	t.Helper()
	hash := stagingHash(seed)
	path, err := w.StoreLocally(hash, 1, make([]byte, size))
	if err != nil {
		t.Fatalf("StoreLocally(%s): %v", seed, err)
	}
	rows.commit(1, hash, int64(size))
	return *path
}

// finishUpload drops a body's pending row and then removes its staged file, in that
// order, as an upload's finalize does.
func finishUpload(t *testing.T, w *UploadWorker, rows *pendingRows, seed, path string) {
	t.Helper()
	rows.drop(1, stagingHash(seed))
	if err := w.RemoveLocalFile(path); err != nil {
		t.Fatalf("RemoveLocalFile(%s): %v", seed, err)
	}
}

func stagingSize(w *UploadWorker) int64 {
	return atomic.LoadInt64(&w.currentStagingSize)
}

// The refresh reads the cached size before its database queries. A delivery that
// stages its body and commits its row before the backlog query takes its snapshot is
// then in the snapshot as well as in the local change since that read; counting both
// left 600 phantom bytes that refused intake on an empty spool until the next refresh.
func TestStagingRefreshDoesNotRecountAWriteTheSnapshotHas(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1400
	rows := newPendingRows()
	a := deliver(t, w, rows, "a", 500)

	var b string
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		b = deliver(t, w, rows, "b", 600)
		return &db.UploaderStats{}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return rows.snapshot(), nil
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if got := stagingSize(w); got != 1100 {
		t.Errorf("staging size = %d after a refresh whose snapshot already holds the 600 bytes staged during it, want 1100", got)
	}
	if w.IsStagingLimitExceeded(100) {
		t.Errorf("a 100-byte delivery is refused with 1100 bytes staged under a 1400-byte limit (counted %d)", stagingSize(w))
	}

	finishUpload(t, w, rows, "a", a)
	finishUpload(t, w, rows, "b", b)
	if got := stagingSize(w); got != 0 {
		t.Errorf("staging size = %d with nothing left on the spool, want 0", got)
	}
}

// The mirror image: an upload that drops its row and removes its body before the
// backlog query takes its snapshot. Subtracting the removal on top of a snapshot that
// already lacks the row put the count at zero with 500 bytes still staged, and the
// guard then admitted 1100 bytes past a 1500-byte limit.
func TestStagingRefreshDoesNotSubtractARemovalTheSnapshotHas(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1500
	rows := newPendingRows()
	deliver(t, w, rows, "a", 500)
	b := deliver(t, w, rows, "b", 600)

	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		finishUpload(t, w, rows, "b", b)
		return &db.UploaderStats{}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return rows.snapshot(), nil
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if got := stagingSize(w); got != 500 {
		t.Errorf("staging size = %d after a refresh whose snapshot already lacks the 600 bytes removed during it, want 500", got)
	}
	if !w.IsStagingLimitExceeded(1100) {
		t.Errorf("an 1100-byte delivery is admitted with 500 bytes staged under a 1500-byte limit (counted %d)", stagingSize(w))
	}
}

// A removal the snapshot predates must still count: the row is in the snapshot, the
// body has left the spool. (Its write counterpart is
// TestStagingSizeRefreshKeepsConcurrentWrites.)
func TestStagingRefreshKeepsARemovalTheSnapshotPredates(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1500
	rows := newPendingRows()
	deliver(t, w, rows, "a", 500)
	b := deliver(t, w, rows, "b", 600)

	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		snap := rows.snapshot()
		finishUpload(t, w, rows, "b", b)
		return snap, nil
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if got := stagingSize(w); got != 500 {
		t.Errorf("staging size = %d after a refresh whose snapshot predates the 600-byte removal, want 500", got)
	}
}

// A refresh whose measurement fails leaves the count to the local accounting, and
// later changes are counted as they happen.
func TestStagingRefreshThatFailsKeepsTheLocalCount(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	rows := newPendingRows()
	deliver(t, w, rows, "a", 500)

	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		deliver(t, w, rows, "b", 600)
		return &db.UploaderStats{}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return UploadBacklog{}, errors.New("database unavailable")
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}
	if got := stagingSize(w); got != 1100 {
		t.Fatalf("staging size = %d after a refresh that could not measure the backlog, want the local 1100", got)
	}

	deliver(t, w, rows, "c", 300)
	if got := stagingSize(w); got != 1400 {
		t.Errorf("staging size = %d after staging 300 more bytes, want 1400", got)
	}
}

// A change the count could not take in full, because the count was already below what
// is on disk, must not be taken back out by the refresh. Here a delivery replaces a
// 1000-byte leftover the count never held (the spool was not yet measured) with its
// 600-byte body: the 400-byte shrink is clamped at zero. Matching the body's change
// from its 1000 bytes on disk, as if all 1000 had been counted, added the clamped 400
// back: 1000 counted with 600 staged, intake refused under a 1000-byte limit, and 400
// phantom bytes left once the body is gone.
func TestStagingRefreshCountsAClampedChangeAsItLanded(t *testing.T) {
	w, rdb, _, _, _ := setupTestWorker(t)
	w.maxStagingSize = 1000
	rows := newPendingRows()
	stageFile(t, w, stagingHash("a"), 1, 1000)

	var a string
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		a = deliver(t, w, rows, "a", 600)
		return &db.UploaderStats{}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return rows.snapshot(), nil
	}

	if err := w.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if got := stagingSize(w); got != 600 {
		t.Errorf("staging size = %d with the 600-byte body staged, want 600", got)
	}
	if w.IsStagingLimitExceeded(300) {
		t.Errorf("a 300-byte delivery is refused with 600 bytes staged under a 1000-byte limit (counted %d)", stagingSize(w))
	}

	finishUpload(t, w, rows, "a", a)
	if got := stagingSize(w); got != 0 {
		t.Errorf("staging size = %d with nothing left on the spool, want 0", got)
	}
}
