package uploader

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type afterEndRefreshDB struct {
	UploaderDB
	after func()
}

func (d *afterEndRefreshDB) PendingUploadBacklog(ctx context.Context, instance string, attempts int, changed func() []StagedBody) (UploadBacklog, error) {
	return d.UploaderDB.PendingUploadBacklog(ctx, instance, attempts, func() []StagedBody { bodies := changed(); d.after(); return bodies })
}

// The refresh closes its change window before applying the snapshot delta. An
// upload starting in that gap must renew an existing on-disk entry's generation,
// so this refresh cannot prune it while finalize drops the row before the file.
func TestStagingRefreshKeepsUploadClaimedAfterWindow(t *testing.T) {
	w, rdb, _, cache, _ := setupTestWorker(t)
	rows := newPendingRows()
	snapshotRows(rdb, rows)
	a := deliver(t, w, rows, "a", 600)
	b := deliver(t, w, rows, "b", 300)
	finalized, release, done := make(chan struct{}), make(chan struct{}), make(chan uploadOutcome, 1)
	var releaseOnce sync.Once
	resume := func() { releaseOnce.Do(func() { close(release) }) }
	defer resume()
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, id int64, owner, hash string, account int64, keys []string) error {
		rows.drop(account, hash)
		close(finalized)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	cache.MoveInFunc = func(path, hash string) error { return os.Remove(path) }
	var startOnce sync.Once
	w.rdb = &afterEndRefreshDB{UploaderDB: rdb, after: func() {
		startOnce.Do(func() {
			go func() {
				done <- w.processSingleUpload(context.Background(), db.PendingUpload{ID: 2, AccountID: 1, ContentHash: stagingHash("b"), Size: 300})
			}()
			select {
			case <-finalized:
			case <-time.After(3 * time.Second):
				t.Fatal("upload did not reach finalize")
			}
		})
	}}
	require.NoError(t, w.monitorStuckUploads(context.Background()))
	require.Equal(t, int64(900), stagingSize(w))
	require.NoError(t, w.monitorStuckUploads(context.Background()))
	assert.Equal(t, int64(900), stagingSize(w), "row is gone but both bodies still occupy the spool")
	resume()
	select {
	case result := <-done:
		require.Equal(t, uploadDone, result)
	case <-time.After(3 * time.Second):
		t.Fatal("upload did not finish")
	}
	requireSwept(t, b)
	assert.Equal(t, int64(600), stagingSize(w), "removing uploaded 300 must leave queued 600 counted")
	require.Equal(t, int64(600), fileSize(a))
}
