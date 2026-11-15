package uploader

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leaseQueue models the pending_uploads lease (AcquireAndLeasePendingUploads): a row is
// taken while its last_attempt is NULL or before now - retry_interval, and taking it sets
// last_attempt; a completed upload deletes it.
type leaseQueue struct {
	mu          sync.Mutex
	rows        map[int64]*db.PendingUpload
	leases      map[int64]int
	maxLeases   int // safety stop for a pass that would otherwise never end
	gotInterval []time.Duration
}

func (q *leaseQueue) lease(_ context.Context, _ string, batchSize int, retryInterval time.Duration, _ int) ([]db.PendingUpload, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.gotInterval = append(q.gotInterval, retryInterval)
	before := time.Now().Add(-retryInterval)
	var out []db.PendingUpload
	for _, id := range []int64{1, 2} {
		r, ok := q.rows[id]
		if !ok || q.leases[id] >= q.maxLeases {
			continue
		}
		if r.LastAttempt.Valid && !r.LastAttempt.Time.Before(before) {
			continue
		}
		r.LastAttempt = sql.NullTime{Time: time.Now(), Valid: true}
		q.leases[id]++
		out = append(out, *r)
		if len(out) == batchSize {
			break
		}
	}
	return out, nil
}

func (q *leaseQueue) complete(_ context.Context, pendingID int64, _, _ string, _ int64, _ []string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.rows, pendingID)
	return nil
}

// A retry_interval <= 0 made the lease take back rows the running pass had leased a
// moment ago: an upload the provider refuses on every attempt was leased again at once,
// and with another upload of the pass succeeding the pass never saw an empty queue, so it
// hammered S3 and the database without ever returning to the cycle backoff (#1091). The
// worker uses the 30s default for such a value, so each row is leased once per pass.
func TestProcessPendingUploads_NonPositiveRetryIntervalLeasesEachRowOncePerPass(t *testing.T) {
	const (
		refused  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		accepted = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	for _, interval := range []time.Duration{0, -30 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			worker, rdb, s3, cache, _ := setupTestWorker(t)
			worker.retryInterval = interval
			for _, h := range []string{refused, accepted} {
				p := worker.FilePath(h, 100)
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
				require.NoError(t, os.WriteFile(p, []byte("test data"), 0644))
			}

			q := &leaseQueue{
				rows: map[int64]*db.PendingUpload{
					1: {ID: 1, AccountID: 100, ContentHash: refused, Size: 9},
					2: {ID: 2, AccountID: 100, ContentHash: accepted, Size: 9},
				},
				leases:    map[int64]int{},
				maxLeases: 20,
			}
			rdb.AcquireAndLeasePendingUploadsWithRetryFunc = q.lease
			rdb.CompleteLeasedS3UploadWithRetryFunc = q.complete
			s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
				if strings.Contains(key, refused) {
					return errors.New("403 AccessDenied")
				}
				return nil
			}
			cache.MoveInFunc = func(srcPath, contentHash string) error { return os.Remove(srcPath) }

			require.NoError(t, worker.processPendingUploads(context.Background()))

			q.mu.Lock()
			defer q.mu.Unlock()
			assert.Equal(t, 1, q.leases[1], "the refused upload is leased once per pass, not again at once")
			assert.Equal(t, 1, q.leases[2], "the accepted upload is leased once")
			assert.NotContains(t, q.rows, int64(2), "the accepted upload completed")
			for _, got := range q.gotInterval {
				if !assert.Equal(t, 30*time.Second, got, "the lease uses the 30s default for retry_interval %v", interval) {
					break
				}
			}
		})
	}
}
