package uploader

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An upload holds no lock across its transfer: held across the S3 round trip, the
// per-object lock pinned one pooled connection per upload in flight, so concurrency was
// bounded by the pooler's pool rather than by the provider. It passes a gate before
// touching S3, which leases its pending row to it; it renews that lease while the
// transfer runs, and nothing but its own finalize deletes a leased row
// (db.PassS3WriteGate, db.CompleteLeasedS3Upload).

const gateTestHash = "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2"

func gateTestUpload() db.PendingUpload {
	return db.PendingUpload{ID: 77, AccountID: 4242, ContentHash: gateTestHash, Size: 9}
}

func stageGateTestBody(t *testing.T, w *UploadWorker) string {
	t.Helper()
	path := w.FilePath(gateTestHash, 4242)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte("test data"), 0644))
	return path
}

// shortLease makes the lease renew every few milliseconds for one test.
func shortLease(t *testing.T, renew, ttl time.Duration) {
	t.Helper()
	oldRenew, oldTTL := uploadLeaseRenewInterval, uploadLeaseTTL
	uploadLeaseRenewInterval, uploadLeaseTTL = renew, ttl
	t.Cleanup(func() { uploadLeaseRenewInterval, uploadLeaseTTL = oldRenew, oldTTL })
}

// events records the order in which an upload talked to the database and S3.
type events struct {
	mu   sync.Mutex
	list []string
}

func (e *events) add(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.list = append(e.list, name)
}

func (e *events) get() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.list...)
}

func TestProcessSingleUpload_PassesTheGateBeforeTouchingS3(t *testing.T) {
	worker, rdb, s3, _, _ := setupTestWorker(t)
	stageGateTestBody(t, worker)

	var ev events
	rdb.PassS3WriteGateFunc = func(ctx context.Context, pendingID, accountID int64, contentHash string, ttl time.Duration) (db.S3WriteGate, error) {
		assert.Equal(t, int64(77), pendingID, "the gate leases the row this upload leased")
		assert.Equal(t, uploadLeaseTTL, ttl)
		ev.add("gate")
		return db.S3WriteOpen, nil
	}
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		ev.add("put")
		return nil
	}
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		assert.Equal(t, int64(77), pendingID, "the finalize checks the row this upload leased")
		ev.add("finalize")
		return nil
	}
	rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
		ev.add("release")
		return nil
	}

	assert.Equal(t, uploadDone, worker.processSingleUpload(context.Background(), gateTestUpload()))
	assert.Equal(t, []string{"gate", "put", "finalize"}, ev.get(),
		"the gate comes before anything touches S3, and a finalize ends the lease itself")
}

func TestProcessSingleUpload_GateTurnsTheUploadAway(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate db.S3WriteGate
		err  error
		want uploadOutcome
	}{
		// A delete, restore or cross-account copy of this body is under way.
		{"busy", db.S3WriteBusy, nil, uploadSkipped},
		// The account was deleted, or the upload reaped: nothing is left to upload.
		{"abandoned", db.S3WriteAbandoned, nil, uploadSkipped},
		// The database did not answer; nothing is known about the content.
		{"database error", db.S3WriteBusy, errors.New("db is down"), uploadRetryLater},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, staged := range []bool{true, false} {
				worker, rdb, s3, cache, _ := setupTestWorker(t)
				path := worker.FilePath(gateTestHash, 4242)
				if staged {
					path = stageGateTestBody(t, worker)
				}
				rdb.PassS3WriteGateFunc = func(ctx context.Context, pendingID, accountID int64, contentHash string, ttl time.Duration) (db.S3WriteGate, error) {
					return tc.gate, tc.err
				}
				var touched, counted, finalized, leased bool
				s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
					touched = true
					return nil
				}
				s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) {
					touched = true
					return true, nil
				}
				rdb.MarkUploadAttemptWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
					counted = true
					return nil
				}
				rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
					finalized = true
					return nil
				}
				rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
					leased = true
					return nil
				}
				cache.MoveInFunc = func(srcPath, contentHash string) error {
					t.Error("a body that was not uploaded must not move into the cache")
					return nil
				}

				assert.Equal(t, tc.want, worker.processSingleUpload(context.Background(), gateTestUpload()), "staged=%v", staged)
				assert.False(t, touched, "S3 must not be asked anything before the gate opens (staged=%v)", staged)
				assert.False(t, counted, "a closed gate says nothing about the content (staged=%v)", staged)
				assert.False(t, finalized, "staged=%v", staged)
				assert.False(t, leased, "a closed gate grants no lease to release (staged=%v)", staged)
				if staged {
					_, err := os.Stat(path)
					assert.NoError(t, err, "the staged body stays; the orphan sweep decides once its row is gone")
				}
			}
		})
	}
}

// A transfer can outlast the lease the gate granted; the upload renews it until the
// finalize, and not after: a renewal racing the finalize would see the row it deletes.
func TestProcessSingleUpload_RenewsTheLeaseUntilTheFinalize(t *testing.T) {
	shortLease(t, 5*time.Millisecond, time.Second)
	worker, rdb, s3, _, _ := setupTestWorker(t)
	stageGateTestBody(t, worker)

	var renewals atomic.Int32
	var finalizing atomic.Bool
	rdb.RenewPendingUploadLeaseFunc = func(ctx context.Context, pendingID int64, ttl time.Duration) (bool, error) {
		assert.Equal(t, int64(77), pendingID)
		assert.False(t, finalizing.Load(), "no renewal may run once the finalize has started")
		renewals.Add(1)
		return true, nil
	}
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		time.Sleep(60 * time.Millisecond) // a slow transfer
		return nil
	}
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		finalizing.Store(true)
		time.Sleep(20 * time.Millisecond)
		return nil
	}

	assert.Equal(t, uploadDone, worker.processSingleUpload(context.Background(), gateTestUpload()))
	assert.GreaterOrEqual(t, renewals.Load(), int32(3), "the lease must be renewed while the transfer runs")
}

// If a renewal finds the row gone, the body must not land: nothing protects it any more.
func TestProcessSingleUpload_LostLeaseStopsTheTransfer(t *testing.T) {
	shortLease(t, 5*time.Millisecond, time.Second)
	worker, rdb, s3, cache, _ := setupTestWorker(t)
	path := stageGateTestBody(t, worker)

	rdb.RenewPendingUploadLeaseFunc = func(ctx context.Context, pendingID int64, ttl time.Duration) (bool, error) {
		return false, nil // the row is gone
	}
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			t.Error("the transfer went on after the lease was lost")
			return nil
		}
	}
	var finalized, released bool
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		finalized = true
		return nil
	}
	rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
		released = true
		return nil
	}
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		t.Error("a body whose lease was lost must not move into the cache")
		return nil
	}

	assert.Equal(t, uploadSkipped, worker.processSingleUpload(context.Background(), gateTestUpload()), "the row is gone: nothing to retry")
	assert.False(t, finalized)
	assert.False(t, released, "there is no row left to release")
	_, err := os.Stat(path)
	assert.NoError(t, err, "the staged body stays for the orphan sweep")
}

// Renewals that keep failing would let the lease run out mid-transfer; the transfer stops
// first and the row is retried, since it may well still be there.
func TestProcessSingleUpload_UnrenewableLeaseStopsTheTransfer(t *testing.T) {
	shortLease(t, 5*time.Millisecond, 30*time.Millisecond)
	worker, rdb, s3, _, _ := setupTestWorker(t)
	stageGateTestBody(t, worker)

	rdb.RenewPendingUploadLeaseFunc = func(ctx context.Context, pendingID int64, ttl time.Duration) (bool, error) {
		return false, errors.New("db is down")
	}
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			t.Error("the transfer outlived a lease that could not be renewed")
			return nil
		}
	}
	var released atomic.Bool
	rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
		released.Store(true)
		return nil
	}

	assert.Equal(t, uploadRetryLater, worker.processSingleUpload(context.Background(), gateTestUpload()))
	assert.True(t, released.Load(), "the lease is released so that account deletion need not wait it out")
}

// Every way out that does not finalize gives the lease back, so a failed upload does not
// hold up the deletion of its account until the lease runs out.
func TestProcessSingleUpload_FailedUploadReleasesItsLease(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(w *UploadWorker, rdb *mockDB, s3 *mockS3)
		want  uploadOutcome
	}{
		{"put fails", func(w *UploadWorker, rdb *mockDB, s3 *mockS3) {
			stageGateTestBody(t, w)
			s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
				return errors.New("503 SlowDown")
			}
		}, uploadRetryLater},
		{"finalize fails", func(w *UploadWorker, rdb *mockDB, s3 *mockS3) {
			stageGateTestBody(t, w)
			rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
				return errors.New("db is down")
			}
		}, uploadRetryLater},
		{"size mismatch", func(w *UploadWorker, rdb *mockDB, s3 *mockS3) {
			path := w.FilePath(gateTestHash, 4242)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
			require.NoError(t, os.WriteFile(path, []byte("short"), 0644))
		}, uploadContentProblem},
		{"missing file, absent from S3", func(w *UploadWorker, rdb *mockDB, s3 *mockS3) {}, uploadContentProblem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker, rdb, s3, _, _ := setupTestWorker(t)
			tc.setup(worker, rdb, s3)
			var released []int64
			rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
				released = append(released, pendingID)
				return nil
			}
			assert.Equal(t, tc.want, worker.processSingleUpload(context.Background(), gateTestUpload()))
			assert.Equal(t, []int64{77}, released)
		})
	}
}

// The row went away after the body landed (the lease ran out, or something deleted the
// row regardless). Nothing is marked, nothing is retried, and the body is not deleted
// here: no delete from this side could be made durable, and the keys are logged instead.
func TestProcessSingleUpload_RowGoneAtTheFinalize(t *testing.T) {
	worker, rdb, _, cache, _ := setupTestWorker(t)
	path := stageGateTestBody(t, worker)
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		return db.ErrPendingUploadGone
	}
	rdb.ReleasePendingUploadLeaseFunc = func(ctx context.Context, pendingID int64) error {
		t.Error("there is no row left to release")
		return nil
	}
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		t.Error("an upload that was not finalized must not move its body into the cache")
		return nil
	}

	assert.Equal(t, uploadSkipped, worker.processSingleUpload(context.Background(), gateTestUpload()))
	_, err := os.Stat(path)
	assert.NoError(t, err, "the staged body stays for the orphan sweep")
}
