package uploader

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An upload holds no lock across its transfer: held across the S3 round trip, the
// per-object lock pinned one pooled connection per upload in flight, so concurrency was
// bounded by the pooler's pool rather than by the provider. It passes a gate before
// touching S3 and has its leased pending row re-checked at the finalize instead
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

func TestProcessSingleUpload_PassesTheGateAndHoldsNoLock(t *testing.T) {
	worker, rdb, s3, _, _ := setupTestWorker(t)
	stageGateTestBody(t, worker)

	var ev events
	rdb.PassS3WriteGateFunc = func(ctx context.Context, pendingID, accountID int64, contentHash string) (db.S3WriteGate, error) {
		assert.Equal(t, int64(77), pendingID, "the gate checks the row this upload leased")
		ev.add("gate")
		return db.S3WriteOpen, nil
	}
	rdb.ExecuteWithS3ObjectLockFunc = func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
		t.Error("an upload must not hold the object lock across its transfer")
		return fn(ctx)
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

	assert.Equal(t, uploadDone, worker.processSingleUpload(context.Background(), gateTestUpload()))
	assert.Equal(t, []string{"gate", "put", "finalize"}, ev.get(), "the gate comes before anything touches S3")
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
		// The account was purged, or the upload reaped: nothing is left to upload.
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
				rdb.PassS3WriteGateFunc = func(ctx context.Context, pendingID, accountID int64, contentHash string) (db.S3WriteGate, error) {
					return tc.gate, tc.err
				}
				var touched, counted, finalized bool
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
				cache.MoveInFunc = func(srcPath, contentHash string) error {
					t.Error("a body that was not uploaded must not move into the cache")
					return nil
				}

				assert.Equal(t, tc.want, worker.processSingleUpload(context.Background(), gateTestUpload()), "staged=%v", staged)
				assert.False(t, touched, "S3 must not be asked anything before the gate opens (staged=%v)", staged)
				assert.False(t, counted, "a closed gate says nothing about the content (staged=%v)", staged)
				assert.False(t, finalized, "staged=%v", staged)
				if staged {
					_, err := os.Stat(path)
					assert.NoError(t, err, "the staged body stays; the orphan sweep decides once its row is gone")
				}
			}
		})
	}
}

// Account deletion drops pending rows before its S3 phase, so a purge can delete a key
// and the rows carrying it while the body is still in flight, and the write lands after.
// The finalize refuses (the leased row is gone), and the uploader removes, under the
// object lock, what it wrote and nothing references.
func TestProcessSingleUpload_PendingRowGoneMidFlightDiscardsWhatNothingReferences(t *testing.T) {
	worker, rdb, s3, cache, _ := setupTestWorker(t)
	path := stageGateTestBody(t, worker)

	purged := helpers.NewS3Key("example.com", "purged", gateTestHash)
	stillListed := helpers.NewS3Key("example.com", "listed", gateTestHash)
	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
		return []string{purged, stillListed}, nil
	}
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		return db.ErrPendingUploadGone
	}

	var mu sync.Mutex
	inLock := false
	rdb.ExecuteWithS3ObjectLockFunc = func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
		mu.Lock()
		inLock = true
		mu.Unlock()
		defer func() {
			mu.Lock()
			inLock = false
			mu.Unlock()
		}()
		return fn(ctx)
	}
	rdb.UnreferencedS3KeysFunc = func(ctx context.Context, contentHash string, keys []string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		assert.True(t, inLock, "the re-check must run under the object lock, like every deleter's")
		assert.ElementsMatch(t, []string{purged, stillListed}, keys, "every key this upload wrote is checked")
		// An uploaded row still carries stillListed: the cleaner lists it once expunged.
		return []string{purged}, nil
	}
	var deleted []string
	s3.DeleteWithRetryFunc = func(ctx context.Context, key string) error {
		mu.Lock()
		defer mu.Unlock()
		assert.True(t, inLock, "the delete must happen under the object lock")
		deleted = append(deleted, key)
		return nil
	}
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		t.Error("an abandoned upload's body must not move into the cache")
		return nil
	}

	outcome := worker.processSingleUpload(context.Background(), gateTestUpload())
	assert.Equal(t, uploadDone, outcome, "storage took the writes, which is what the cycle backoff needs to hear")
	assert.Equal(t, []string{purged}, deleted, "only what no row carries is removed; the rest is the cleaner's to list")
	_, err := os.Stat(path)
	assert.NoError(t, err, "the staged body stays for the orphan sweep")
}

func TestProcessSingleUpload_SelfHealOfAnAbandonedUploadDiscardsInsteadOfFinalizing(t *testing.T) {
	worker, rdb, s3, _, _ := setupTestWorker(t)
	// No staged file; every key is already in S3 (an earlier attempt wrote them).
	s3.ExistsWithRetryFunc = func(ctx context.Context, key string) (bool, error) { return true, nil }
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		return db.ErrPendingUploadGone
	}
	var checked bool
	rdb.UnreferencedS3KeysFunc = func(ctx context.Context, contentHash string, keys []string) ([]string, error) {
		checked = true
		return keys, nil
	}
	var deleted []string
	s3.DeleteWithRetryFunc = func(ctx context.Context, key string) error {
		deleted = append(deleted, key)
		return nil
	}

	assert.Equal(t, uploadSkipped, worker.processSingleUpload(context.Background(), gateTestUpload()))
	assert.True(t, checked)
	assert.Equal(t, []string{helpers.NewS3Key("example.com", "user", gateTestHash)}, deleted)
}

func TestProcessSingleUpload_FailedDiscardIsReportedNotRetried(t *testing.T) {
	worker, rdb, s3, _, _ := setupTestWorker(t)
	stageGateTestBody(t, worker)
	rdb.CompleteLeasedS3UploadWithRetryFunc = func(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
		return db.ErrPendingUploadGone
	}
	rdb.UnreferencedS3KeysFunc = func(ctx context.Context, contentHash string, keys []string) ([]string, error) {
		return keys, nil
	}
	s3.DeleteWithRetryFunc = func(ctx context.Context, key string) error {
		return errors.New("503 SlowDown")
	}

	// Nothing will lease the row again (it is gone), so the outcome is about the write.
	assert.Equal(t, uploadDone, worker.processSingleUpload(context.Background(), gateTestUpload()))
}
