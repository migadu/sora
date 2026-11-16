package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubRekeyDB struct {
	pendingUploadExists func(ctx context.Context, contentHash string, accountID int64) (bool, error)
	executeWithLock     func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error
	rekeyContentHash    func(ctx context.Context, accountID int64, obj db.ContentObject, newHash string) (int64, error)
	isReferenced        func(ctx context.Context, obj db.ContentObject) (bool, error)
}

func (s *stubRekeyDB) PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	if s.pendingUploadExists != nil {
		return s.pendingUploadExists(ctx, contentHash, accountID)
	}
	return false, nil
}

func (s *stubRekeyDB) ExecuteWithS3ObjectLock(ctx context.Context, contentHash string, accountID int64, executionFunc func(ctx context.Context) error) error {
	if s.executeWithLock != nil {
		return s.executeWithLock(ctx, contentHash, accountID, executionFunc)
	}
	return executionFunc(ctx)
}

func (s *stubRekeyDB) RekeyContentHashWithRetry(ctx context.Context, accountID int64, obj db.ContentObject, newHash string) (int64, error) {
	if s.rekeyContentHash != nil {
		return s.rekeyContentHash(ctx, accountID, obj, newHash)
	}
	return 1, nil
}

func (s *stubRekeyDB) IsContentObjectReferencedWithRetry(ctx context.Context, obj db.ContentObject) (bool, error) {
	if s.isReferenced != nil {
		return s.isReferenced(ctx, obj)
	}
	return false, nil
}

// ctxAwareStubStore mirrors storage.S3Storage: Get/Put/Delete use context.Background(),
// whereas GetContext/PutContext/DeleteContext honor the caller's context.
type ctxAwareStubStore struct {
	mu      sync.Mutex
	objects map[string][]byte

	getFn    func(ctx context.Context, key string) (io.ReadCloser, error)
	putFn    func(ctx context.Context, key string, body io.Reader, size int64) error
	deleteFn func(ctx context.Context, key string) error

	putCalls    atomic.Int32
	deleteCalls atomic.Int32
}

func newCtxAwareStubStore() *ctxAwareStubStore {
	return &ctxAwareStubStore{objects: make(map[string][]byte)}
}

func (s *ctxAwareStubStore) Get(key string) (io.ReadCloser, error) {
	return s.GetContext(context.Background(), key)
}

func (s *ctxAwareStubStore) GetContext(ctx context.Context, key string) (io.ReadCloser, error) {
	if s.getFn != nil {
		return s.getFn(ctx, key)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	data, ok := s.objects[key]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
}

func (s *ctxAwareStubStore) Put(key string, reader io.Reader, size int64) error {
	return s.PutContext(context.Background(), key, reader, size)
}

func (s *ctxAwareStubStore) PutContext(ctx context.Context, key string, reader io.Reader, size int64) error {
	s.putCalls.Add(1)
	if s.putFn != nil {
		return s.putFn(ctx, key, reader, size)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.objects[key] = data
	s.mu.Unlock()
	return nil
}

func (s *ctxAwareStubStore) Exists(key string) (bool, string, error) {
	s.mu.Lock()
	_, ok := s.objects[key]
	s.mu.Unlock()
	return ok, "", nil
}

func (s *ctxAwareStubStore) Delete(key string) error {
	return s.DeleteContext(context.Background(), key)
}

func (s *ctxAwareStubStore) DeleteContext(ctx context.Context, key string) error {
	s.deleteCalls.Add(1)
	if s.deleteFn != nil {
		return s.deleteFn(ctx, key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.objects, key)
	s.mu.Unlock()
	return nil
}

func (s *ctxAwareStubStore) Copy(sourcePath, destPath string) error { return nil }
func (s *ctxAwareStubStore) EnableEncryption(encryptionKey string) error {
	return nil
}

func newTestS3StorageForServer(t *testing.T, handler http.Handler) *storage.S3Storage {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	s3, err := storage.New(
		strings.TrimPrefix(srv.URL, "http://"),
		"test-access-key",
		"test-secret-key",
		"test-bucket",
		false,
		false,
		5*time.Second,
	)
	require.NoError(t, err)
	return s3
}

func TestRekeyMoveBodyHonorsGuardedLockContext(t *testing.T) {
	body := []byte("From: a@example.com\r\nSubject: lock\r\n\r\nhello\r\n")
	oldObj := db.ContentObject{S3Domain: "example.com", S3Localpart: "user", ContentHash: sha256Hex(body)}
	newObj := db.ContentObject{S3Domain: "example.com", S3Localpart: "user", ContentHash: helpers.HashContent(body)}

	t.Run("lock lost before new-key check stops without writing S3 object", func(t *testing.T) {
		store := newCtxAwareStubStore()
		var rekeyCalled atomic.Bool
		errLockLost := errors.New("advisory lock connection lost")

		rdb := &stubRekeyDB{
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				guarded, cancel := context.WithCancelCause(ctx)
				cancel(errLockLost)
				if err := fn(guarded); err != nil {
					return err
				}
				return fmt.Errorf("S3 object lock was lost while the guarded work ran: %w", errLockLost)
			},
			rekeyContentHash: func(ctx context.Context, accountID int64, obj db.ContentObject, newHash string) (int64, error) {
				rekeyCalled.Store(true)
				return 0, ctx.Err()
			},
		}

		r := &rekeyRun{rdb: rdb, store: store, accountID: 42, report: &rekeyReport{}}
		rows, wrote, err := r.moveBody(context.Background(), oldObj, newObj, body)
		require.Error(t, err)
		assert.Zero(t, rows)
		assert.False(t, wrote, "must not upload new object when S3 object lock context is already canceled")
		assert.Zero(t, store.putCalls.Load(), "Put must not be called after lock context cancellation")
		assert.False(t, rekeyCalled.Load(), "DB rekey must not run after lock loss")
	})

	t.Run("lock lost during new-key Get does not fall through into Put", func(t *testing.T) {
		store := newCtxAwareStubStore()
		store.objects[newObj.Key()] = body
		errLockLost := errors.New("lock heartbeat failed during GET")

		var cancelGuard context.CancelCauseFunc
		store.getFn = func(ctx context.Context, key string) (io.ReadCloser, error) {
			cancelGuard(errLockLost)
			return nil, errLockLost
		}

		rdb := &stubRekeyDB{
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				var guarded context.Context
				guarded, cancelGuard = context.WithCancelCause(ctx)
				defer cancelGuard(nil)
				return fn(guarded)
			},
		}

		r := &rekeyRun{rdb: rdb, store: store, accountID: 42, report: &rekeyReport{}}
		_, wrote, err := r.moveBody(context.Background(), oldObj, newObj, body)
		require.Error(t, err)
		assert.False(t, wrote)
		assert.Zero(t, store.putCalls.Load(), "a Get that failed because the lock context canceled must not trigger Put")
	})

	t.Run("lock lost mid-Put aborts S3Storage HTTP upload", func(t *testing.T) {
		var cancelGuard context.CancelCauseFunc
		var putCompletedUnprotected atomic.Bool

		s3 := newTestS3StorageForServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.Method {
			case http.MethodGet:
				http.NotFound(w, req)
			case http.MethodPut:
				cancelGuard(errors.New("advisory lock lost during PUT"))
				select {
				case <-req.Context().Done():
					return
				case <-time.After(250 * time.Millisecond):
					putCompletedUnprotected.Store(true)
					w.WriteHeader(http.StatusOK)
				}
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))

		rdb := &stubRekeyDB{
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				var guarded context.Context
				guarded, cancelGuard = context.WithCancelCause(ctx)
				defer cancelGuard(nil)
				if err := fn(guarded); err != nil {
					return err
				}
				if err := context.Cause(guarded); err != nil {
					return fmt.Errorf("S3 object lock was lost while the guarded work ran: %w", err)
				}
				return nil
			},
		}

		r := &rekeyRun{rdb: rdb, store: s3, accountID: 42, report: &rekeyReport{}}
		_, wrote, err := r.moveBody(context.Background(), oldObj, newObj, body)
		require.Error(t, err)
		assert.False(t, putCompletedUnprotected.Load(), "S3 PUT completed unprotected after lock context was canceled")
		assert.False(t, wrote)
	})
}

func TestRekeyDeleteOldObjectHonorsGuardedLockContextAndAccounting(t *testing.T) {
	body := []byte("From: a@example.com\r\nSubject: old\r\n\r\nold body\r\n")
	oldObj := db.ContentObject{S3Domain: "example.com", S3Localpart: "user", ContentHash: sha256Hex(body)}

	t.Run("lock lost mid-Delete aborts S3Storage HTTP delete and records OldLeft", func(t *testing.T) {
		var cancelGuard context.CancelCauseFunc
		var deleteCompletedUnprotected atomic.Bool

		s3 := newTestS3StorageForServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodDelete {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			cancelGuard(errors.New("advisory lock lost during DELETE"))
			select {
			case <-req.Context().Done():
				return
			case <-time.After(250 * time.Millisecond):
				deleteCompletedUnprotected.Store(true)
				w.WriteHeader(http.StatusNoContent)
			}
		}))

		rdb := &stubRekeyDB{
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				var guarded context.Context
				guarded, cancelGuard = context.WithCancelCause(ctx)
				defer cancelGuard(nil)
				if err := fn(guarded); err != nil {
					return err
				}
				if err := context.Cause(guarded); err != nil {
					return fmt.Errorf("S3 object lock was lost while the guarded work ran: %w", err)
				}
				return nil
			},
		}

		r := &rekeyRun{rdb: rdb, store: s3, accountID: 42, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
		r.deleteOldObject(context.Background(), oldObj)

		assert.False(t, deleteCompletedUnprotected.Load(), "S3 DELETE completed unprotected after lock context was canceled")
		assert.Zero(t, r.report.OldDeleted)
		assert.Len(t, r.report.OldLeft, 1, "uncompleted delete must be recorded in OldLeft")
		assert.Empty(t, r.report.Failed)
	})

	t.Run("lock lost after S3 Delete succeeded counts OldDeleted and Failed instead of OldLeft", func(t *testing.T) {
		store := newCtxAwareStubStore()
		store.objects[oldObj.Key()] = body

		rdb := &stubRekeyDB{
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				if err := fn(ctx); err != nil {
					return err
				}
				return errors.New("S3 object lock was lost while the guarded work ran: connection reset")
			},
		}

		r := &rekeyRun{rdb: rdb, store: store, accountID: 42, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
		r.deleteOldObject(context.Background(), oldObj)

		assert.Equal(t, 1, r.report.OldDeleted, "the old S3 object was deleted and must be counted in OldDeleted")
		assert.Empty(t, r.report.OldLeft, "an already-deleted object must not be reported under OldLeft ('Old objects not deleted')")
		require.Len(t, r.report.Failed, 1, "lost lock during delete must still be reported as a failure")
		assert.Contains(t, r.report.Failed[0], oldObj.Key())
	})

	t.Run("referenced object is recorded in OldKept even if lock drops after check", func(t *testing.T) {
		store := newCtxAwareStubStore()
		store.objects[oldObj.Key()] = body

		rdb := &stubRekeyDB{
			isReferenced: func(ctx context.Context, obj db.ContentObject) (bool, error) {
				return true, nil
			},
			executeWithLock: func(ctx context.Context, contentHash string, accountID int64, fn func(ctx context.Context) error) error {
				if err := fn(ctx); err != nil {
					return err
				}
				return errors.New("S3 object lock was lost while the guarded work ran: connection reset")
			},
		}

		r := &rekeyRun{rdb: rdb, store: store, accountID: 42, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
		r.deleteOldObject(context.Background(), oldObj)

		assert.Zero(t, store.deleteCalls.Load())
		assert.Zero(t, r.report.OldDeleted)
		assert.Equal(t, []string{oldObj.Key()}, r.report.OldKept)
		assert.Empty(t, r.report.OldLeft)
		assert.Empty(t, r.report.Failed)
	})

	t.Run("clean delete and failed S3 delete accounting", func(t *testing.T) {
		store := newCtxAwareStubStore()
		store.objects[oldObj.Key()] = body

		// First: S3 delete fails -> OldLeft gets oldObj, OldDeleted stays 0.
		store.deleteFn = func(ctx context.Context, key string) error {
			return errors.New("503 SlowDown")
		}
		r := &rekeyRun{rdb: &stubRekeyDB{}, store: store, accountID: 42, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
		r.deleteOldObject(context.Background(), oldObj)
		assert.Zero(t, r.report.OldDeleted)
		assert.Len(t, r.report.OldLeft, 1)
		assert.Empty(t, r.report.OldKept)
		assert.Empty(t, r.report.Failed)

		// Second: S3 delete succeeds -> OldDeleted increments, OldLeft empty.
		store.deleteFn = nil
		r2 := &rekeyRun{rdb: &stubRekeyDB{}, store: store, accountID: 42, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
		r2.deleteOldObject(context.Background(), oldObj)
		assert.Equal(t, 1, r2.report.OldDeleted)
		assert.Empty(t, r2.report.OldLeft)
		assert.Empty(t, r2.report.OldKept)
		assert.Empty(t, r2.report.Failed)
	})
}

func TestRekeyProcessObjectHonorsCallerContextOnGet(t *testing.T) {
	body := []byte("From: a@example.com\r\nSubject: cancel\r\n\r\nhello\r\n")
	oldObj := db.ContentObject{S3Domain: "example.com", S3Localpart: "user", ContentHash: sha256Hex(body)}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	var getIgnoredCtx atomic.Bool

	s3 := newTestS3StorageForServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cancelRun()
		select {
		case <-req.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
			getIgnoredCtx.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}
	}))

	r := &rekeyRun{
		rdb:     &stubRekeyDB{},
		store:   s3,
		opts:    rekeyOptions{DryRun: true},
		report:  &rekeyReport{},
		written: make(map[db.ContentObject]bool),
	}
	r.processObject(runCtx, oldObj)

	assert.False(t, getIgnoredCtx.Load(), "processObject download ignored caller context cancellation")
	assert.Empty(t, r.report.Unreadable, "a canceled run must not classify the interrupted object as unreadable")
}

func (s *stubRekeyDB) ExecuteWithSharedS3ObjectLocks(ctx context.Context, accountID int64, hashes []string, fn func(context.Context) error) error {
	if len(hashes) != 1 {
		return fmt.Errorf("expected one hash")
	}
	return s.ExecuteWithS3ObjectLock(ctx, hashes[0], accountID, fn)
}

func (s *stubRekeyDB) ExecuteWithS3BodyCleanup(ctx context.Context, objects []db.UserScopedObjectForCleanup, _ time.Duration, fn func(context.Context, []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error)) (int64, error) {
	if len(objects) == 0 {
		return 0, nil
	}
	o := objects[0]
	err := s.ExecuteWithS3ObjectLock(ctx, o.ContentHash, o.AccountID, func(c context.Context) error {
		referenced, err := s.IsContentObjectReferencedWithRetry(c, db.ContentObject{S3Domain: o.S3Domain, S3Localpart: o.S3Localpart, ContentHash: o.ContentHash})
		if err != nil {
			return err
		}
		o.KeepObject = referenced
		_, err = fn(c, []db.UserScopedObjectForCleanup{o})
		return err
	})
	return 0, err
}
