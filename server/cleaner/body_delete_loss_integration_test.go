//go:build integration

package cleaner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

type oneHTTPBodyDeleter struct{ store *storage.S3Storage }

func (s oneHTTPBodyDeleter) DeleteBulkWithRetry(ctx context.Context, keys []string) map[string]error {
	failed := map[string]error{}
	for _, key := range keys {
		if err := s.store.DeleteContext(ctx, key); err != nil {
			failed[key] = err
		}
	}
	return failed
}

// The storage server deliberately accepts DELETE before the PG holder dies, then
// finishes it after a new account can attempt a claim. HTTP cancellation cannot
// retract an operation the remote server already accepted.
func TestBodyDeleteHolderLossDoesNotDeleteNewClaim(t *testing.T) {
	o := newSharedObject(t)
	ctx := context.Background()
	body := []byte(fmt.Sprintf("body of %s %d", t.Name(), time.Now().UnixNano()))
	o.hash = helpers.HashContent(body)
	o.key = helpers.NewS3Key("example.com", o.localpart, o.hash)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	entered, release := make(chan struct{}), make(chan struct{})
	var once, enteredOnce sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	present := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, r.Body)
			mu.Lock()
			present = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			enteredOnce.Do(func() { close(entered) })
			<-release // Deliberately do not infer cancellation from the disconnected client.
			mu.Lock()
			present = false
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer func() { unblock(); srv.Close() }()
	st, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test-access", "test-secret", "mail", false, false, 10*time.Second)
	require.NoError(t, err)
	require.NoError(t, st.PutContext(ctx, o.key, bytes.NewReader(body), int64(len(body))))
	done := make(chan error, 1)
	go func() {
		_, _, err := reapS3Objects(ctx, o.rdb, oneHTTPBodyDeleter{st}, sharedObjectGrace, []db.UserScopedObjectForCleanup{o.candidate(o.a)})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP DELETE did not start after the global reference check")
	}
	id := uint64(db.GetS3ObjectLockID(o.a, o.hash))
	var pid int
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`, int64(id>>32), int64(id&0xffffffff)).Scan(&pid))
	var terminated bool
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&terminated))
	require.True(t, terminated)
	o.addRow(t, o.b, o.inboxB, o.localpart, false, time.Time{})
	var pendingID int64
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('holder-loss-claimer',$1,$2,$3) RETURNING id`, o.hash, len(body), o.b).Scan(&pendingID))
	gate, err := o.rdb.PassS3WriteGateWithRetry(ctx, pendingID, o.b, o.hash, "holder-loss-claimer", time.Minute)
	require.NoError(t, err)
	if gate == db.S3WriteOpen {
		require.NoError(t, st.PutContext(ctx, o.key, bytes.NewReader(body), int64(len(body))))
		require.NoError(t, o.rdb.CompleteLeasedS3UploadWithRetry(ctx, pendingID, "holder-loss-claimer", o.hash, o.b, []string{o.key}))
	}
	unblock()
	select {
	case err := <-done:
		t.Logf("cleanup returned %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not return after HTTP DELETE completed")
	}
	var uploaded bool
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `SELECT uploaded FROM messages WHERE account_id=$1 AND content_hash=$2`, o.b, o.hash).Scan(&uploaded))
	mu.Lock()
	exists := present
	mu.Unlock()
	t.Logf("terminated PG holder=%d; new-account gate=%v uploaded=%v object_exists=%v", pid, gate, uploaded, exists)
	require.False(t, uploaded && !exists, "a storage DELETE accepted before holder loss removed the newly committed live body")
	require.Equal(t, db.S3WriteBusy, gate, "new claims must remain blocked after the holder loses its lock")
	intents, err := o.rdb.GetOperationalDatabase().ListS3BodyDeleteIntents(ctx)
	require.NoError(t, err)
	found := false
	for _, intent := range intents {
		if intent.ContentHash == o.hash {
			found = true
			require.Contains(t, intent.ObjectKeys, o.key)
			require.NotNil(t, intent.LastError)
		}
	}
	require.True(t, found, "uncertain DELETE lost its durable reconciliation anchor")
	_, err = o.rdb.ExecWithRetry(ctx, `UPDATE s3_body_delete_intents SET created_at=now()-interval '100 years' WHERE content_hash=$1`, o.hash)
	require.NoError(t, err)
	gate, err = o.rdb.PassS3WriteGateWithRetry(ctx, pendingID, o.b, o.hash, "after-http-completion", time.Nanosecond)
	require.NoError(t, err)
	require.Equal(t, db.S3WriteBusy, gate, "intent age or upload TTL must not silently clear storage uncertainty")
	require.Equal(t, 1, o.rows(t, o.a), "lost retirement connection must retain its candidate row")
	// The accepted old HTTP request has now completed. Clearing requires that
	// explicit operational fact, this exact UUID, and a fresh reference check.
	var intent db.S3BodyDeleteIntent
	for _, i := range intents {
		if i.ContentHash == o.hash {
			intent = i
		}
	}
	called := false
	err = o.rdb.ReconcileS3BodyDeleteIntent(ctx, o.hash, intent.OperationID, false, func(context.Context, db.S3BodyDeleteIntent, map[string]bool) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called)
	require.NoError(t, o.rdb.ReconcileS3BodyDeleteIntent(ctx, o.hash, intent.OperationID, true, func(c context.Context, i db.S3BodyDeleteIntent, required map[string]bool) error {
		require.False(t, required[o.key], "new claimant has staged bytes and is not falsely marked uploaded")
		return st.DeleteContext(c, o.key)
	}))
	gate, err = o.rdb.PassS3WriteGateWithRetry(ctx, pendingID, o.b, o.hash, "reconciled", time.Minute)
	require.NoError(t, err)
	require.Equal(t, db.S3WriteOpen, gate)
	require.NoError(t, st.PutContext(ctx, o.key, bytes.NewReader(body), int64(len(body))))
	require.NoError(t, o.rdb.CompleteLeasedS3UploadWithRetry(ctx, pendingID, "reconciled", o.hash, o.b, []string{o.key}))
	mu.Lock()
	exists = present
	mu.Unlock()
	require.True(t, exists)
}

type lateExpungeDeleter struct{ beforeReturn func() }

func (s lateExpungeDeleter) DeleteBulkWithRetry(context.Context, []string) map[string]error {
	s.beforeReturn()
	return nil
}

func TestBodyRetirementRetainsNewlyExpungedRow(t *testing.T) {
	o := newSharedObject(t)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	d := lateExpungeDeleter{beforeReturn: func() {
		o.addRow(t, o.a, o.inboxA, o.localpart, false, time.Now())
		_, err := o.rdb.ExecWithRetry(context.Background(), `INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('late-staged-body',$1,100,$2)`, o.hash, o.a)
		require.NoError(t, err)
	}}
	_, _, err := reapS3Objects(context.Background(), o.rdb, d, sharedObjectGrace, []db.UserScopedObjectForCleanup{o.candidate(o.a)})
	require.NoError(t, err)
	require.Equal(t, 1, o.rows(t, o.a), "retirement swept a new staged/expunged row that is still inside the restore grace period")
}

// A stalled PUT can outlive its lease and even remote cancellation. It may leave
// an orphan object, but it must not admit uploaded metadata after cleanup removed
// the exact pending row. The DELETE intent protocol addresses destructive requests;
// it does not claim to retract every accepted PUT at the provider.
func TestBodyUploadOutlivesLeaseCannotFinalizeRetiredRow(t *testing.T) {
	o := newSharedObject(t)
	ctx := context.Background()
	body := []byte(t.Name() + fmt.Sprint(time.Now().UnixNano()))
	o.hash = helpers.HashContent(body)
	o.key = helpers.NewS3Key("example.com", o.localpart, o.hash)
	o.addRow(t, o.a, o.inboxA, o.localpart, false, time.Now().Add(-2*sharedObjectGrace))
	var pending int64
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('stalled-put',$1,$2,$3) RETURNING id`, o.hash, len(body), o.a).Scan(&pending))
	gate, err := o.rdb.PassS3WriteGateWithRetry(ctx, pending, o.a, o.hash, "stalled-owner", time.Minute)
	require.NoError(t, err)
	require.Equal(t, db.S3WriteOpen, gate)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	present := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			<-release
			mu.Lock()
			present = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			mu.Lock()
			present = false
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer func() { unblock(); srv.Close() }()
	st, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test-access", "test-secret", "mail", false, false, 10*time.Second)
	require.NoError(t, err)
	putDone := make(chan error, 1)
	go func() { putDone <- st.PutContext(ctx, o.key, bytes.NewReader(body), int64(len(body))) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("PUT did not reach actual storage endpoint")
	}
	// Model a process unable to renew past TTL, then the failed-upload retirement.
	_, err = o.rdb.ExecWithRetry(ctx, `UPDATE pending_uploads SET lease_until=now()-interval '1 minute' WHERE id=$1`, pending)
	require.NoError(t, err)
	_, err = o.rdb.ExecWithRetry(ctx, `DELETE FROM pending_uploads WHERE id=$1 AND lease_until<now()`, pending)
	require.NoError(t, err)
	_, _, err = reapS3Objects(ctx, o.rdb, oneHTTPBodyDeleter{st}, sharedObjectGrace, []db.UserScopedObjectForCleanup{o.candidate(o.a)})
	require.NoError(t, err)
	require.Zero(t, o.rows(t, o.a))
	unblock()
	require.NoError(t, <-putDone)
	err = o.rdb.CompleteLeasedS3UploadWithRetry(ctx, pending, "stalled-owner", o.hash, o.a, []string{o.key})
	require.ErrorIs(t, err, db.ErrUploadLeaseLost)
	require.Zero(t, o.rows(t, o.a), "expired writer admitted a retired row")
	mu.Lock()
	exists := present
	mu.Unlock()
	require.True(t, exists, "fixture must prove the late PUT actually finished, leaving only a reclaimable orphan")
}
