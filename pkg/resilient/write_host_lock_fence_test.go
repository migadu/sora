//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Advisory locks exclude only what runs on the server that holds them. Once Sora writes
// through another server, the locks it still holds on the former write host order
// nothing there: an upload through the new writer passes its write gate, writes the
// body and finalizes its row, and a cleaner still holding the body's lock on the former
// writer deletes it afterwards (#824). The tests below pin that the work guarded by
// those locks is cancelled before the first write reaches the new server.

// newDeleteRecordingS3 returns S3 storage backed by a fake server that records the keys
// of every DeleteObjects request.
func newDeleteRecordingS3(t *testing.T) (*ResilientS3Storage, *deleteObjectsRecorder) {
	t.Helper()
	recorder := &deleteObjectsRecorder{}
	server := httptest.NewServer(recorder)
	t.Cleanup(server.Close)
	base, err := storage.New(strings.TrimPrefix(server.URL, "http://"),
		"test-access-key", "test-secret-key", "test-bucket", false, false, 5*time.Second)
	require.NoError(t, err)
	return NewResilientS3Storage(base), recorder
}

func (r *deleteObjectsRecorder) deletedKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var keys []string
	for _, request := range r.requests {
		keys = append(keys, request...)
	}
	return keys
}

// The cleaner on this node has confirmed a body is an orphan and holds its lock on the
// write host A. The runtime selector then moves writes to B. Every write this node
// makes from then on — an upload passing its gate, writing the body and finalizing the
// row — runs on B, where A's lock excludes nothing, so the cleaner's S3 delete must be
// cancelled by the time B is handed out, not whenever A's session happens to die.
func TestWriteHostSwitchCancelsS3DeleteGuardedOnFormerWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	rdb := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))
	former := rdb.failoverManager.writePools[0]
	// The promoted writer. One PostgreSQL server stands for both hosts: what is under
	// test is the order this process keeps, not what a second server would do.
	b := newTestPool(t, cfg, nil)
	promoted := &DatabasePool{database: &db.Database{WritePool: b, ReadPool: b}, host: "promoted-B"}
	promoted.isHealthy.Store(true)
	rdb.failoverManager.writePools = append(rdb.failoverManager.writePools, promoted)

	f := newCopyFixture(t, former.database.WritePool, 1)
	_, err := former.database.WritePool.Exec(ctx,
		`UPDATE messages SET expunged_at = now() - interval '2 days' WHERE account_id = $1`, f.accountID)
	require.NoError(t, err)
	orphan := db.UserScopedObjectForCleanup{
		AccountID:   f.accountID,
		ContentHash: fmt.Sprintf("hash-%d-1", f.accountID),
		S3Domain:    "example.com",
		S3Localpart: "user",
	}
	key := helpers.NewS3Key(orphan.S3Domain, orphan.S3Localpart, orphan.ContentHash)
	s3, recorder := newDeleteRecordingS3(t)

	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	cleaned := make(chan error, 1)
	go func() {
		cleaned <- rdb.ExecuteWithLockedS3Orphans(ctx, []db.UserScopedObjectForCleanup{orphan}, time.Hour,
			func(guarded context.Context, orphans []db.UserScopedObjectForCleanup) error {
				if len(orphans) != 1 {
					return fmt.Errorf("expected the expunged body to be an orphan, got %d orphans", len(orphans))
				}
				entered <- guarded
				<-resume
				// As reapS3Objects does.
				if failures := s3.DeleteBulkWithRetry(guarded, []string{key}); len(failures) > 0 {
					return failures[key]
				}
				return nil
			})
	}()
	var guarded context.Context
	select {
	case guarded = <-entered:
	case err := <-cleaned:
		t.Fatalf("the cleanup ended before its S3 delete: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// The health check finds A unhealthy; the next write operation moves to B.
	former.isHealthy.Store(false)
	require.Same(t, promoted.database, rdb.getOperationalDatabaseForOperation(ctx, true), "writes must move to promoted-B")
	guardErr := guarded.Err() // read at once: no waiting for a keepalive
	close(resume)
	err = <-cleaned

	assert.Error(t, guardErr, "the cleanup guarded by locks on the former write host was still live when writes moved to promoted-B")
	assert.Error(t, err, "the cleanup reported success although its locks no longer excluded anything on the write host")
	assert.Empty(t, recorder.deletedKeys(), "the former writer's cleanup deleted the body after writes moved to promoted-B")
}

// One write host whose name now leads to another server: a write fails with SQLSTATE
// 25006 because the connection still reaches the old primary, now read-only, and Sora
// drops the pool's connections so the next ones reach the new primary. The lock
// transaction keeps its connection to the old server, so the work it guards is no
// longer protected against writers on the new one.
func TestReadOnlyWriteHostCancelsWorkGuardedOnIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	rdb := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))

	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	finished := make(chan error, 1)
	hash := fmt.Sprintf("read-only-writer-%d", time.Now().UnixNano())
	go func() {
		finished <- rdb.ExecuteWithS3ObjectLock(ctx, hash, 1, func(guarded context.Context) error {
			entered <- guarded
			<-resume
			return guarded.Err()
		})
	}()
	var guarded context.Context
	select {
	case guarded = <-entered:
	case err := <-finished:
		t.Fatalf("the guarded work ended early: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	_, err := rdb.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, func(ctx context.Context, tx pgx.Tx) (any, error) {
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return nil, err
		}
		_, err := tx.Exec(ctx, "SELECT nextval('messages_modseq')")
		return nil, err
	})
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "expected a PostgreSQL error, got %v", err)
	require.Equal(t, "25006", pgErr.Code)
	guardErr := guarded.Err()
	close(resume)
	err = <-finished

	assert.Error(t, guardErr, "the work guarded on the read-only server was still live after its write pool was reconnected")
	assert.Error(t, err, "the guarded work reported success although its lock no longer excluded the new primary's writers")
}

// Multi-write-host failover: a writer opens its transaction on former write host A before
// failover switches writes to promoted-B and guarded work takes advisory locks on B. When
// the writer's statement on A subsequently fails with SQLSTATE 25006, it must not reset B's
// pool or fence B's advisory locks.
func TestReadOnlyTxFromFormerWriteHostDoesNotFencePromotedWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	rdb := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))
	former := rdb.failoverManager.writePools[0]
	b := newTestPool(t, cfg, nil)
	promoted := &DatabasePool{database: &db.Database{WritePool: b, ReadPool: b}, host: "promoted-B"}
	promoted.isHealthy.Store(true)
	rdb.failoverManager.writePools = append(rdb.failoverManager.writePools, promoted)

	txOpened := make(chan struct{})
	runWrite := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		_, err := rdb.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, func(ctx context.Context, tx pgx.Tx) (any, error) {
			close(txOpened)
			<-runWrite
			if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
				return nil, err
			}
			_, err := tx.Exec(ctx, "SELECT nextval('messages_modseq')")
			return nil, err
		})
		writeDone <- err
	}()
	select {
	case <-txOpened:
	case err := <-writeDone:
		t.Fatalf("writer ended before opening tx on former write host: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Failover moves writes from former to promoted-B while W1's tx is still open on former.
	former.isHealthy.Store(false)
	require.Same(t, promoted.database, rdb.getOperationalDatabaseForOperation(ctx, true), "writes must move to promoted-B")

	// Guarded work acquires advisory locks on the healthy promoted writer B, and B holds
	// an established idle connection in its pool.
	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	finished := make(chan error, 1)
	hash := fmt.Sprintf("promoted-writer-lock-%d", time.Now().UnixNano())
	go func() {
		finished <- rdb.ExecuteWithS3ObjectLock(ctx, hash, 1, func(guarded context.Context) error {
			entered <- guarded
			<-resume
			return guarded.Err()
		})
	}()
	var guardedOnPromoted context.Context
	select {
	case guardedOnPromoted = <-entered:
	case err := <-finished:
		t.Fatalf("guarded work on promoted-B ended early: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var promotedPIDBefore int
	require.NoError(t, promoted.database.WritePool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&promotedPIDBefore))

	// W1 now runs its write statement on the connection still open to former (A) and gets 25006.
	close(runWrite)
	writeErr := <-writeDone
	var pgErr *pgconn.PgError
	require.True(t, errors.As(writeErr, &pgErr), "expected a PostgreSQL error, got %v", writeErr)
	require.Equal(t, "25006", pgErr.Code)

	assert.NoError(t, guardedOnPromoted.Err(), "a 25006 from an in-flight tx on the former write host fenced locks on promoted-B")
	var promotedPIDAfter int
	require.NoError(t, promoted.database.WritePool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&promotedPIDAfter))
	assert.Equal(t, promotedPIDBefore, promotedPIDAfter, "a 25006 on the former write host reset promoted-B's connection pool")

	close(resume)
	assert.NoError(t, <-finished, "guarded work on promoted-B failed after former write host returned 25006")
}

// Multi-write-host failover before the 30s health check runs: when SQLSTATE 25006 arrives
// on writePools[0] while writePools[1] is healthy, Sora must mark writePools[0] unhealthy,
// retire it, and fail writes and advisory lock transactions over to writePools[1] at once.
func TestReadOnlyWriteHostFailsOverToHealthyWritePool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	rdb := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))
	former := rdb.failoverManager.writePools[0]
	b := newTestPool(t, cfg, nil)
	promoted := &DatabasePool{database: &db.Database{WritePool: b, ReadPool: b}, host: "promoted-B"}
	promoted.isHealthy.Store(true)
	rdb.failoverManager.writePools = append(rdb.failoverManager.writePools, promoted)

	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	finished := make(chan error, 1)
	hash := fmt.Sprintf("failover-on-25006-%d", time.Now().UnixNano())
	go func() {
		finished <- rdb.ExecuteWithS3ObjectLock(ctx, hash, 1, func(guarded context.Context) error {
			entered <- guarded
			<-resume
			return guarded.Err()
		})
	}()
	var formerGuarded context.Context
	select {
	case formerGuarded = <-entered:
	case err := <-finished:
		t.Fatalf("guarded work on former write host ended early: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	_, err := rdb.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, func(ctx context.Context, tx pgx.Tx) (any, error) {
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return nil, err
		}
		_, err := tx.Exec(ctx, "SELECT nextval('messages_modseq')")
		return nil, err
	})
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "expected a PostgreSQL error, got %v", err)
	require.Equal(t, "25006", pgErr.Code)

	assert.Error(t, formerGuarded.Err(), "work guarded on the read-only former write host was not cancelled")
	close(resume)
	assert.Error(t, <-finished, "work guarded on the read-only former write host succeeded")

	assert.False(t, former.isHealthy.Load(), "read-only former write host remained marked healthy")
	assert.Same(t, promoted.database, rdb.getOperationalDatabaseForOperation(ctx, true),
		"writes and advisory lock transactions stayed on the read-only write host instead of failing over to promoted-B")
	lock, retireErr := former.database.BeginAdvisoryLockTx(ctx)
	if lock != nil {
		lock.Release()
	}
	assert.ErrorIs(t, retireErr, db.ErrAdvisoryLocksFenced, "former write host was not retired on failover to promoted-B")
}

// Single write host behind a VIP/DNS with two concurrent pre-failover writers: W1 and W2
// both open transactions before failover. W1 hits 25006 first, resetting the pool and
// fencing pre-failover locks. Guarded work then opens a fresh post-reset connection to the
// new primary and takes advisory locks there. When W2 subsequently hits 25006 on its
// pre-reset connection, it must not reset the pool again or fence the post-reset locks.
func TestSecondPreFailoverReadOnlyTxDoesNotFencePostResetLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	pool := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, pool)

	startPausedReadOnlyWrite := func() (opened <-chan struct{}, run chan<- struct{}, done <-chan error) {
		openedCh := make(chan struct{})
		runCh := make(chan struct{})
		doneCh := make(chan error, 1)
		go func() {
			_, err := rdb.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, func(ctx context.Context, tx pgx.Tx) (any, error) {
				close(openedCh)
				<-runCh
				if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
					return nil, err
				}
				_, err := tx.Exec(ctx, "SELECT nextval('messages_modseq')")
				return nil, err
			})
			doneCh <- err
		}()
		return openedCh, runCh, doneCh
	}

	w1Opened, w1Run, w1Done := startPausedReadOnlyWrite()
	w2Opened, w2Run, w2Done := startPausedReadOnlyWrite()
	for i, ch := range []<-chan struct{}{w1Opened, w2Opened} {
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatalf("writer %d did not open tx: %v", i+1, ctx.Err())
		}
	}

	// W1 hits 25006 on its pre-failover connection and resets + fences the pool.
	close(w1Run)
	w1Err := <-w1Done
	var pgErr *pgconn.PgError
	require.True(t, errors.As(w1Err, &pgErr), "expected W1 to fail with 25006, got %v", w1Err)
	require.Equal(t, "25006", pgErr.Code)

	// Post-reset advisory lock transaction and idle pooled connection on the new primary.
	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	finished := make(chan error, 1)
	hash := fmt.Sprintf("post-reset-lock-%d", time.Now().UnixNano())
	go func() {
		finished <- rdb.ExecuteWithS3ObjectLock(ctx, hash, 1, func(guarded context.Context) error {
			entered <- guarded
			<-resume
			return guarded.Err()
		})
	}()
	var postResetGuarded context.Context
	select {
	case postResetGuarded = <-entered:
	case err := <-finished:
		t.Fatalf("post-reset guarded work ended early: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var pidAfterFirstReset int
	require.NoError(t, pool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pidAfterFirstReset))

	// W2 now hits 25006 on its pre-reset connection that was opened before W1's reset.
	close(w2Run)
	w2Err := <-w2Done
	pgErr = nil
	require.True(t, errors.As(w2Err, &pgErr), "expected W2 to fail with 25006, got %v", w2Err)
	require.Equal(t, "25006", pgErr.Code)

	assert.NoError(t, postResetGuarded.Err(), "a second pre-reset transaction's 25006 fenced post-reset advisory locks")
	var pidAfterSecond25006 int
	require.NoError(t, pool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pidAfterSecond25006))
	assert.Equal(t, pidAfterFirstReset, pidAfterSecond25006, "a second pre-reset transaction's 25006 reset the pool again")

	close(resume)
	assert.NoError(t, <-finished, "post-reset guarded work failed after pre-reset W2 returned 25006")
}
