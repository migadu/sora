package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests below pin the contract of AdvisoryLockTx, the primitive that replaced Sora's
// session-level advisory locks after the 2026-09-06 lock-table exhaustion (see its doc
// comment): a lock lives exactly as long as its transaction, on the backend that runs
// that transaction, and the transaction outlives idle_in_transaction_session_timeout.

func advisoryLockTestDB(t *testing.T) *Database {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database := setupTestDatabaseWithMaxConns(t, 10)
	t.Cleanup(database.Close)
	return database
}

// advisoryLockEntries counts the granted lock-table entries for id, whoever holds them.
func advisoryLockEntries(t *testing.T, database *Database, id int64) int {
	t.Helper()
	var n int
	require.NoError(t, database.GetWritePool().QueryRow(context.Background(), `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND granted
		  AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1
	`, int64(uint64(id)>>32), int64(uint32(uint64(id)))).Scan(&n))
	return n
}

// heldByOther reports whether id is held by some other transaction: a fresh
// transaction's try-lock fails exactly then.
func heldByOther(t *testing.T, database *Database, id int64) bool {
	t.Helper()
	probe, err := database.BeginAdvisoryLockTx(context.Background())
	require.NoError(t, err)
	defer probe.Release()
	acquired, err := probe.TryLock(context.Background(), id)
	require.NoError(t, err)
	return !acquired
}

func TestAdvisoryLockTxExcludesOthersAndReleasesEverything(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()
	id := GetS3ObjectLockID(1, fmt.Sprintf("advisory-tx-%d", time.Now().UnixNano()))

	holder, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	acquired, err := holder.TryLock(ctx, id)
	require.NoError(t, err)
	require.True(t, acquired)

	assert.True(t, heldByOther(t, database, id), "a second transaction must not get the lock")
	assert.Equal(t, 1, advisoryLockEntries(t, database, id))

	// Lock waits for the holder and proceeds once it is gone.
	waiter, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer waiter.Release()
	got := make(chan error, 1)
	go func() { got <- waiter.Lock(ctx, id) }()
	select {
	case err := <-got:
		t.Fatalf("Lock returned %v while the lock was held", err)
	case <-time.After(300 * time.Millisecond):
	}
	holder.Release()
	select {
	case err := <-got:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Lock did not proceed after the holder released")
	}
	assert.True(t, heldByOther(t, database, id), "the waiter now holds the lock")

	waiter.Release()
	waiter.Release() // idempotent
	assert.Equal(t, 0, advisoryLockEntries(t, database, id), "no lock-table entry may survive Release")
	assert.False(t, heldByOther(t, database, id))
	assert.Error(t, waiter.Ping(ctx), "a released transaction is unusable")
}

func TestAdvisoryLockTxTryLockAllKeepsOrder(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	free := GetS3ObjectLockID(1, fmt.Sprintf("advisory-all-free-%d", suffix))
	taken := GetS3ObjectLockID(1, fmt.Sprintf("advisory-all-taken-%d", suffix))

	other, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer other.Release()
	acquired, err := other.TryLock(ctx, taken)
	require.NoError(t, err)
	require.True(t, acquired)

	batch, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer batch.Release()
	// The same id twice is stacked on this transaction, never read as held elsewhere.
	results, err := batch.TryLockAll(ctx, []int64{free, taken, free})
	require.NoError(t, err)
	assert.Equal(t, []bool{true, false, true}, results)

	batch.Release()
	assert.Equal(t, 0, advisoryLockEntries(t, database, free))
}

func TestAdvisoryLockTxDiesWithItsBackend(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()
	id := GetS3ObjectLockID(1, fmt.Sprintf("advisory-dies-%d", time.Now().UnixNano()))

	holder, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	acquired, err := holder.TryLock(ctx, id)
	require.NoError(t, err)
	require.True(t, acquired)

	var pid int
	require.NoError(t, holder.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	}))

	// The backend dies (a failover, a pooler retiring it, an operator): the lock must go
	// with it and the holder must find out, rather than the lock lingering anywhere.
	var terminated bool
	require.NoError(t, database.GetWritePool().QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&terminated))
	require.True(t, terminated)

	require.Eventually(t, func() bool { return advisoryLockEntries(t, database, id) == 0 },
		5*time.Second, 50*time.Millisecond, "the lock must vanish with its backend")
	assert.Error(t, holder.Ping(ctx), "the holder must learn that its locks are gone")
	holder.Release() // must be safe on a dead transaction
}

// idle_in_transaction_session_timeout kills a transaction that sits idle, and a lock
// transaction sits idle by design while the guarded S3 work runs elsewhere. The
// keepalive is what carries the locks across that: without it (first case) the server
// kills the transaction and the lock is gone; with it, the lock survives.
func TestAdvisoryLockTxKeepaliveOutlivesIdleTimeout(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()

	cases := []struct {
		name      string
		keepalive time.Duration
		survives  bool
	}{
		{"without keepalive the server kills the idle transaction", time.Hour, false},
		{"with keepalive the lock survives", 50 * time.Millisecond, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			previous := advisoryLockKeepalive
			advisoryLockKeepalive = tc.keepalive
			t.Cleanup(func() { advisoryLockKeepalive = previous })

			id := GetS3ObjectLockID(1, fmt.Sprintf("advisory-keepalive-%d", time.Now().UnixNano()))
			holder, err := database.BeginAdvisoryLockTx(ctx)
			require.NoError(t, err)
			defer holder.Release()
			acquired, err := holder.TryLock(ctx, id)
			require.NoError(t, err)
			require.True(t, acquired)

			// Shorten the server-side timeout on this very session. SET inside the
			// transaction is undone by its ROLLBACK, so nothing leaks back to the pool.
			require.NoError(t, holder.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "SET idle_in_transaction_session_timeout = '300ms'")
				return err
			}))

			time.Sleep(1200 * time.Millisecond)

			if tc.survives {
				assert.NoError(t, holder.Ping(ctx))
				assert.True(t, heldByOther(t, database, id), "the lock must still be held")
			} else {
				assert.Error(t, holder.Ping(ctx))
				assert.False(t, heldByOther(t, database, id), "the lock died with the transaction")
			}
		})
	}
}

// While the guarded work runs, the lock transaction idles. It must do so holding no
// snapshot: with one, VACUUM cannot reclaim anything newer for the whole S3 round trip,
// and CREATE INDEX CONCURRENTLY waits for the transaction to end — which, for the
// migration leader lock, deadlocks a migration that runs one (observed on the test
// database before run() gained its trailing SELECT 1). Both the function lookup in a
// lock statement and the portal of an extended-protocol statement leave a snapshot
// behind, so both are exercised.
func TestAdvisoryLockTxIdlesWithoutSnapshot(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()
	pool := database.GetWritePool()

	_, err := pool.Exec(ctx, "CREATE TABLE IF NOT EXISTS advisory_lock_cic_probe (id int)")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS advisory_lock_cic_probe") })

	lock, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer lock.Release()

	var pid int
	require.NoError(t, lock.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	}))
	idle := func(step string) {
		t.Helper()
		var state string
		var hasXID, hasXmin bool
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT state, backend_xid IS NOT NULL, backend_xmin IS NOT NULL
			FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&state, &hasXID, &hasXmin))
		assert.Equal(t, "idle in transaction", state, step)
		assert.False(t, hasXID, "%s: the lock transaction must not have a transaction id", step)
		assert.False(t, hasXmin, "%s: the lock transaction must not pin a snapshot while idle", step)
	}

	acquired, err := lock.TryLock(ctx, GetS3ObjectLockID(1, fmt.Sprintf("advisory-idle-%d", time.Now().UnixNano())))
	require.NoError(t, err)
	require.True(t, acquired)
	idle("after TryLock")

	require.NoError(t, lock.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT $1::int", 1) // extended protocol: leaves an unnamed portal
		return err
	}))
	idle("after an extended-protocol statement")

	cicCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = pool.Exec(cicCtx, "CREATE INDEX CONCURRENTLY advisory_lock_cic_probe_idx ON advisory_lock_cic_probe (id)")
	require.NoError(t, err, "CREATE INDEX CONCURRENTLY must not wait for an idle lock transaction")
}

// A keepalive tick that fires while another statement holds the transaction must not
// arm its statement timeout before it gets the transaction: a deadline that ran out in
// the queue would cancel the ping the moment it starts, abort the transaction, and drop
// every lock — while the holder believes it is still protected. (Caught in review
// before it shipped.)
func TestAdvisoryLockTxKeepaliveSurvivesContention(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()

	prevKeepalive, prevTimeout := advisoryLockKeepalive, advisoryLockStatementTimeout
	advisoryLockKeepalive, advisoryLockStatementTimeout = 20*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { advisoryLockKeepalive, advisoryLockStatementTimeout = prevKeepalive, prevTimeout })

	id := GetS3ObjectLockID(1, fmt.Sprintf("advisory-contention-%d", time.Now().UnixNano()))
	holder, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	acquired, err := holder.TryLock(ctx, id)
	require.NoError(t, err)
	require.True(t, acquired)

	// Hold the transaction for longer than the statement timeout while ticks queue up.
	require.NoError(t, holder.run(ctx, func(context.Context, pgx.Tx) error {
		time.Sleep(400 * time.Millisecond)
		return nil
	}))
	time.Sleep(100 * time.Millisecond) // let the queued ticks run

	assert.NoError(t, holder.Ping(ctx), "a queued keepalive must not have aborted the transaction")
	assert.NoError(t, holder.Err())
	assert.True(t, heldByOther(t, database, id), "the lock must still be held")
}

// Work guarded by the locks must learn that they are gone: Guard's context is cancelled
// when the loss is noticed, Err reports it, and a guard taken afterwards is born
// cancelled. Release cancels outstanding guards as well.
func TestAdvisoryLockTxGuardCancelsWhenLocksAreLost(t *testing.T) {
	database := advisoryLockTestDB(t)
	ctx := context.Background()

	prev := advisoryLockKeepalive
	advisoryLockKeepalive = 50 * time.Millisecond // notice the loss promptly
	t.Cleanup(func() { advisoryLockKeepalive = prev })

	holder, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	acquired, err := holder.TryLock(ctx, GetS3ObjectLockID(1, fmt.Sprintf("advisory-guard-%d", time.Now().UnixNano())))
	require.NoError(t, err)
	require.True(t, acquired)

	guarded, done := holder.Guard(ctx)
	defer done()
	require.NoError(t, guarded.Err())

	var pid int
	require.NoError(t, holder.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	}))
	var terminated bool
	require.NoError(t, database.GetWritePool().QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&terminated))
	require.True(t, terminated)

	select {
	case <-guarded.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the guarded context was not cancelled after the backend died")
	}
	assert.Error(t, context.Cause(guarded))
	assert.Error(t, holder.Err())

	late, doneLate := holder.Guard(ctx)
	defer doneLate()
	assert.Error(t, late.Err(), "a guard taken after the loss must be born cancelled")

	// Release cancels the guards of a healthy transaction too.
	other, err := database.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	released, doneReleased := other.Guard(ctx)
	defer doneReleased()
	other.Release()
	select {
	case <-released.Done():
	case <-time.After(time.Second):
		t.Fatal("Release must cancel outstanding guards")
	}
}
