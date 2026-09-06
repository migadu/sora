//go:build integration

package resilient_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

// advisoryLockEntries counts the granted lock-table entries for id, whoever holds them.
func advisoryLockEntries(t *testing.T, rdb *resilient.ResilientDatabase, id int64) int {
	t.Helper()
	var n int
	require.NoError(t, rdb.QueryRowWithRetry(context.Background(), `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND granted
		  AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1
	`, int64(uint64(id)>>32), int64(uint32(uint64(id)))).Scan(&n))
	return n
}

// The per-object S3 lock must be held for exactly the callback, released on every path,
// and shared with every other node: two pools model two nodes.
func TestS3ObjectLockHeldForTheCallbackOnly(t *testing.T) {
	ctx := context.Background()
	nodeA := common.SetupTestDatabase(t)
	nodeB := common.SetupTestDatabase(t)

	const accountID = int64(424242)
	hash := fmt.Sprintf("s3lock-%d", time.Now().UnixNano())
	lockID := db.GetS3ObjectLockID(accountID, hash)

	// A transaction-scoped try-lock in autocommit is released at once, so it is a pure
	// probe: false exactly while another transaction holds the lock.
	free := func() bool {
		var ok bool
		require.NoError(t, nodeB.QueryRowWithRetry(ctx, "SELECT pg_try_advisory_xact_lock($1)", lockID).Scan(&ok))
		return ok
	}
	require.True(t, free())

	var heldInside bool
	require.NoError(t, nodeA.ExecuteWithS3ObjectLock(ctx, hash, accountID, func(guarded context.Context) error {
		require.NoError(t, guarded.Err(), "the guarded context must be live while the lock is held")
		heldInside = !free()
		return nil
	}))
	require.True(t, heldInside, "the lock must be held while the callback runs")
	require.True(t, free(), "the lock must be released when the callback returns")
	require.Equal(t, 0, advisoryLockEntries(t, nodeB, lockID), "no lock-table entry may survive the callback")

	boom := errors.New("boom")
	require.ErrorIs(t, nodeA.ExecuteWithS3ObjectLock(ctx, hash, accountID, func(context.Context) error { return boom }), boom)
	require.True(t, free(), "the lock must be released when the callback fails")

	// A second node waits for the holder instead of running alongside it.
	release := make(chan struct{})
	holding := make(chan struct{})
	go func() {
		_ = nodeB.ExecuteWithS3ObjectLock(ctx, hash, accountID, func(context.Context) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- nodeA.ExecuteWithS3ObjectLock(ctx, hash, accountID, func(context.Context) error { return nil })
	}()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("ran while node B held the lock (err=%v)", err)
	default:
	}
	close(release)
	require.NoError(t, <-done)
	require.GreaterOrEqual(t, time.Since(started), 300*time.Millisecond)
}

// After a release nothing may remain in the lock table for the cleanup lock: a stranded
// entry is how the 2026-09-06 outage filled PostgreSQL's shared lock table.
func TestCleanupLockLeavesNoLockTableEntryBehind(t *testing.T) {
	ctx := context.Background()
	node := common.SetupTestDatabase(t)

	got, err := node.AcquireCleanupLockWithRetry(ctx)
	require.NoError(t, err)
	require.True(t, got, "the cleanup lock must be free (another test run may hold it briefly)")
	require.Equal(t, 1, advisoryLockEntries(t, node, db.CLEANUP_ADVISORY_LOCK_ID))
	require.NoError(t, node.ReleaseCleanupLockWithRetry(ctx))
	require.Equal(t, 0, advisoryLockEntries(t, node, db.CLEANUP_ADVISORY_LOCK_ID))
}
