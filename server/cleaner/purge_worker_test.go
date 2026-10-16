package cleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// fakePurgeWorkerDB scripts what the worker sees: which accounts are due, which it can
// claim, and which purges fail. The purge itself is the real PurgeAccount over fake
// steps that report "nothing left" at once, so a purge succeeds unless scripted to fail.
type fakePurgeWorkerDB struct {
	fakePurgeObjectDB
	due       []int64
	held      map[int64]bool  // claimed by "another node"
	failing   map[int64]error // purge fails with this error
	restored  map[int64]bool  // not soft-deleted any more
	claims    []int64
	failures  []int64
	purged    []int64
	pending   int64
	oldest    time.Duration
	finalized map[int64]bool
}

func newFakePurgeWorkerDB(due ...int64) *fakePurgeWorkerDB {
	return &fakePurgeWorkerDB{due: due, held: map[int64]bool{}, failing: map[int64]error{}, restored: map[int64]bool{}, finalized: map[int64]bool{}}
}

func (f *fakePurgeWorkerDB) ListAccountsForPurgeWithRetry(context.Context, int) ([]int64, error) {
	return f.due, nil
}

func (f *fakePurgeWorkerDB) ExecuteWithAccountPurgeLock(ctx context.Context, accountID int64, fn func(ctx context.Context) error) (bool, error) {
	if f.held[accountID] {
		return false, nil
	}
	f.claims = append(f.claims, accountID)
	return true, fn(ctx)
}

func (f *fakePurgeWorkerDB) RecordAccountPurgeFailureWithRetry(_ context.Context, accountID int64, base, _ time.Duration) (time.Time, error) {
	f.failures = append(f.failures, accountID)
	return time.Now().Add(base), nil
}

func (f *fakePurgeWorkerDB) PendingAccountPurgesWithRetry(context.Context) (int64, time.Duration, error) {
	return f.pending, f.oldest, nil
}

// The purge pipeline over the fakes: hard delete done, nothing in S3, finalize succeeds
// unless the account is scripted to fail or was restored.
func (f *fakePurgeWorkerDB) HardDeleteAccountWithRetry(_ context.Context, accountID int64) error {
	if err := f.failing[accountID]; err != nil {
		return err
	}
	return nil
}

func (f *fakePurgeWorkerDB) FinalizeAccountDeletionsWithRetry(_ context.Context, ids []int64) (int64, error) {
	if f.restored[ids[0]] {
		return 0, nil
	}
	f.finalized[ids[0]] = true
	f.purged = append(f.purged, ids[0])
	return 1, nil
}

func (f *fakePurgeWorkerDB) GetAccountDeletionStateWithRetry(_ context.Context, accountID int64) (bool, bool, error) {
	if f.restored[accountID] {
		return true, false, nil
	}
	return !f.finalized[accountID], true, nil
}

func TestPurgeWorker_RunOnce_PurgesEachDueAccountItCanClaim(t *testing.T) {
	rdb := newFakePurgeWorkerDB(1, 2, 3)
	rdb.held[2] = true
	w := newPurgeWorker(rdb, okBulkDeleter{}, time.Minute)

	purged, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, purged)
	require.Equal(t, []int64{1, 3}, rdb.claims, "the account another node holds is not claimed")
	require.Equal(t, []int64{1, 3}, rdb.purged)
	require.Empty(t, rdb.failures)
}

func TestPurgeWorker_RunOnce_FailureIsBackedOffAndDoesNotStopTheCycle(t *testing.T) {
	rdb := newFakePurgeWorkerDB(1, 2)
	rdb.failing[1] = errors.New("S3 refused")
	w := newPurgeWorker(rdb, okBulkDeleter{}, time.Minute)

	purged, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, purged)
	require.Equal(t, []int64{1}, rdb.failures, "the failed account is backed off")
	require.Equal(t, []int64{2}, rdb.purged, "the next account is still purged")
}

func TestPurgeWorker_RunOnce_RestoredAccountIsNeitherPurgedNorBackedOff(t *testing.T) {
	rdb := newFakePurgeWorkerDB(1)
	rdb.restored[1] = true
	w := newPurgeWorker(rdb, okBulkDeleter{}, time.Minute)

	purged, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 0, purged)
	require.Empty(t, rdb.purged)
	require.Empty(t, rdb.failures, "a restore is not a failure to retry")
}

func TestPurgeWorker_RunOnce_CancelledContextStopsWithoutBackoff(t *testing.T) {
	rdb := newFakePurgeWorkerDB(1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	rdb.failing[1] = context.Canceled
	w := newPurgeWorker(rdb, okBulkDeleter{}, time.Minute)
	cancel()

	purged, err := w.RunOnce(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, purged)
	require.Empty(t, rdb.failures, "shutting down is not the account's failure")
}

func TestPurgeWorker_WakeIsNonBlockingAndCoalesces(t *testing.T) {
	w := newPurgeWorker(newFakePurgeWorkerDB(), okBulkDeleter{}, time.Minute)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			w.Wake()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wake blocked")
	}
	require.Len(t, w.wake, 1)
}

var _ = db.AccountPurgeLockID // the claim's lock id lives in db; see ExecuteWithAccountPurgeLock
