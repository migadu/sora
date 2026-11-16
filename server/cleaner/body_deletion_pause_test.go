package cleaner

import (
	"context"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestBodyDeletionPausedBeforeDestructiveWork(t *testing.T) {
	// Nil dependencies make any attempted delete/retirement fail the test immediately.
	for _, protocol := range []string{"", "paused"} {
		t.Run(protocol, func(t *testing.T) {
			w := &CleanupWorker{bodyDeletionProtocol: protocol}
			n, err := w.deleteS3Objects(context.Background(), []db.UserScopedObjectForCleanup{{AccountID: 1, ContentHash: "body"}})
			require.Zero(t, n)
			require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)
			stats, err := PurgeAccount(context.Background(), nil, nil, 1, protocol)
			require.Equal(t, PurgeStats{}, stats)
			require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)
		})
	}
}

func TestPurgeWorkerDefaultPausedRetainsQueuedAccounts(t *testing.T) {
	rdb := newFakePurgeWorkerDB(1, 2)
	w := newPurgeWorker(rdb, okBulkDeleter{}, time.Minute)
	purged, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, purged)
	require.Empty(t, rdb.claims)
	require.Empty(t, rdb.purged)
	require.Empty(t, rdb.failures)
}

func TestCleanupDefaultPausedRetainsBodyCandidatesAndRows(t *testing.T) {
	ctx := context.Background()
	rdb := new(mockDatabase)
	// Non-body maintenance continues; every body/retirement method is deliberately
	// absent from the expectations, so invoking it is a substantive failure.
	rdb.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	rdb.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	rdb.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	rdb.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	rdb.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	rdb.On("GetUnusedFTSKeysWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.FTSKey{}, db.FTSKey{}, nil).Once()
	rdb.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything, mock.Anything).Return([]int64{}, nil).Once()
	w := &CleanupWorker{rdb: rdb, healthStatusRetention: time.Hour}
	require.NoError(t, w.runOnce(ctx))
	rdb.AssertExpectations(t)
}
