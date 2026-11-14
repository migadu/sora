package cleaner

import (
	"context"
	"errors"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// expectIdleCyclePhases lets every cleanup phase other than the FTS orphan sweep run any
// number of times, or not at all, with nothing to do.
func expectIdleCyclePhases(m *mockDatabase, ctx context.Context) {
	m.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Maybe()
	m.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Maybe()
	m.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	m.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Maybe()
	m.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything, mock.Anything).Return([]int64{}, nil).Maybe()
}

// TestCleanupWorker_FTSOrphanSweepResumes: one GetUnusedFTSKeys call scans a bounded part of
// messages_fts_v2, so each cycle continues where the previous one stopped and starts over
// after the end of the table. Every cycle used to rescan the same lowest-hash prefix, and
// the orphans past it were never removed (#284).
func TestCleanupWorker_FTSOrphanSweepResumes(t *testing.T) {
	mockDB := new(mockDatabase)
	ctx := context.Background()
	worker := &CleanupWorker{rdb: mockDB, s3: &mockS3{healthy: true}, cache: new(mockCache)}
	expectIdleCyclePhases(mockDB, ctx)

	k1 := db.FTSKey{ContentHash: "1111", AccountID: 1}
	k2 := db.FTSKey{ContentHash: "2222", AccountID: 2}
	mid := db.FTSKey{ContentHash: "8888", AccountID: 3}

	// Cycle 1 starts at the beginning and stops at its scan bound.
	mockDB.On("GetUnusedFTSKeysWithRetry", ctx, db.FTSKey{}, db.BATCH_PURGE_SIZE).Return([]db.FTSKey{k1}, mid, nil).Once()
	mockDB.On("DeleteMessagesFTSByKeyBatchWithRetry", ctx, []db.FTSKey{k1}).Return(int64(1), nil).Once()
	// Cycle 2 continues from there and reaches the end of the table.
	mockDB.On("GetUnusedFTSKeysWithRetry", ctx, mid, db.BATCH_PURGE_SIZE).Return([]db.FTSKey{k2}, db.FTSKey{}, nil).Once()
	mockDB.On("DeleteMessagesFTSByKeyBatchWithRetry", ctx, []db.FTSKey{k2}).Return(int64(1), nil).Once()
	// Cycle 3 starts over.
	mockDB.On("GetUnusedFTSKeysWithRetry", ctx, db.FTSKey{}, db.BATCH_PURGE_SIZE).Return([]db.FTSKey{}, mid, nil).Once()

	for i := 0; i < 3; i++ {
		assert.NoError(t, worker.runOnce(ctx))
	}
	mockDB.AssertExpectations(t)
}

// TestCleanupWorker_FTSOrphanSweepRetriesFailedDelete: when deleting the orphans fails, the
// next cycle scans the same rows again instead of moving past them for a whole lap.
func TestCleanupWorker_FTSOrphanSweepRetriesFailedDelete(t *testing.T) {
	mockDB := new(mockDatabase)
	ctx := context.Background()
	start := db.FTSKey{ContentHash: "4444", AccountID: 4}
	worker := &CleanupWorker{rdb: mockDB, s3: &mockS3{healthy: true}, cache: new(mockCache), ftsSweepCursor: start}
	expectIdleCyclePhases(mockDB, ctx)

	orphans := []db.FTSKey{{ContentHash: "5555", AccountID: 5}}
	next := db.FTSKey{ContentHash: "6666", AccountID: 6}
	mockDB.On("GetUnusedFTSKeysWithRetry", ctx, start, db.BATCH_PURGE_SIZE).Return(orphans, next, nil).Twice()
	mockDB.On("DeleteMessagesFTSByKeyBatchWithRetry", ctx, orphans).Return(int64(0), errors.New("deadlock detected")).Once()
	mockDB.On("DeleteMessagesFTSByKeyBatchWithRetry", ctx, orphans).Return(int64(1), nil).Once()
	mockDB.On("GetUnusedFTSKeysWithRetry", ctx, next, db.BATCH_PURGE_SIZE).Return([]db.FTSKey{}, db.FTSKey{}, nil).Once()

	for i := 0; i < 3; i++ {
		assert.NoError(t, worker.runOnce(ctx))
	}
	mockDB.AssertExpectations(t)
}
