package cleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mocks ---

type mockDatabase struct {
	mock.Mock
}

func (m *mockDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	args := m.Called(ctx)
	return args.Bool(0), args.Error(1)
}
func (m *mockDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *mockDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	args := m.Called(ctx, maxAge)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	args := m.Called(ctx, gracePeriod)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	args := m.Called(ctx, gracePeriod)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	args := m.Called(ctx, gracePeriod)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	args := m.Called(ctx, retention)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, limit int) ([]db.UserScopedObjectForCleanup, error) {
	args := m.Called(ctx, gracePeriod, limit)
	return args.Get(0).([]db.UserScopedObjectForCleanup), args.Error(1)
}
func (m *mockDatabase) ExecuteS3DeleteTxWithRetry(ctx context.Context, accountID int64, contentHash string, gracePeriod time.Duration, s3DeleteFunc func() error) (bool, error) {
	args := m.Called(ctx, accountID, contentHash, gracePeriod, s3DeleteFunc)
	return args.Bool(0), args.Error(1)
}
func (m *mockDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, objects []db.UserScopedObjectForCleanup) (int64, error) {
	args := m.Called(ctx, objects)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) PruneOldMessageVectorsWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	args := m.Called(ctx, retention)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) GetUnusedFTSHashesWithRetry(ctx context.Context, limit int) ([]string, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]string), args.Error(1)
}
func (m *mockDatabase) DeleteMessagesFTSByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error) {
	args := m.Called(ctx, hashes)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, limit int) ([]int64, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]int64), args.Error(1)
}
func (m *mockDatabase) FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error) {
	args := m.Called(ctx, accountIDs)
	return args.Get(0).(int64), args.Error(1)
}

type mockS3 struct {
	mock.Mock
	healthy bool
}

func (m *mockS3) IsHealthy() bool {
	return m.healthy
}

func (m *mockS3) DeleteWithRetry(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type mockCache struct {
	mock.Mock
}

func (m *mockCache) Delete(contentHash string) error {
	args := m.Called(contentHash)
	return args.Error(0)
}

// --- Tests ---

func TestCleanupWorker_RunOnce_HappyPath(t *testing.T) {
	// Setup
	mockDB := new(mockDatabase)
	mockS3 := &mockS3{healthy: true}
	mockCache := new(mockCache)
	ctx := context.Background()

	gracePeriod := 14 * 24 * time.Hour
	maxAge := 365 * 24 * time.Hour
	ftsRetention := 0 * time.Hour // Don't prune vectors in this test
	healthRetention := 30 * 24 * time.Hour

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		cache:                 mockCache,
		gracePeriod:           gracePeriod,
		maxAgeRestriction:     maxAge,
		ftsRetention:          ftsRetention,
		healthStatusRetention: healthRetention,
	}

	// --- Mock expectations ---
	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("ExpungeOldMessagesWithRetry", ctx, maxAge).Return(int64(5), nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, gracePeriod).Return(int64(1), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, gracePeriod).Return(int64(1), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, gracePeriod).Return(int64(2), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, healthRetention).Return(int64(20), nil).Once()

	// Phase 1: User-scoped cleanup
	userScopedCandidates := []db.UserScopedObjectForCleanup{
		{ContentHash: "hash1", S3Domain: "example.com", S3Localpart: "user1"},
		{ContentHash: "hash2-not-found", S3Domain: "example.com", S3Localpart: "user2"},
	}
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, gracePeriod, db.BATCH_PURGE_SIZE).Return(userScopedCandidates, nil).Once()

	// hash1: ExecuteS3DeleteTxWithRetry acquires lock, confirms orphan, deletes S3 → success
	mockDB.On("ExecuteS3DeleteTxWithRetry", ctx, int64(0), "hash1", gracePeriod, mock.AnythingOfType("func() error")).
		Return(true, nil).Once()

	// hash2-not-found: ExecuteS3DeleteTxWithRetry acquires lock, confirms orphan, calls s3DeleteFunc → S3 returns 404
	// → the real implementation catches 404 internally and returns (true, nil)
	mockDB.On("ExecuteS3DeleteTxWithRetry", ctx, int64(0), "hash2-not-found", gracePeriod, mock.AnythingOfType("func() error")).
		Return(true, nil).Once()

	mockDB.On("DeleteExpungedMessagesByS3KeyPartsBatchWithRetry", ctx, userScopedCandidates).Return(int64(2), nil).Once()

	// Phase 2a2: FTS vector pruning (skipped since ftsRetention = 0)

	// Phase 2b: Global resource cleanup (FTS)
	orphanHashes := []string{"orphan1", "orphan2"}
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, db.BATCH_PURGE_SIZE).Return(orphanHashes, nil).Once()
	mockDB.On("DeleteMessagesFTSByHashBatchWithRetry", ctx, orphanHashes).Return(int64(2), nil).Once()

	// Phase 3: Final account deletion
	danglingAccounts := []int64{101, 102}
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, db.BATCH_PURGE_SIZE).Return(danglingAccounts, nil).Once()
	mockDB.On("FinalizeAccountDeletionsWithRetry", ctx, danglingAccounts).Return(int64(2), nil).Once()

	// --- Run test ---
	err := worker.runOnce(ctx)

	// --- Assertions ---
	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockS3.AssertExpectations(t)
	mockCache.AssertExpectations(t)
}

func TestCleanupWorker_RunOnce_LockNotAcquired(t *testing.T) {
	mockDB := new(mockDatabase)
	worker := &CleanupWorker{rdb: mockDB}
	ctx := context.Background()

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(false, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "ReleaseCleanupLockWithRetry", mock.Anything)
}

func TestCleanupWorker_RunOnce_PartialFailures(t *testing.T) {
	mockDB := new(mockDatabase)
	mockS3 := &mockS3{healthy: true}
	mockCache := new(mockCache)
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		cache:                 mockCache,
		maxAgeRestriction:     1 * time.Hour,
		ftsRetention:          0,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()

	// Expunge fails, but worker should continue
	mockDB.On("ExpungeOldMessagesWithRetry", ctx, mock.Anything).Return(int64(0), errors.New("db error expunge")).Once()

	// This one is critical and should stop the run
	criticalErr := errors.New("critical db error")
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, criticalErr).Once()

	err := worker.runOnce(ctx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, criticalErr)
	mockDB.AssertExpectations(t)
	// Ensure later phases are not called
}

func TestCleanupWorker_RunOnce_S3DeleteFails(t *testing.T) {
	mockDB := new(mockDatabase)
	mockS3 := &mockS3{healthy: true}
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		maxAgeRestriction:     1 * time.Hour,
		ftsRetention:          0,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("ExpungeOldMessagesWithRetry", ctx, mock.Anything).Return(int64(0), nil)
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil)
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil)
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil)
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil)

	s3Err := errors.New("s3 is down")
	candidates := []db.UserScopedObjectForCleanup{{ContentHash: "hash1", S3Domain: "d", S3Localpart: "l"}}
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return(candidates, nil).Once()
	// ExecuteS3DeleteTxWithRetry returns the S3 error (not a 404, so not handled internally)
	mockDB.On("ExecuteS3DeleteTxWithRetry", ctx, mock.Anything, "hash1", mock.Anything, mock.AnythingOfType("func() error")).
		Return(false, s3Err).Once()

	// DB batch delete should not be called for the failed S3 key

	// The rest of the cleanup should proceed
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockS3.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "DeleteExpungedMessagesByS3KeyPartsBatchWithRetry", mock.Anything, mock.Anything)
}

func TestCleanupWorker_RunOnce_NoOp(t *testing.T) {
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "ExpungeOldMessagesWithRetry")
	mockDB.AssertNotCalled(t, "PruneOldMessageVectorsWithRetry")
	mockCache.AssertNotCalled(t, "Delete")
}

func TestCleanupWorker_RunOnce_VectorPruning(t *testing.T) {
	// Test that vector pruning is called when ftsRetention > 0
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()

	ftsRetention := 1095 * 24 * time.Hour // 3 years

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		ftsRetention:          ftsRetention,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()

	// Both pruning functions should be called
	mockDB.On("PruneOldMessageVectorsWithRetry", ctx, ftsRetention).Return(int64(5), nil).Once()

	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}

func TestCleanupWorker_RunOnce_NoFTSPruningWhenBothZero(t *testing.T) {
	// When ftsRetention is 0, no FTS vector pruning should occur
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		ftsRetention:          0, // keep vectors forever
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()

	// PruneOldMessageVectorsWithRetry should not be called (ftsRetention = 0)
	// (no On() setup means test will fail if they're called)

	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	// Verify pruning was NOT called
	mockDB.AssertNotCalled(t, "PruneOldMessageVectorsWithRetry", mock.Anything, mock.Anything)
}

func TestCleanupWorker_RunOnce_NoFTSRetention(t *testing.T) {
	// ftsRetention is 0 — no FTS pruning should occur at all
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		ftsRetention:          0, // keep vectors forever
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()

	// Vector pruning should NOT be called (ftsRetention = 0)

	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "PruneOldMessageVectorsWithRetry", mock.Anything, mock.Anything)
}

func TestCleanupWorker_RunOnce_SkipsFailedUploadCleanupWhenS3Unhealthy(t *testing.T) {
	// CRITICAL SAFETY TEST: When S3 is down, CleanupFailedUploads must NOT run.
	// If it runs during S3 outage, it would delete messages that can't be uploaded,
	// causing permanent message loss.
	mockDB := new(mockDatabase)
	mockS3 := &mockS3{healthy: false} // S3 is DOWN
	mockCache := new(mockCache)
	ctx := context.Background()

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		cache:                 mockCache,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()

	// CleanupFailedUploadsWithRetry should NOT be called when S3 is unhealthy
	// (no On() setup means test fails if it's called)

	// Other cleanup operations should still proceed
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	// CRITICAL: Verify CleanupFailedUploads was NOT called
	mockDB.AssertNotCalled(t, "CleanupFailedUploadsWithRetry", mock.Anything, mock.Anything)
	t.Log("✓ CleanupFailedUploads correctly skipped when S3 is unhealthy — messages preserved")
}

func TestCleanupWorker_RunOnce_VectorOnlyPruning(t *testing.T) {
	// ftsRetention is set — vector pruning should be called
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()

	ftsRetention := 1095 * 24 * time.Hour // 3 years

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		ftsRetention:          ftsRetention,
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()

	// Vector pruning should be called when ftsRetention > 0
	mockDB.On("PruneOldMessageVectorsWithRetry", ctx, ftsRetention).Return(int64(8), nil).Once()

	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}
