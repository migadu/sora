package cleaner

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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
func (m *mockDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, objects []db.UserScopedObjectForCleanup) (int64, error) {
	args := m.Called(ctx, objects)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) PruneOldMessageBodiesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	args := m.Called(ctx, retention)
	return args.Get(0).(int64), args.Error(1)
}
func (m *mockDatabase) GetUnusedContentHashesWithRetry(ctx context.Context, limit int) ([]string, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]string), args.Error(1)
}
func (m *mockDatabase) DeleteMessageContentsByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error) {
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
	mockS3 := new(mockS3)
	mockCache := new(mockCache)
	ctx := context.Background()

	gracePeriod := 14 * 24 * time.Hour
	maxAge := 365 * 24 * time.Hour
	ftsRetention := 730 * 24 * time.Hour
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
	mockS3.On("DeleteWithRetry", ctx, "example.com/user1/hash1").Return(nil).Once()
	// Create a proper AWS HTTP 404 error
	notFoundErr := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 404}},
			Err:      errors.New("not found"),
		},
	}
	mockS3.On("DeleteWithRetry", ctx, "example.com/user2/hash2-not-found").Return(notFoundErr).Once()
	mockDB.On("DeleteExpungedMessagesByS3KeyPartsBatchWithRetry", ctx, userScopedCandidates).Return(int64(2), nil).Once()

	// Phase 2a: FTS pruning
	mockDB.On("PruneOldMessageBodiesWithRetry", ctx, ftsRetention).Return(int64(15), nil).Once()

	// Phase 2b: Global resource cleanup
	orphanHashes := []string{"orphan1", "orphan2"}
	mockDB.On("GetUnusedContentHashesWithRetry", ctx, db.BATCH_PURGE_SIZE).Return(orphanHashes, nil).Once()
	mockDB.On("DeleteMessageContentsByHashBatchWithRetry", ctx, orphanHashes).Return(int64(2), nil).Once()
	mockCache.On("Delete", "orphan1").Return(nil).Once()
	mockCache.On("Delete", "orphan2").Return(nil).Once()

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
	mockS3 := new(mockS3)
	mockCache := new(mockCache)
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		cache:                 mockCache,
		maxAgeRestriction:     1 * time.Hour,
		ftsRetention:          1 * time.Hour,
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
	mockDB.AssertNotCalled(t, "GetUnusedContentHashesWithRetry", mock.Anything, mock.Anything)
}

func TestCleanupWorker_RunOnce_S3DeleteFails(t *testing.T) {
	mockDB := new(mockDatabase)
	mockS3 := new(mockS3)
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    mockS3,
		maxAgeRestriction:     1 * time.Hour,
		ftsRetention:          1 * time.Hour,
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
	mockS3.On("DeleteWithRetry", ctx, "d/l/hash1").Return(s3Err).Once()

	// DB batch delete should not be called for the failed S3 key

	// The rest of the cleanup should proceed
	mockDB.On("PruneOldMessageBodiesWithRetry", ctx, mock.Anything).Return(int64(0), nil)
	mockDB.On("GetUnusedContentHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
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
	mockDB.On("GetUnusedContentHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	err := worker.runOnce(ctx)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "ExpungeOldMessagesWithRetry")
	mockDB.AssertNotCalled(t, "PruneOldMessageBodiesWithRetry")
	mockCache.AssertNotCalled(t, "Delete")
}
