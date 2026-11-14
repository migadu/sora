package cleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/mock"
)

// TestCleanupWorker_KeepsVacationHistoryForTheLongestDays is issue #292: the rows of
// vacation_responses are what stops a second reply to a sender within the script's
// :days (RFC 5230 §4.1: "The ":days" argument is used to specify the period in which
// addresses are kept and are not responded to"), which Sora honours up to 365 days.
// The cleaner deleted them after [cleanup] grace_period, the two-phase deletion window
// for expunged messages (14 days by default), so a longer :days was cut short.
func TestCleanupWorker_KeepsVacationHistoryForTheLongestDays(t *testing.T) {
	mockDB := new(mockDatabase)
	ctx := context.Background()
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 new(mockCache),
		gracePeriod:           time.Hour,
		maxAgeRestriction:     time.Hour,
		healthStatusRetention: time.Hour,
	}

	var vacationRetention time.Duration
	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("ExpungeOldMessagesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).
		Run(func(args mock.Arguments) { vacationRetention = args.Get(1).(time.Duration) }).
		Return(int64(0), nil).Once()
	mockDB.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	// Stop the run once the metadata cleanup is done.
	stop := errors.New("stop")
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).
		Return([]db.UserScopedObjectForCleanup{}, stop).Once()

	if err := worker.runOnce(ctx); !errors.Is(err, stop) {
		t.Fatalf("runOnce: %v", err)
	}
	if want := 365 * 24 * time.Hour; vacationRetention < want {
		t.Errorf("vacation history kept for %v, want at least %v (the longest :days) whatever grace_period is", vacationRetention, want)
	}
}
