package cleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/mock"
)

// TestCleanupWorker_KeepsRedirectLogForTheRateWindow is issue #430: the Sieve redirect
// rate limit counts an account's redirect_log rows within limits.redirect_rate_window.
// The cleaner deleted them after [cleanup] grace_period, the two-phase deletion window
// for expunged messages, so a window longer than the grace period forgot the earlier
// redirects and let more through than configured.
func TestCleanupWorker_KeepsRedirectLogForTheRateWindow(t *testing.T) {
	mockDB := new(mockDatabase)
	ctx := context.Background()
	window := 24 * time.Hour
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 new(mockCache),
		gracePeriod:           time.Hour,
		maxAgeRestriction:     time.Hour,
		healthStatusRetention: time.Hour,
		redirectLogRetention:  window,
	}

	var redirectRetention time.Duration
	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("ExpungeOldMessagesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).
		Run(func(args mock.Arguments) { redirectRetention = args.Get(1).(time.Duration) }).
		Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	// Stop the run once the metadata cleanup is done.
	stop := errors.New("stop")
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).
		Return([]db.UserScopedObjectForCleanup{}, stop).Once()

	if err := worker.runOnce(ctx); !errors.Is(err, stop) {
		t.Fatalf("runOnce: %v", err)
	}
	if redirectRetention != window {
		t.Errorf("redirect_log kept for %v, want %v (the redirect rate window) whatever grace_period is", redirectRetention, window)
	}
}
