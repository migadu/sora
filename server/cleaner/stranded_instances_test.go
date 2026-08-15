package cleaner

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// syncBuffer serialises writes from the slog handler, so the capture is safe
// under -race even if a log line is emitted from another goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs redirects the default slog logger (which logger.Get() falls back to
// when the process never called logger.Initialize) for the duration of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

func expectRoutineCleanupCalls(mockDB *mockDatabase, ctx context.Context) {
	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()
}

// TestCleanupWorker_ReportsStrandedInstances covers the visibility requirement:
// mail dropped because a node disappeared must not be dropped silently, and a
// backlog that can never be reaped (liveness unknown) must not stay invisible.
// The existing failed-upload alerting only fires at attempts >= max_attempts, and
// a stranded instance never increments attempts at all.
func TestCleanupWorker_ReportsStrandedInstances(t *testing.T) {
	mockDB := new(mockDatabase)
	mockCache := new(mockCache)
	ctx := context.Background()

	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    &mockS3{healthy: true},
		cache:                 mockCache,
		gracePeriod:           14 * 24 * time.Hour,
		healthStatusRetention: time.Hour,
		uploadMaxAttempts:     5,
		instanceLiveness:      7 * 24 * time.Hour,
	}

	expectRoutineCleanupCalls(mockDB, ctx)
	mockDB.On("GetStrandedUploadInstancesWithRetry", ctx, 5, 7*24*time.Hour).Return([]db.StrandedUploadInstance{
		{
			InstanceID:    "mail-07",
			PendingCount:  1234,
			PendingBytes:  9_000_000,
			OldestPending: time.Now().Add(-30 * 24 * time.Hour),
			LastSeen:      sql.NullTime{Time: time.Now().Add(-20 * 24 * time.Hour), Valid: true},
		},
		{
			InstanceID:    "mail-03",
			PendingCount:  7,
			PendingBytes:  4096,
			OldestPending: time.Now().Add(-60 * 24 * time.Hour),
			LastSeen:      sql.NullTime{},
		},
	}, nil).Once()

	logs := captureLogs(t)

	require.NoError(t, worker.runOnce(ctx))
	mockDB.AssertExpectations(t)

	out := logs.String()

	require.Contains(t, out, "mail-07",
		"the id of the instance whose mail is being dropped must appear in the log")
	assert.Contains(t, out, "1234", "the operator needs the count of affected uploads")
	assert.True(t, strings.Contains(out, "level=WARN"),
		"dropping a decommissioned instance's mail must be reported at WARN, got:\n%s", out)

	require.Contains(t, out, "mail-03",
		"an instance of unknown liveness holds a backlog that is never reaped and must be reported")
}
