// FILE 2 (corroborating): server/cleaner/worker_s3_deadguard_test.go
// Reuses mockDatabase / mockCache already defined in worker_test.go.
// =========================================================================
package cleaner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCleanupWorker_S3HealthGuardIsDeadCode is the end-to-end consequence of the
// IsHealthy() blind spot proved in pkg/resilient.
//
// TestCleanupWorker_RunOnce_SkipsFailedUploadCleanupWhenS3Unhealthy (worker_test.go)
// asserts the safety guard works — but it uses `&mockS3{healthy: false}`, a hand-set
// boolean. This test uses the REAL S3Manager the cleaner is wired with in
// production (resilient.NewResilientS3Storage, worker.go:84) against a totally
// dead S3, and asks whether the guard actually fires.
//
// Expected correct behaviour: CleanupFailedUploadsWithRetry is skipped.
// RED result (defect confirmed):  it runs anyway, deleting the metadata of
// messages whose bodies were never uploaded — permanent message loss during an
// S3 outage, which is precisely what the guard exists to prevent.
func TestCleanupWorker_S3HealthGuardIsDeadCode(t *testing.T) {
	// A totally dead S3: every request 500s.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	s3storage, err := storage.New(
		strings.TrimPrefix(server.URL, "http://"),
		"test-access-key", "test-secret-key", "test-bucket",
		false, false, 5*time.Second,
	)
	require.NoError(t, err)

	// This is exactly what cleaner.New() builds and stores in CleanupWorker.s3.
	resilientS3 := resilient.NewResilientS3Storage(s3storage)

	ctx := context.Background()

	// Simulate a previous cleanup cycle's S3 traffic: the cleaner only ever
	// deletes, so drive deletes until the resilient layer gives up on S3.
	deadline := time.Now().Add(60 * time.Second)
	for resilientS3.GetDeleteBreakerState() != circuitbreaker.StateOpen && time.Now().Before(deadline) {
		require.Error(t, resilientS3.DeleteWithRetry(ctx, "cleanup/candidate-object"))
	}
	require.Equal(t, circuitbreaker.StateOpen, resilientS3.GetDeleteBreakerState(),
		"precondition: S3 is demonstrably down for the cleaner's only S3 operation")

	mockDB := new(mockDatabase)
	worker := &CleanupWorker{
		rdb:                   mockDB,
		s3:                    resilientS3, // the production wiring, not &mockS3{}
		cache:                 new(mockCache),
		healthStatusRetention: 1 * time.Hour,
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	// Declared as .Maybe() so an unexpected call fails the AssertNotCalled below
	// with a clean assertion instead of panicking inside testify.
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Maybe()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return([]db.UserScopedObjectForCleanup{}, nil).Once()
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	require.NoError(t, worker.runOnce(ctx))

	assert.False(t, worker.s3.IsHealthy(),
		"the cleaner's S3Manager must report unhealthy while S3 deletes are circuit-broken")
	mockDB.AssertNotCalled(t, "CleanupFailedUploadsWithRetry", mock.Anything, mock.Anything)
}
