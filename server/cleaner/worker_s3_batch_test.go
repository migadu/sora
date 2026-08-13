package cleaner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// s3ProbeDatabase reproduces, in-process, the two shapes the cleaner's S3 deletion
// path can take:
//
//   - ExecuteS3DeleteTxWithRetry invokes the caller's S3 delete from inside an open
//     write transaction (pkg/resilient/cleanup_operations.go runs s3DeleteFunc between
//     BEGIN and COMMIT), so the probe marks a transaction open around it.
//   - ExecuteWithLockedS3Orphans holds only the per-object advisory locks on a
//     dedicated session, with no transaction open while the callback runs.
//
// Everything else is delegated to the testify mockDatabase from worker_test.go.
type s3ProbeDatabase struct {
	*mockDatabase

	mu          sync.Mutex
	locksHeld   int
	rowsDeleted []db.UserScopedObjectForCleanup
}

// holdingLocks reports whether the per-object advisory locks are held right now, i.e.
// whether the caller is inside the ExecuteWithLockedS3Orphans callback.
func (d *s3ProbeDatabase) holdingLocks() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.locksHeld > 0
}

func (d *s3ProbeDatabase) ExecuteWithLockedS3Orphans(ctx context.Context, objects []db.UserScopedObjectForCleanup, gracePeriod time.Duration, fn func(orphans []db.UserScopedObjectForCleanup) error) error {
	// Models the real contract: the per-object advisory locks are held on a dedicated
	// session for the duration of fn, and no transaction is open while it runs.
	d.mu.Lock()
	d.locksHeld++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.locksHeld--
		d.mu.Unlock()
	}()
	return fn(objects)
}

func (d *s3ProbeDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, objects []db.UserScopedObjectForCleanup) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rowsDeleted = append(d.rowsDeleted, objects...)
	return int64(len(objects)), nil
}

// s3ProbeStorage counts S3 round trips and records whether each one was issued while the
// per-object advisory locks were held.
type s3ProbeStorage struct {
	rdb *s3ProbeDatabase

	mu           sync.Mutex
	roundTrips   int
	deletedKeys  []string
	outsideLocks int
}

func (s *s3ProbeStorage) IsHealthy() bool { return true }

func (s *s3ProbeStorage) record(keys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roundTrips++
	s.deletedKeys = append(s.deletedKeys, keys...)
	if !s.rdb.holdingLocks() {
		s.outsideLocks++
	}
}

func (s *s3ProbeStorage) DeleteWithRetry(ctx context.Context, key string) error {
	s.record(key)
	return nil
}

func (s *s3ProbeStorage) DeleteBulkWithRetry(ctx context.Context, keys []string) map[string]error {
	s.record(keys...)
	return nil
}

// TestCleanupWorker_S3DeletesAreBatchedAndOutsideTransactions pins the two properties
// the cleaner's S3 deletion path must have:
//
//  1. Every S3 delete happens inside the advisory-lock window, on a dedicated session
//     with no transaction open. The lock is what keeps the delete from racing an
//     uploader PUT for the same object; holding it via a transaction instead would park
//     a pool connection and its locks for the length of a network round trip.
//  2. A batch of candidates costs one S3 request, not one request per object.
//
// The lock-window assertion is checked against the callback the cleaner actually uses,
// so moving a delete out of that window fails this test. An earlier version keyed it on
// a probe method the cleaner no longer calls, which made it unfalsifiable.
func TestCleanupWorker_S3DeletesAreBatchedAndOutsideTransactions(t *testing.T) {
	mockDB := new(mockDatabase)
	probeDB := &s3ProbeDatabase{mockDatabase: mockDB}
	probeS3 := &s3ProbeStorage{rdb: probeDB}
	ctx := context.Background()

	worker := &CleanupWorker{
		rdb:                   probeDB,
		s3:                    probeS3,
		cache:                 new(mockCache),
		gracePeriod:           14 * 24 * time.Hour,
		healthStatusRetention: time.Hour,
	}

	candidates := []db.UserScopedObjectForCleanup{
		{AccountID: 1, ContentHash: "hashA", S3Domain: "example.com", S3Localpart: "user1"},
		{AccountID: 1, ContentHash: "hashB", S3Domain: "example.com", S3Localpart: "user1"},
		{AccountID: 2, ContentHash: "hashC", S3Domain: "example.com", S3Localpart: "user2"},
	}

	mockDB.On("AcquireCleanupLockWithRetry", ctx).Return(true, nil).Once()
	mockDB.On("ReleaseCleanupLockWithRetry", ctx).Return(nil).Once()
	mockDB.On("CleanupFailedUploadsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupSoftDeletedAccountsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("PurgeSoftDeletedMailboxesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldVacationResponsesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldRedirectsWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("CleanupOldHealthStatusesWithRetry", ctx, mock.Anything).Return(int64(0), nil).Once()
	mockDB.On("GetUserScopedObjectsForCleanupWithRetry", ctx, mock.Anything, mock.Anything).Return(candidates, nil).Once()
	mockDB.On("GetUnusedFTSHashesWithRetry", ctx, mock.Anything).Return([]string{}, nil).Once()
	mockDB.On("GetDanglingAccountsForFinalDeletionWithRetry", ctx, mock.Anything).Return([]int64{}, nil).Once()

	require.NoError(t, worker.runOnce(ctx))

	assert.ElementsMatch(t,
		[]string{"example.com/user1/hashA", "example.com/user1/hashB", "example.com/user2/hashC"},
		probeS3.deletedKeys, "every orphaned body must still be deleted from S3")
	assert.Equal(t, 0, probeS3.outsideLocks,
		"every S3 delete must happen while that object's advisory lock is held: deleting outside "+
			"the lock window races the uploader, which takes the same lock before a PUT, and can "+
			"remove a body a concurrent delivery is about to reference")
	assert.Equal(t, 1, probeS3.roundTrips,
		"the whole candidate batch must cost one S3 delete request, not one per object")
	assert.Len(t, probeDB.rowsDeleted, 3,
		"message rows must be removed once their S3 body is gone")
	mockDB.AssertExpectations(t)
}
