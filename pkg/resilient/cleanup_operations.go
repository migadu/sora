package resilient

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// --- Cleanup Worker Wrappers ---

// ExecuteWithLockedS3Orphans holds the per-object advisory locks for objects and runs
// fn with the subset that is still orphaned. Deliberately not wrapped in a retry: fn
// performs the S3 deletion, which a database-level retry would replay.
func (rd *ResilientDatabase) ExecuteWithLockedS3Orphans(ctx context.Context, objects []db.UserScopedObjectForCleanup, gracePeriod time.Duration, fn func(ctx context.Context, orphans []db.UserScopedObjectForCleanup) error) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).ExecuteWithLockedS3Orphans(ctx, objects, gracePeriod, fn)
}

// AcquireCleanupLockWithRetry takes the cluster-wide cleanup lock for the duration of a
// cleanup cycle, or reports false when another node holds it.
//
// It is held in a db.AdvisoryLockTx until ReleaseCleanupLockWithRetry: transaction-
// scoped, in a dedicated transaction that stays open (and is kept alive) for the whole
// cycle. It was once a transaction-level lock taken inside a wrapper that committed
// immediately — released before the cycle even started, so every node ran the full
// cycle every wake (N× the candidate scans, lock_timeout noise from contending on the
// same mailbox rows, duplicated reaping work) — and then a session-level lock on a
// pooled connection, which a transaction-pooling proxy strands on a backend the unlock
// never reaches (see db.AdvisoryLockTx).
func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	rd.cleanupLockMu.Lock()
	defer rd.cleanupLockMu.Unlock()
	if rd.cleanupLock != nil {
		return false, fmt.Errorf("cleanup lock is already held by this process")
	}

	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	lock, err := rd.getOperationalDatabaseForOperation(ctx, true).BeginAdvisoryLockTx(lockCtx)
	if err != nil {
		return false, err
	}
	acquired, err := lock.TryLock(lockCtx, db.CLEANUP_ADVISORY_LOCK_ID)
	if err != nil {
		lock.Release()
		return false, fmt.Errorf("failed to try the cleanup advisory lock: %w", err)
	}
	if !acquired {
		lock.Release()
		return false, nil
	}
	rd.cleanupLock = lock
	return true, nil
}

// ReleaseCleanupLockWithRetry releases the cleanup lock taken by
// AcquireCleanupLockWithRetry and returns its connection to the pool. The release runs
// on a detached context, so it happens even when the cycle's context is gone.
func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	rd.cleanupLockMu.Lock()
	lock := rd.cleanupLock
	rd.cleanupLock = nil
	rd.cleanupLockMu.Unlock()
	if lock != nil {
		lock.Release()
	}
	return nil
}

func (rd *ResilientDatabase) GetStrandedUploadInstancesWithRetry(ctx context.Context, maxAttempts int, livenessThreshold time.Duration) ([]db.StrandedUploadInstance, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetStrandedUploadInstances(ctx, maxAttempts, livenessThreshold)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]db.StrandedUploadInstance), nil
}

func (rd *ResilientDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ExpungeOldMessages(ctx, tx, maxAge)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetMessagesForMailboxAndChildren(ctx context.Context, accountID int64, mailboxID int64, mailboxPath string) ([]db.Message, error) {
	return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesForMailboxAndChildren(ctx, accountID, mailboxID, mailboxPath)
}

func (rd *ResilientDatabase) PurgeMessagesByIDs(ctx context.Context, messageIDs []int64) (int64, error) {
	return rd.getOperationalDatabaseForOperation(ctx, true).PurgeMessagesByIDs(ctx, messageIDs)
}

func (rd *ResilientDatabase) GetMessagesForAccount(ctx context.Context, accountID int64) ([]db.Message, error) {
	return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) ExpungeAllMessagesForAccount(ctx context.Context, accountID int64) (int64, error) {
	return rd.getOperationalDatabaseForOperation(ctx, true).ExpungeAllMessagesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) GetUserScopedObjectsForAccount(ctx context.Context, accountID int64, gracePeriod time.Duration, limit int) ([]db.UserScopedObjectForCleanup, error) {
	return rd.getOperationalDatabaseForOperation(ctx, false).GetUserScopedObjectsForAccount(ctx, accountID, gracePeriod, limit)
}

func (rd *ResilientDatabase) GetAllUploadedObjectsForAccount(ctx context.Context, accountID int64, limit int) ([]db.UserScopedObjectForCleanup, error) {
	return rd.getOperationalDatabaseForOperation(ctx, false).GetAllUploadedObjectsForAccount(ctx, accountID, limit)
}

func (rd *ResilientDatabase) PurgeMailboxesForAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).PurgeMailboxesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) PurgeCredentialsForAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).PurgeCredentialsForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) PurgeAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).PurgeAccount(ctx, accountID)
}

// ExpungeMessagesByIDsWithRetry marks message rows expunged for the cleaner to reclaim.
func (rd *ResilientDatabase) ExpungeMessagesByIDsWithRetry(ctx context.Context, messageIDs []int64) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ExpungeMessagesByIDs(ctx, tx, messageIDs)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
