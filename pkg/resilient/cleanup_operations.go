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
func (rd *ResilientDatabase) ExecuteWithLockedS3Orphans(ctx context.Context, objects []db.UserScopedObjectForCleanup, gracePeriod time.Duration, fn func(orphans []db.UserScopedObjectForCleanup) error) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).ExecuteWithLockedS3Orphans(ctx, objects, gracePeriod, fn)
}

// AcquireCleanupLockWithRetry takes the cluster-wide cleanup lock for the duration of a
// cleanup cycle, or reports false when another node holds it.
//
// It is a SESSION-level advisory lock on a dedicated connection, held until
// ReleaseCleanupLockWithRetry. It was once a transaction-level lock taken inside a
// wrapper that committed immediately — released before the cycle even started, so every
// node ran the full cycle every wake (N× the candidate scans, lock_timeout noise from
// contending on the same mailbox rows, duplicated reaping work). The dedicated connection
// is the same pattern the per-object S3 lock uses (ExecuteWithS3ObjectSessionLock).
func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	rd.cleanupLockMu.Lock()
	defer rd.cleanupLockMu.Unlock()
	if rd.cleanupLockConn != nil {
		return false, fmt.Errorf("cleanup lock is already held by this process")
	}

	pool := rd.getOperationalDatabaseForOperation(ctx, true).GetWritePool()
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pool.Acquire(lockCtx)
	if err != nil {
		return false, err
	}
	var acquired bool
	if err := conn.QueryRow(lockCtx, "SELECT pg_try_advisory_lock($1)", db.CLEANUP_ADVISORY_LOCK_ID).Scan(&acquired); err != nil {
		conn.Release()
		return false, fmt.Errorf("failed to try the cleanup advisory lock: %w", err)
	}
	if !acquired {
		conn.Release()
		return false, nil
	}
	rd.cleanupLockConn = conn
	return true, nil
}

// ReleaseCleanupLockWithRetry releases the cleanup lock taken by
// AcquireCleanupLockWithRetry and returns its connection to the pool. It uses a
// detached context so the unlock happens even when the cycle's context is gone.
func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	rd.cleanupLockMu.Lock()
	conn := rd.cleanupLockConn
	rd.cleanupLockConn = nil
	rd.cleanupLockMu.Unlock()
	if conn == nil {
		return nil
	}
	defer conn.Release()
	_, err := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", db.CLEANUP_ADVISORY_LOCK_ID)
	return err
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
