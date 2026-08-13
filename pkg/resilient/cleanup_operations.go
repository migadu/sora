package resilient

import (
	"context"
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

func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	// Transaction-scoped advisory lock - use executeWriteInTxWithRetry
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).AcquireCleanupLock(ctx, tx)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	// Transaction-scoped locks auto-release on commit/rollback - this is a no-op
	// Kept for API compatibility
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).ReleaseCleanupLock(ctx, tx)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
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
