package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// --- Cleanup Worker Wrappers ---

func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).AcquireCleanupLock(ctx, tx)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).ReleaseCleanupLock(ctx, tx)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).ExpungeOldMessages(ctx, tx, maxAge)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetMessagesForMailboxAndChildren(ctx context.Context, accountID int64, mailboxID int64, mailboxPath string) ([]db.Message, error) {
	return rd.getOperationalDatabaseForOperation(false).GetMessagesForMailboxAndChildren(ctx, accountID, mailboxID, mailboxPath)
}

func (rd *ResilientDatabase) PurgeMessagesByIDs(ctx context.Context, messageIDs []int64) (int64, error) {
	return rd.getOperationalDatabaseForOperation(true).PurgeMessagesByIDs(ctx, messageIDs)
}

func (rd *ResilientDatabase) GetMessagesForAccount(ctx context.Context, accountID int64) ([]db.Message, error) {
	return rd.getOperationalDatabaseForOperation(false).GetMessagesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) ExpungeAllMessagesForAccount(ctx context.Context, accountID int64) (int64, error) {
	return rd.getOperationalDatabaseForOperation(true).ExpungeAllMessagesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) GetUserScopedObjectsForAccount(ctx context.Context, accountID int64, gracePeriod time.Duration, limit int) ([]db.UserScopedObjectForCleanup, error) {
	return rd.getOperationalDatabaseForOperation(false).GetUserScopedObjectsForAccount(ctx, accountID, gracePeriod, limit)
}

func (rd *ResilientDatabase) GetAllUploadedObjectsForAccount(ctx context.Context, accountID int64, limit int) ([]db.UserScopedObjectForCleanup, error) {
	return rd.getOperationalDatabaseForOperation(false).GetAllUploadedObjectsForAccount(ctx, accountID, limit)
}

func (rd *ResilientDatabase) PurgeMailboxesForAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(true).PurgeMailboxesForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) PurgeCredentialsForAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(true).PurgeCredentialsForAccount(ctx, accountID)
}

func (rd *ResilientDatabase) PurgeAccount(ctx context.Context, accountID int64) error {
	return rd.getOperationalDatabaseForOperation(true).PurgeAccount(ctx, accountID)
}
