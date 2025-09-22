package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- Cleanup Worker Wrappers ---

func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).AcquireCleanupLock(ctx, tx)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).ReleaseCleanupLock(ctx, tx)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).ExpungeOldMessages(ctx, tx, maxAge)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
