package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/pkg/retry"
)

// --- Cleanup Worker Wrappers ---

// cleanupRetryConfig provides a default retry strategy for background cleanup tasks.
var cleanupRetryConfig = retry.BackoffConfig{
	InitialInterval: 1 * time.Second,
	MaxInterval:     30 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	var locked bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).AcquireCleanupLock(writeCtx, tx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		locked = result.(bool)
		return nil
	}, cleanupRetryConfig)
	return locked, err
}

func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabaseForOperation(true).ReleaseCleanupLock(writeCtx, tx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).ExpungeOldMessages(writeCtx, tx, maxAge)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}
