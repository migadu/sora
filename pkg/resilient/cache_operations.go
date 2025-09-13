package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/pkg/retry"
)

// --- Cache Helper Wrappers ---

func (rd *ResilientDatabase) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	var existingHashes []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).FindExistingContentHashes(readCtx, hashes)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			existingHashes = result.([]string)
		} else {
			existingHashes = nil
		}
		return nil
	}, cleanupRetryConfig) // Use cleanup config as this is for background maintenance
	return existingHashes, err
}

func (rd *ResilientDatabase) GetRecentMessagesForWarmupWithRetry(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	var messages map[string][]string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetRecentMessagesForWarmup(readCtx, userID, mailboxNames, messageCount)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			messages = result.(map[string][]string)
		} else {
			messages = nil
		}
		return nil
	}, apiRetryConfig) // Use api config as this is for interactive performance
	return messages, err
}

// --- Cache Metrics Wrappers ---

func (rd *ResilientDatabase) StoreCacheMetricsWithRetry(ctx context.Context, instanceID, serverHostname string, hits, misses int64, uptimeSeconds int64) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).StoreCacheMetrics(writeCtx, tx, instanceID, serverHostname, hits, misses, uptimeSeconds)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return cbErr
	}, config)
}

func (rd *ResilientDatabase) CleanupOldCacheMetricsWithRetry(ctx context.Context, olderThan time.Duration) (int64, error) {
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
			return rd.getOperationalDatabaseForOperation(true).CleanupOldCacheMetrics(writeCtx, tx, olderThan)
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
