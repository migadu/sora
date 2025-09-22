package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- Cache Helper Wrappers ---

func (rd *ResilientDatabase) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).FindExistingContentHashes(ctx, hashes)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]string), nil
}

func (rd *ResilientDatabase) GetRecentMessagesForWarmupWithRetry(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetRecentMessagesForWarmup(ctx, userID, mailboxNames, messageCount)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(map[string][]string), nil
}

// --- Cache Metrics Wrappers ---

func (rd *ResilientDatabase) StoreCacheMetricsWithRetry(ctx context.Context, instanceID, serverHostname string, hits, misses int64, uptimeSeconds int64) error {
	config := writeRetryConfig
	config.MaxRetries = 2 // Override for this specific, less critical write
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).StoreCacheMetrics(ctx, tx, instanceID, serverHostname, hits, misses, uptimeSeconds)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) CleanupOldCacheMetricsWithRetry(ctx context.Context, olderThan time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupOldCacheMetrics(ctx, tx, olderThan)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
