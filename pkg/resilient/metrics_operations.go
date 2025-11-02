package resilient

import (
	"context"

	"github.com/migadu/sora/pkg/metrics"
)

// GetMetricsStatsWithRetry retrieves aggregate metrics statistics with retry logic
func (rdb *ResilientDatabase) GetMetricsStatsWithRetry(ctx context.Context) (*metrics.MetricsStats, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		dbStats, err := rdb.getOperationalDatabaseForOperation(false).GetMetricsStats(ctx)
		if err != nil {
			return nil, err
		}
		// Convert db.MetricsStats to metrics.MetricsStats
		return &metrics.MetricsStats{
			TotalAccounts:  dbStats.TotalAccounts,
			TotalMailboxes: dbStats.TotalMailboxes,
			TotalMessages:  dbStats.TotalMessages,
		}, nil
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*metrics.MetricsStats), nil
}
