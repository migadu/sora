package resilient

import (
	"context"
	"time"

	"github.com/migadu/sora/db"
)

// --- HTTP API Wrappers ---

func (rd *ResilientDatabase) AccountExistsWithRetry(ctx context.Context, email string) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).AccountExists(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) GetLatestCacheMetricsWithRetry(ctx context.Context) ([]*db.CacheMetricsRecord, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetLatestCacheMetrics(ctx)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.CacheMetricsRecord{}, nil
	}
	return result.([]*db.CacheMetricsRecord), nil
}

func (rd *ResilientDatabase) GetCacheMetricsWithRetry(ctx context.Context, instanceID string, since time.Time, limit int) ([]*db.CacheMetricsRecord, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetCacheMetrics(ctx, instanceID, since, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.CacheMetricsRecord{}, nil
	}
	return result.([]*db.CacheMetricsRecord), nil
}

func (rd *ResilientDatabase) GetSystemHealthOverviewWithRetry(ctx context.Context, hostname string) (*db.SystemHealthOverview, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetSystemHealthOverview(ctx, hostname)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.SystemHealthOverview), nil
}

func (rd *ResilientDatabase) GetAllHealthStatusesWithRetry(ctx context.Context, hostname string) ([]*db.HealthStatus, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetAllHealthStatuses(ctx, hostname)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.HealthStatus{}, nil
	}
	return result.([]*db.HealthStatus), nil
}

func (rd *ResilientDatabase) GetHealthHistoryWithRetry(ctx context.Context, hostname, component string, since time.Time, limit int) ([]*db.HealthStatus, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetHealthHistory(ctx, hostname, component, since, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.HealthStatus{}, nil
	}
	return result.([]*db.HealthStatus), nil
}

func (rd *ResilientDatabase) GetHealthStatusWithRetry(ctx context.Context, hostname, component string) (*db.HealthStatus, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetHealthStatus(ctx, hostname, component)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.HealthStatus), nil
}

func (rd *ResilientDatabase) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUploaderStats(ctx, maxAttempts)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.UploaderStats), nil
}

func (rd *ResilientDatabase) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts, limit int) ([]db.PendingUpload, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetFailedUploads(ctx, maxAttempts, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.PendingUpload{}, nil
	}
	return result.([]db.PendingUpload), nil
}
