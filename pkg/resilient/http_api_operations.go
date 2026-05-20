package resilient

import (
	"context"
	"time"

	"github.com/migadu/sora/db"
)

// --- HTTP API Wrappers ---

func (rd *ResilientDatabase) AccountExistsWithRetry(ctx context.Context, email string) (*db.AccountExistsResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).AccountExists(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*db.AccountExistsResult), nil
}

func (rd *ResilientDatabase) GetLatestCacheMetricsWithRetry(ctx context.Context) ([]*db.CacheMetricsRecord, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetLatestCacheMetrics(ctx)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetCacheMetrics(ctx, instanceID, since, limit)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetSystemHealthOverview(ctx, hostname)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAllHealthStatuses(ctx, hostname)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetHealthHistory(ctx, hostname, component, since, limit)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetHealthStatus(ctx, hostname, component)
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
		return rd.getOperationalDatabaseForOperation(ctx, false).GetUploaderStats(ctx, maxAttempts)
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

func (rd *ResilientDatabase) GetPendingUploadsByInstanceWithRetry(ctx context.Context) ([]db.InstanceUploadStats, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetPendingUploadsByInstance(ctx)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]db.InstanceUploadStats), nil
}

func (rd *ResilientDatabase) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts, limit int) ([]db.PendingUpload, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetFailedUploads(ctx, maxAttempts, limit)
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

func (rd *ResilientDatabase) GetFailedUploadsWithEmailWithRetry(ctx context.Context, maxAttempts, limit int) ([]db.PendingUploadWithEmail, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetFailedUploadsWithEmail(ctx, maxAttempts, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, apiRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.PendingUploadWithEmail{}, nil
	}
	return result.([]db.PendingUploadWithEmail), nil
}
