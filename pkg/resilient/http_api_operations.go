package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- HTTP API Wrappers ---

// apiRetryConfig provides a default retry strategy for HTTP API handlers.
var apiRetryConfig = retry.BackoffConfig{
	InitialInterval: 200 * time.Millisecond,
	MaxInterval:     2 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) AccountExistsWithRetry(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).AccountExists(readCtx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		exists = result.(bool)
		return nil
	}, apiRetryConfig)
	return exists, err
}

func (rd *ResilientDatabase) GetActiveConnectionsWithRetry(ctx context.Context) ([]db.ConnectionInfo, error) {
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetActiveConnections(readCtx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			connections = result.([]db.ConnectionInfo)
		}
		return nil
	}, apiRetryConfig)
	return connections, err
}

func (rd *ResilientDatabase) MarkConnectionsForTerminationWithRetry(ctx context.Context, criteria db.TerminationCriteria) (int64, error) {
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
			return rd.getOperationalDatabaseForOperation(true).MarkConnectionsForTermination(writeCtx, tx, criteria)
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
	}, apiRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetConnectionStatsWithRetry(ctx context.Context) (*db.ConnectionStats, error) {
	var stats *db.ConnectionStats
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetConnectionStats(readCtx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(*db.ConnectionStats)
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) GetUserConnectionsWithRetry(ctx context.Context, email string) ([]db.ConnectionInfo, error) {
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUserConnections(readCtx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			connections = result.([]db.ConnectionInfo)
		}
		return nil
	}, apiRetryConfig)
	return connections, err
}

func (rd *ResilientDatabase) GetLatestCacheMetricsWithRetry(ctx context.Context) ([]*db.CacheMetricsRecord, error) {
	var metrics []*db.CacheMetricsRecord
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetLatestCacheMetrics(readCtx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			metrics = result.([]*db.CacheMetricsRecord)
		}
		return nil
	}, apiRetryConfig)
	return metrics, err
}

func (rd *ResilientDatabase) GetCacheMetricsWithRetry(ctx context.Context, instanceID string, since time.Time, limit int) ([]*db.CacheMetricsRecord, error) {
	var metrics []*db.CacheMetricsRecord
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetCacheMetrics(readCtx, instanceID, since, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			metrics = result.([]*db.CacheMetricsRecord)
		}
		return nil
	}, apiRetryConfig)
	return metrics, err
}

func (rd *ResilientDatabase) GetSystemHealthOverviewWithRetry(ctx context.Context, hostname string) (*db.SystemHealthOverview, error) {
	var overview *db.SystemHealthOverview
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetSystemHealthOverview(readCtx, hostname)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			overview = result.(*db.SystemHealthOverview)
		}
		return nil
	}, apiRetryConfig)
	return overview, err
}

func (rd *ResilientDatabase) GetAllHealthStatusesWithRetry(ctx context.Context, hostname string) ([]*db.HealthStatus, error) {
	var statuses []*db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetAllHealthStatuses(readCtx, hostname)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			statuses = result.([]*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return statuses, err
}

func (rd *ResilientDatabase) GetHealthHistoryWithRetry(ctx context.Context, hostname, component string, since time.Time, limit int) ([]*db.HealthStatus, error) {
	var history []*db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetHealthHistory(readCtx, hostname, component, since, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			history = result.([]*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return history, err
}

func (rd *ResilientDatabase) GetHealthStatusWithRetry(ctx context.Context, hostname, component string) (*db.HealthStatus, error) {
	var status *db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetHealthStatus(readCtx, hostname, component)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			status = result.(*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return status, err
}

func (rd *ResilientDatabase) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	var stats *db.UploaderStats
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUploaderStats(readCtx, maxAttempts)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(*db.UploaderStats)
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts, limit int) ([]db.PendingUpload, error) {
	var uploads []db.PendingUpload
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetFailedUploads(readCtx, maxAttempts, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			uploads = result.([]db.PendingUpload)
		}
		return nil
	}, apiRetryConfig)
	return uploads, err
}

func (rd *ResilientDatabase) GetAuthAttemptsStatsWithRetry(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error) {
	var stats map[string]interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetAuthAttemptsStats(readCtx, windowDuration)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(map[string]interface{})
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) CleanupStaleConnectionsWithRetry(ctx context.Context, staleDuration time.Duration) (int64, error) {
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
			return rd.getOperationalDatabaseForOperation(true).CleanupStaleConnections(writeCtx, tx, staleDuration)
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
	}, adminRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetBlockedIPsWithRetry(ctx context.Context, ipWindow, usernameWindow time.Duration, maxAttemptsIP, maxAttemptsUsername int) ([]map[string]interface{}, error) {
	var blocked []map[string]interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetBlockedIPs(readCtx, ipWindow, usernameWindow, maxAttemptsIP, maxAttemptsUsername)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			blocked = result.([]map[string]interface{})
		} else {
			blocked = nil
		}
		return nil
	}, adminRetryConfig)
	return blocked, err
}
