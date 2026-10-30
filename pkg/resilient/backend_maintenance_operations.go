package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// maintenancePollRetryConfig is a single attempt. Every proxy polls the maintenance list
// every few seconds, so the next poll is the retry; backing off inside one would only
// stack polls up behind a database that is already failing them.
var maintenancePollRetryConfig = retry.BackoffConfig{
	InitialInterval: time.Second,
	MaxInterval:     time.Second,
	Multiplier:      1,
	MaxRetries:      0,
	OperationName:   "db_backend_maintenance_poll",
}

// SetBackendMaintenanceWithRetry puts a host in maintenance, or updates the mark of one
// already in it, and returns the stored row (see db.SetBackendMaintenance).
func (rd *ResilientDatabase) SetBackendMaintenanceWithRetry(ctx context.Context, m db.BackendMaintenance) (db.BackendMaintenance, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).SetBackendMaintenance(ctx, tx, m)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return db.BackendMaintenance{}, err
	}
	return result.(db.BackendMaintenance), nil
}

// ClearBackendMaintenanceWithRetry takes a host out of maintenance and reports whether it
// was in it (see db.ClearBackendMaintenance).
func (rd *ResilientDatabase) ClearBackendMaintenanceWithRetry(ctx context.Context, host string) (bool, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ClearBackendMaintenance(ctx, tx, host)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// ListBackendMaintenanceWithRetry returns every host in maintenance (see
// db.ListBackendMaintenance). One attempt only: it is the proxies' poll, and the next
// poll is its retry.
func (rd *ResilientDatabase) ListBackendMaintenanceWithRetry(ctx context.Context) ([]db.BackendMaintenance, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListBackendMaintenance(ctx)
	}
	result, err := rd.executeReadWithRetry(ctx, maintenancePollRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	hosts, _ := result.([]db.BackendMaintenance)
	return hosts, nil
}

// GetInstanceUploadBacklogWithRetry reports an instance's pending and parked uploads
// (see db.GetInstanceUploadBacklog).
func (rd *ResilientDatabase) GetInstanceUploadBacklogWithRetry(ctx context.Context, instanceID string, maxAttempts int) (db.InstanceUploadBacklog, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetInstanceUploadBacklog(ctx, instanceID, maxAttempts)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return db.InstanceUploadBacklog{}, err
	}
	return result.(db.InstanceUploadBacklog), nil
}
