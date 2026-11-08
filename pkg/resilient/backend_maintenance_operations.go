package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
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

// GetInstanceDrainStateWithRetry reads an instance's pending uploads and latest sessions
// report (see db.GetInstanceDrainState).
func (rd *ResilientDatabase) GetInstanceDrainStateWithRetry(ctx context.Context, instanceID string, maxAttempts int) (db.InstanceDrainState, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetInstanceDrainState(ctx, instanceID, maxAttempts)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return db.InstanceDrainState{}, err
	}
	return result.(db.InstanceDrainState), nil
}

// ListUploaderInstancesWithRetry returns the instance ids seen since the given time (see
// db.ListUploaderInstances).
func (rd *ResilientDatabase) ListUploaderInstancesWithRetry(ctx context.Context, since time.Time) ([]db.UploaderInstance, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListUploaderInstances(ctx, since)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	instances, _ := result.([]db.UploaderInstance)
	return instances, nil
}

// sessionsReportRetryConfig is a single attempt: the node reports every few seconds, so
// the next report is the retry.
var sessionsReportRetryConfig = retry.BackoffConfig{
	InitialInterval: time.Second,
	MaxInterval:     time.Second,
	Multiplier:      1,
	MaxRetries:      0,
	OperationName:   "db_instance_sessions_report",
}

// ReportInstanceSessionsWithRetry stores a node's sessions report (see
// db.ReportInstanceSessions). One attempt only.
func (rd *ResilientDatabase) ReportInstanceSessionsWithRetry(ctx context.Context, s db.InstanceSessions) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).ReportInstanceSessions(ctx, tx, s)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, sessionsReportRetryConfig, timeoutWrite, op)
	return err
}

// GetMaintenanceRefusalWithRetry returns when the maintenance began that instanceID's node
// refuses new sessions for (see db.GetMaintenanceRefusal). Always read the primary: a
// lagging replica must not reopen the gate while the primary still holds a report of
// refusing with no sessions open. One attempt only: the node looks again at its next report.
func (rd *ResilientDatabase) GetMaintenanceRefusalWithRetry(ctx context.Context, instanceID string, refuseAfter time.Duration) (*time.Time, error) {
	masterCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).GetMaintenanceRefusal(ctx, instanceID, refuseAfter)
	}
	result, err := rd.executeReadWithRetry(masterCtx, sessionsReportRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	since, _ := result.(*time.Time)
	return since, nil
}
