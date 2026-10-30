package db

// backend_maintenance.go - backend hosts taken out of rotation, and the upload backlog
// that decides when such a host may be stopped.
//
// An operator marks a host with `sora-admin backends maintenance on`; proxies poll
// ListBackendMaintenance and stop routing new sessions to it. The host keeps running
// until its node-local pending uploads are finished (a pending_upload is leased only by
// the instance that wrote it), which GetInstanceUploadBacklog reports.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BackendMaintenance is one host in maintenance. Host is normalized by the caller (lower
// case, no port); InstanceID is the uploader instance id whose backlog must drain before
// the host is stopped. CreatedAt is when maintenance began.
type BackendMaintenance struct {
	Host       string
	InstanceID string
	Reason     string
	CreatedBy  string
	CreatedAt  time.Time
}

// SetBackendMaintenance puts m.Host in maintenance, or updates the instance id, reason
// and author of a host already in it, and returns the stored row. CreatedAt is the
// database's, and a host already in maintenance keeps its original one: marking it again
// must not reset how long it has been draining.
//
// An empty instance id is refused: its backlog would always read as empty and report the
// host safe to stop while its real uploads were still on disk.
func (db *Database) SetBackendMaintenance(ctx context.Context, tx pgx.Tx, m BackendMaintenance) (BackendMaintenance, error) {
	if m.Host == "" {
		return BackendMaintenance{}, fmt.Errorf("backend maintenance needs a host")
	}
	if m.InstanceID == "" {
		return BackendMaintenance{}, fmt.Errorf("backend maintenance of %s needs an instance id", m.Host)
	}

	var stored BackendMaintenance
	err := tx.QueryRow(ctx, `
		INSERT INTO backend_maintenance (host, instance_id, reason, created_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (host) DO UPDATE
		SET instance_id = EXCLUDED.instance_id,
		    reason = EXCLUDED.reason,
		    created_by = EXCLUDED.created_by
		RETURNING host, instance_id, reason, created_by, created_at
	`, m.Host, m.InstanceID, m.Reason, m.CreatedBy).Scan(
		&stored.Host, &stored.InstanceID, &stored.Reason, &stored.CreatedBy, &stored.CreatedAt)
	if err != nil {
		return BackendMaintenance{}, fmt.Errorf("failed to set maintenance of backend %s: %w", m.Host, err)
	}
	return stored, nil
}

// ClearBackendMaintenance takes host out of maintenance and reports whether it was in it.
func (db *Database) ClearBackendMaintenance(ctx context.Context, tx pgx.Tx, host string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM backend_maintenance WHERE host = $1`, host)
	if err != nil {
		return false, fmt.Errorf("failed to clear maintenance of backend %s: %w", host, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListBackendMaintenance returns every host in maintenance, ordered by host.
//
// It reads the pool the context selects. Proxies poll it, and a lagging replica only
// delays when they notice a change by the lag; a caller showing an operator the result of
// their own change pins the primary (consts.UseMasterDBKey).
func (db *Database) ListBackendMaintenance(ctx context.Context) ([]BackendMaintenance, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT host, instance_id, reason, created_by, created_at
		FROM backend_maintenance
		ORDER BY host
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list backend maintenance: %w", err)
	}
	defer rows.Close()

	hosts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (BackendMaintenance, error) {
		var m BackendMaintenance
		err := row.Scan(&m.Host, &m.InstanceID, &m.Reason, &m.CreatedBy, &m.CreatedAt)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan backend maintenance: %w", err)
	}
	return hosts, nil
}

// InstanceUploadBacklog is what an instance still has to upload. Pending counts every
// pending upload it owns, Parked included: a parked upload (one the worker has given up
// retrying) is still mail whose only copy is on that node's disk. Oldest is the creation
// time of the oldest, nil when there are none.
type InstanceUploadBacklog struct {
	Pending int64
	Parked  int64
	Oldest  *time.Time
}

// GetInstanceUploadBacklog reports instanceID's pending uploads; those with at least
// maxAttempts attempts (the uploader's max_attempts) count as parked. The host behind the
// instance is safe to stop only once Pending is zero.
//
// It reads the pool the context selects. A lagging replica can miss an upload queued
// just now, so a caller deciding that a host is safe to stop pins the primary
// (consts.UseMasterDBKey). The (instance_id, created_at) index serves the lookup and the
// minimum.
func (db *Database) GetInstanceUploadBacklog(ctx context.Context, instanceID string, maxAttempts int) (InstanceUploadBacklog, error) {
	var backlog InstanceUploadBacklog
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE attempts >= $2),
		       min(created_at)
		FROM pending_uploads
		WHERE instance_id = $1
	`, instanceID, maxAttempts).Scan(&backlog.Pending, &backlog.Parked, &backlog.Oldest)
	if err != nil {
		return InstanceUploadBacklog{}, fmt.Errorf("failed to get upload backlog of instance %s: %w", instanceID, err)
	}
	return backlog, nil
}
