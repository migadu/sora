package db

// backend_maintenance.go - backend hosts taken out of rotation, and what decides when such
// a host may be stopped.
//
// An operator marks a host with `sora-admin backends maintenance on`; proxies poll
// ListBackendMaintenance and stop routing new sessions to it. The host keeps running
// until its node-local pending uploads are finished (a pending_upload is leased only by
// the instance that wrote it) and nothing on it can add another: the node reports those
// sessions itself (ReportInstanceSessions), and GetInstanceDrainState reads both.

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

// SessionsReportInterval is how often a node rewrites its instance_sessions row.
const SessionsReportInterval = 10 * time.Second

// InstanceSessions is what a node reports about the sessions it must let finish before it
// stops, because they can add uploads or lose work: IMAP and POP3 sessions that have
// authenticated, LMTP transactions, Admin API deliveries in flight. Started counts every
// such session since Since, so one that came and went between two reports still shows; a
// process that restarts reports a new Since and counts from zero.
type InstanceSessions struct {
	InstanceID string
	Open       int64
	Started    int64
	Since      time.Time
}

// ReportInstanceSessions stores s as its instance's latest report, stamped with the
// database clock.
func (db *Database) ReportInstanceSessions(ctx context.Context, tx pgx.Tx, s InstanceSessions) error {
	if s.InstanceID == "" {
		return fmt.Errorf("a sessions report needs an instance id")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO instance_sessions (instance_id, open_sessions, started_sessions, counting_since, reported_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (instance_id) DO UPDATE
		SET open_sessions = EXCLUDED.open_sessions,
		    started_sessions = EXCLUDED.started_sessions,
		    counting_since = EXCLUDED.counting_since,
		    reported_at = now()
	`, s.InstanceID, s.Open, s.Started, s.Since)
	if err != nil {
		return fmt.Errorf("failed to report sessions of instance %s: %w", s.InstanceID, err)
	}
	return nil
}

// InstanceDrainState is what decides whether the node behind an uploader instance may be
// stopped, read in one statement so that its parts describe the same moment.
type InstanceDrainState struct {
	// Pending counts every pending upload the instance owns, Parked included: a parked
	// upload (one the worker has given up retrying) is still mail whose only copy is on
	// that node's disk. Oldest is the creation time of the oldest, nil when there are none.
	Pending int64
	Parked  int64
	Oldest  *time.Time

	// Known reports whether anything was ever recorded under this instance id: a
	// heartbeat, a sessions report or a pending upload. Nothing can be pending under an id
	// no node uses (a typo, or the host's IP in place of its instance id), so for an
	// unknown id an empty queue proves nothing.
	Known bool

	// Sessions is the instance's latest sessions report, nil if it never sent one (a node
	// running a build that does not report). ReportedAt is when it was written and
	// ReportAge its age when this state was read, both by the database clock.
	Sessions   *InstanceSessions
	ReportedAt time.Time
	ReportAge  time.Duration
}

// GetInstanceDrainState reads instanceID's pending uploads (those with at least
// maxAttempts attempts, the uploader's max_attempts, count as parked) and its latest
// sessions report.
//
// It reads the pool the context selects. A lagging replica can miss an upload queued
// just now, so a caller deciding that a host is safe to stop pins the primary
// (consts.UseMasterDBKey). The (instance_id, created_at) index serves the backlog and its
// minimum; the rest are primary-key lookups.
func (db *Database) GetInstanceDrainState(ctx context.Context, instanceID string, maxAttempts int) (InstanceDrainState, error) {
	var (
		state      InstanceDrainState
		heartbeat  bool
		open       *int64
		started    *int64
		since      *time.Time
		reportedAt *time.Time
		dbNow      time.Time
	)
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT b.pending, b.parked, b.oldest,
		       EXISTS (SELECT 1 FROM instance_heartbeats WHERE instance_id = $1),
		       s.open_sessions, s.started_sessions, s.counting_since, s.reported_at,
		       now()
		FROM (
			SELECT count(*) AS pending,
			       count(*) FILTER (WHERE attempts >= $2) AS parked,
			       min(created_at) AS oldest
			FROM pending_uploads
			WHERE instance_id = $1
		) b
		LEFT JOIN instance_sessions s ON s.instance_id = $1
	`, instanceID, maxAttempts).Scan(&state.Pending, &state.Parked, &state.Oldest,
		&heartbeat, &open, &started, &since, &reportedAt, &dbNow)
	if err != nil {
		return InstanceDrainState{}, fmt.Errorf("failed to get drain state of instance %s: %w", instanceID, err)
	}

	if reportedAt != nil {
		state.Sessions = &InstanceSessions{InstanceID: instanceID, Open: *open, Started: *started, Since: *since}
		state.ReportedAt = *reportedAt
		state.ReportAge = dbNow.Sub(*reportedAt)
	}
	state.Known = heartbeat || state.Sessions != nil || state.Pending > 0
	return state, nil
}

// UploaderInstance is an uploader instance id something was recorded under, and when.
type UploaderInstance struct {
	InstanceID string
	LastSeen   time.Time
}

// ListUploaderInstances returns the instance ids that sent a heartbeat or a sessions
// report since the given time, most recent first: the ids an operator can choose from.
func (db *Database) ListUploaderInstances(ctx context.Context, since time.Time) ([]UploaderInstance, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT instance_id, max(seen)
		FROM (
			SELECT instance_id, last_seen AS seen FROM instance_heartbeats
			UNION ALL
			SELECT instance_id, reported_at FROM instance_sessions
		) i
		GROUP BY instance_id
		HAVING max(seen) >= $1
		ORDER BY max(seen) DESC, instance_id
	`, since)
	if err != nil {
		return nil, fmt.Errorf("failed to list uploader instances: %w", err)
	}
	defer rows.Close()

	instances, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (UploaderInstance, error) {
		var i UploaderInstance
		err := row.Scan(&i.InstanceID, &i.LastSeen)
		return i, err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan uploader instances: %w", err)
	}
	return instances, nil
}
