package db

// backend_maintenance.go - backend hosts taken out of rotation, and what decides when such
// a host may be stopped.
//
// An operator marks a host with `sora-admin backends maintenance on`; proxies poll
// ListBackendMaintenance and stop routing new sessions to it. The host keeps running
// until its node-local pending uploads are finished (a pending_upload is leased only by
// the instance that wrote it) and nothing on it can add another: the node itself refuses
// new sessions while in maintenance (GetMaintenanceRefusal) and reports those still open
// (ReportInstanceSessions), and GetInstanceDrainState reads both.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BackendMaintenance is one host in maintenance. Host is normalized by the caller (lower
// case, no port); InstanceID is the uploader instance id whose backlog must drain before
// the host is stopped. CreatedAt is when maintenance began.
//
// Addresses, read by ListBackendMaintenance only, are those the node behind InstanceID last
// reported for itself (ReportInstanceSessions) and no other node has, none if it never
// reported. Proxies match the host by them too: where they run, a Host that is a name may
// resolve to another of the node's addresses than the one they route to it by, or not
// resolve at all.
type BackendMaintenance struct {
	Host       string
	InstanceID string
	Reason     string
	CreatedBy  string
	CreatedAt  time.Time
	Addresses  []string
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

// ListBackendMaintenance returns every host in maintenance, ordered by host, with the
// addresses its node reports for itself. An address another node still reporting has as
// well (a container bridge every Docker host has) names neither node, and is left out. The
// sessions reports are one row per backend, so the check is a scan of a few rows.
//
// It reads the pool the context selects. Proxies poll it, and a lagging replica only
// delays when they notice a change by the lag; a caller showing an operator the result of
// their own change pins the primary (consts.UseMasterDBKey).
func (db *Database) ListBackendMaintenance(ctx context.Context) ([]BackendMaintenance, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT m.host, m.instance_id, m.reason, m.created_by, m.created_at,
		       ARRAY(
		           SELECT a FROM unnest(s.addresses) AS a
		           WHERE NOT EXISTS (
		               SELECT 1 FROM instance_sessions o
		               WHERE o.instance_id <> s.instance_id AND a = ANY (o.addresses)
		                 AND o.reported_at > now() - $1::interval)
		           ORDER BY a)
		FROM backend_maintenance m
		LEFT JOIN instance_sessions s ON s.instance_id = m.instance_id
		ORDER BY m.host
	`, SessionsReportMaxAge)
	if err != nil {
		return nil, fmt.Errorf("failed to list backend maintenance: %w", err)
	}
	defer rows.Close()

	hosts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (BackendMaintenance, error) {
		var m BackendMaintenance
		err := row.Scan(&m.Host, &m.InstanceID, &m.Reason, &m.CreatedBy, &m.CreatedAt, &m.Addresses)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan backend maintenance: %w", err)
	}
	return hosts, nil
}

// SessionsReportInterval is how often a node rewrites its instance_sessions row.
const SessionsReportInterval = 10 * time.Second

// SessionsReportMaxAge is how old a node's sessions report may be for the node to count as
// still reporting: a few missed reports. An older one comes from a node that stopped.
const SessionsReportMaxAge = 6 * SessionsReportInterval

// InstanceSessions is what a node reports about the sessions it must let finish before it
// stops, because they can add uploads or lose work: IMAP and POP3 sessions that have
// authenticated, LMTP transactions, Admin API deliveries in flight.
//
// RefusingSince is set while the node refuses new such sessions because it is in
// maintenance: the CreatedAt of the maintenance it refuses for (GetMaintenanceRefusal). The
// node refuses before it counts, so a report of refusing and none open stays true for as
// long as that maintenance lasts.
//
// Addresses are the node's own, for proxies to match it by while it is in maintenance
// (see BackendMaintenance).
type InstanceSessions struct {
	InstanceID    string
	Open          int64
	RefusingSince *time.Time
	Addresses     []string
}

// ReportInstanceSessions stores s as its instance's latest report, stamped with the
// database clock.
func (db *Database) ReportInstanceSessions(ctx context.Context, tx pgx.Tx, s InstanceSessions) error {
	if s.InstanceID == "" {
		return fmt.Errorf("a sessions report needs an instance id")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO instance_sessions (instance_id, open_sessions, refusing_since, addresses, reported_at)
		VALUES ($1, $2, $3, COALESCE($4::text[], '{}'), now())
		ON CONFLICT (instance_id) DO UPDATE
		SET open_sessions = EXCLUDED.open_sessions,
		    refusing_since = EXCLUDED.refusing_since,
		    addresses = EXCLUDED.addresses,
		    reported_at = now()
	`, s.InstanceID, s.Open, s.RefusingSince, s.Addresses)
	if err != nil {
		return fmt.Errorf("failed to report sessions of instance %s: %w", s.InstanceID, err)
	}
	return nil
}

// GetMaintenanceRefusal returns when the maintenance began that the node behind instanceID
// refuses new sessions for: the oldest of the instance's maintenance rows (one node can be
// in maintenance under several of its names) that has lasted refuseAfter, by the database
// clock. nil when there is none.
//
// It reads the pool the context selects. Callers controlling the admission gate must pin
// the primary (consts.UseMasterDBKey): a lagging replica can otherwise reopen the gate
// while the primary still holds a report of refusing with no sessions open.
func (db *Database) GetMaintenanceRefusal(ctx context.Context, instanceID string, refuseAfter time.Duration) (*time.Time, error) {
	var since *time.Time
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT min(created_at)
		FROM backend_maintenance
		WHERE instance_id = $1 AND created_at <= now() - $2::interval
	`, instanceID, refuseAfter).Scan(&since)
	if err != nil {
		return nil, fmt.Errorf("failed to look up maintenance of instance %s: %w", instanceID, err)
	}
	return since, nil
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

	// Refusing reports whether that report refuses new sessions for a maintenance of this
	// instance that is still on. A report refusing for an earlier one (maintenance turned
	// off and on again since, perhaps while the node restarted) does not count: the node
	// may have let sessions in between.
	Refusing bool
}

// GetInstanceDrainState reads instanceID's pending uploads (those with at least
// maxAttempts attempts, the uploader's max_attempts, count as parked) and its latest
// sessions report.
//
// It reads the pool the context selects. A lagging replica can miss an upload queued
// just now, so a caller deciding that a host is safe to stop pins the primary
// (consts.UseMasterDBKey). The (instance_id, created_at) index serves the backlog and its
// minimum; the rest are primary-key lookups and a scan of the few maintenance rows.
func (db *Database) GetInstanceDrainState(ctx context.Context, instanceID string, maxAttempts int) (InstanceDrainState, error) {
	var (
		state      InstanceDrainState
		heartbeat  bool
		open       *int64
		reportedAt *time.Time
		dbNow      time.Time
		refusing   *time.Time
		addresses  []string
	)
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT b.pending, b.parked, b.oldest,
		       EXISTS (SELECT 1 FROM instance_heartbeats WHERE instance_id = $1),
		       s.open_sessions, s.refusing_since, s.addresses, s.reported_at,
		       EXISTS (SELECT 1 FROM backend_maintenance bm
		               WHERE bm.instance_id = $1 AND bm.created_at = s.refusing_since),
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
		&heartbeat, &open, &refusing, &addresses, &reportedAt, &state.Refusing, &dbNow)
	if err != nil {
		return InstanceDrainState{}, fmt.Errorf("failed to get drain state of instance %s: %w", instanceID, err)
	}

	if reportedAt != nil {
		state.Sessions = &InstanceSessions{InstanceID: instanceID, Open: *open, RefusingSince: refusing, Addresses: addresses}
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
