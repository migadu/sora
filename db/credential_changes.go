package db

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"
)

// CredentialChanges is the visible primary feed at one statement snapshot.
type CredentialChanges struct {
	// ReadAt is the statement's start, a lower bound on its snapshot. It is used
	// only for retention recovery, never as an event-delivery cursor.
	ReadAt time.Time
	// NextCursor is the snapshot xmin: every lower transaction has committed or
	// rolled back. The next successfully applied read starts inclusively here.
	NextCursor int64
	Accounts   []int64
	Removed    []int64
}

// GetCredentialChangesSince reads ALL currently visible events whose writing
// transaction is at or above cursor, even when a lower transaction is still
// open. Event ids and timestamps do not order commits. An uncommitted writer
// cannot fall below the returned safe xmin, so it remains eligible when it
// commits. A caller advances its cursor only after every sink has succeeded.
func (d *Database) GetCredentialChangesSince(ctx context.Context, cursor int64) (CredentialChanges, error) {
	if cursor < 0 {
		return CredentialChanges{}, fmt.Errorf("invalid credential change cursor: %d", cursor)
	}
	var c CredentialChanges
	err := d.GetWritePool().QueryRow(ctx, `
  WITH boundary AS MATERIALIZED (
   SELECT statement_timestamp() AS read_at,
          pg_snapshot_xmin(pg_current_snapshot())::text::bigint AS next_cursor
  )
  SELECT b.read_at, b.next_cursor,
         COALESCE(array_agg(DISTINCT c.account_id ORDER BY c.account_id) FILTER (WHERE c.id IS NOT NULL), '{}'),
         COALESCE(array_agg(DISTINCT c.account_id ORDER BY c.account_id) FILTER (WHERE c.ends_sessions AND NOT EXISTS (
          SELECT 1 FROM accounts a WHERE a.id=c.account_id AND a.deleted_at IS NULL)), '{}')
  FROM boundary b
  LEFT JOIN credential_changes c ON c.writer_xid >= $1
  GROUP BY b.read_at,b.next_cursor
 `, cursor).Scan(&c.ReadAt, &c.NextCursor, &c.Accounts, &c.Removed)
	if err != nil {
		return CredentialChanges{}, fmt.Errorf("failed to read credential changes: %w", err)
	}
	return c, nil
}

// PruneCredentialChanges first observes only rows committed and visible to the
// primary, then deletes rows observed before the cutoff. An event's writer may
// have remained open arbitrarily long: changed_at never makes it pruneable.
func (d *Database) PruneCredentialChanges(ctx context.Context, tx pgx.Tx, before time.Time) (int64, error) {
	if _, err := tx.Exec(ctx, `UPDATE credential_changes SET first_observed_at=clock_timestamp() WHERE first_observed_at IS NULL`); err != nil {
		return 0, fmt.Errorf("failed to observe credential changes: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM credential_changes WHERE first_observed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("failed to prune credential changes: %w", err)
	}
	return tag.RowsAffected(), nil
}
