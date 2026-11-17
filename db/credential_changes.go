package db

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// CredentialChangeEvent is one visible credential_changes row at a statement snapshot.
type CredentialChangeEvent struct {
	ID        int64
	AccountID int64
	WriterXID int64
	Removed   bool
}

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
	Events     []CredentialChangeEvent
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
	rows, err := d.GetWritePool().Query(ctx, `
  WITH boundary AS MATERIALIZED (
   SELECT statement_timestamp() AS read_at,
          pg_snapshot_xmin(pg_current_snapshot())::text::bigint AS next_cursor
  )
  SELECT b.read_at,
         b.next_cursor,
         c.id,
         c.account_id,
         c.writer_xid,
         CASE WHEN c.ends_sessions THEN NOT EXISTS (
          SELECT 1 FROM accounts a WHERE a.id=c.account_id AND a.deleted_at IS NULL
         ) ELSE FALSE END
  FROM boundary b
  LEFT JOIN credential_changes c ON c.writer_xid >= $1
  ORDER BY c.id
 `, cursor)
	if err != nil {
		return CredentialChanges{}, fmt.Errorf("failed to read credential changes: %w", err)
	}
	defer rows.Close()

	c := CredentialChanges{
		Accounts: []int64{},
		Removed:  []int64{},
	}
	hasBoundary := false
	for rows.Next() {
		var (
			readAt     time.Time
			nextCursor int64
			id         *int64
			accountID  *int64
			writerXID  *int64
			removed    bool
		)
		if err := rows.Scan(&readAt, &nextCursor, &id, &accountID, &writerXID, &removed); err != nil {
			return CredentialChanges{}, fmt.Errorf("failed to read credential changes: %w", err)
		}
		if !hasBoundary {
			c.ReadAt = readAt
			c.NextCursor = nextCursor
			hasBoundary = true
		}
		if id != nil {
			ev := CredentialChangeEvent{
				ID:        *id,
				AccountID: *accountID,
				WriterXID: *writerXID,
				Removed:   removed,
			}
			c.Events = append(c.Events, ev)
			c.Accounts = append(c.Accounts, ev.AccountID)
			if ev.Removed {
				c.Removed = append(c.Removed, ev.AccountID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return CredentialChanges{}, fmt.Errorf("failed to read credential changes: %w", err)
	}
	if !hasBoundary {
		return CredentialChanges{}, fmt.Errorf("failed to read credential changes: empty snapshot boundary")
	}
	slices.Sort(c.Accounts)
	c.Accounts = slices.Compact(c.Accounts)
	slices.Sort(c.Removed)
	c.Removed = slices.Compact(c.Removed)
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
