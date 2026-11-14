package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CredentialChanges is what credential_changes holds from a point in time on: the
// accounts whose logins changed (a new password, a removed credential, the account taken
// out of service), as triggers recorded them.
type CredentialChanges struct {
	// ReadAt is the database clock at the read. The next read starts from it, less a
	// window for transactions that were still open (see credchanges.Watcher).
	ReadAt time.Time
	// Accounts holds every account with a change: what a node cached of its logins is
	// stale.
	Accounts []int64
	// Removed holds those among them taken out of service (deleted, or marked for
	// purging) and not restored since: their sessions end as well.
	Removed []int64
}

// GetCredentialChangesSince returns the accounts whose logins changed at or after since,
// each once. It reads the pool the context selects; a lagging replica only delays a
// change to a later read, which goes back far enough to see it.
func (db *Database) GetCredentialChangesSince(ctx context.Context, since time.Time) (CredentialChanges, error) {
	var c CredentialChanges
	// An aggregate without GROUP BY returns its one row with no input, so the clock comes
	// back even when nothing changed.
	// A reader applies a change at every read for a while (see credchanges.Watcher), so
	// an account restored meanwhile must stop counting as removed, or its new sessions
	// would keep being ended.
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT now(),
		       COALESCE(array_agg(DISTINCT c.account_id), '{}'),
		       COALESCE(array_agg(DISTINCT c.account_id) FILTER (WHERE c.ends_sessions AND NOT EXISTS (
		           SELECT 1 FROM accounts a WHERE a.id = c.account_id AND a.deleted_at IS NULL)), '{}')
		FROM credential_changes c
		WHERE c.changed_at >= $1
	`, since).Scan(&c.ReadAt, &c.Accounts, &c.Removed)
	if err != nil {
		return CredentialChanges{}, fmt.Errorf("failed to read credential changes: %w", err)
	}
	return c, nil
}

// PruneCredentialChanges deletes the changes recorded before the given time and returns
// how many there were.
func (db *Database) PruneCredentialChanges(ctx context.Context, tx pgx.Tx, before time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM credential_changes WHERE changed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("failed to prune credential changes: %w", err)
	}
	return tag.RowsAffected(), nil
}
