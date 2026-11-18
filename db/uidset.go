package db

import (
	"context"
	"fmt"

	"github.com/migadu/go-imap"
)

// resolveUIDSet freezes UID wildcards against the mailbox's highest live UID,
// independently of the session's sequence-number view. Static sets need no read.
func (db *Database) resolveUIDSet(ctx context.Context, mailboxID int64, set imap.UIDSet) (imap.UIDSet, error) {
	if !set.Dynamic() {
		return set, nil
	}
	var lastUID imap.UID
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COALESCE((
			SELECT uid FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
			ORDER BY uid DESC LIMIT 1
		), 0)
	`, mailboxID).Scan(&lastUID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UID wildcards: %w", err)
	}
	return resolveUIDSetWildcards(set, lastUID), nil
}

// resolveUIDSetWildcards replaces '*' (zero) with lastUID and normalizes the
// intervals without changing set. An empty mailbox has no wildcard endpoint.
func resolveUIDSetWildcards(set imap.UIDSet, lastUID imap.UID) imap.UIDSet {
	if !set.Dynamic() {
		return set
	}
	resolved := make(imap.UIDSet, 0, len(set))
	for _, r := range set {
		if r.Start == 0 || r.Stop == 0 {
			if lastUID == 0 {
				continue
			}
			if r.Start == 0 {
				r.Start = lastUID
			}
			if r.Stop == 0 {
				r.Stop = lastUID
			}
		}
		// Substitution can move a range before an earlier interval or make
		// ranges overlap. Contains requires a sorted, merged set.
		resolved.AddRange(r.Start, r.Stop)
	}
	return resolved
}
