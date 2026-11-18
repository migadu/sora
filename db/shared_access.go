package db

import (
	"context"
	"fmt"
)

// SetSharedMailboxAccess sets whether this database serves other owners' shared
// mailboxes, following [shared_mailboxes] enabled. With access off, every lookup a
// user makes (LIST, name and ID resolution, NOTIFY, the User API's message reads) sees
// only the user's own mailboxes, and every right check grants the owner alone: a grant
// to another user or to "anyone" counts for nothing. The owner keeps every mailbox,
// those created in the shared namespace included.
//
// The grants themselves stay. GetMailboxACLs and an administrative SetMailboxACL
// (grantor 0) work on them whatever this says, so an operator can still list, revoke
// or purge them; a user other than the owner can no longer change them. Access is on
// until this is called: sora-admin and tests that never call it keep the
// unrestricted view.
func (db *Database) SetSharedMailboxAccess(enabled bool) {
	db.sharedAccessOff.Store(!enabled)
}

// sharedAccess reports whether other owners' shared mailboxes are served. Queries
// pass it as a boolean parameter that gates every branch reaching another owner's
// mailbox through mailbox_acls.
func (db *Database) sharedAccess() bool {
	return !db.sharedAccessOff.Load()
}

// rightSQL is the SQL expression for account accountExpr holding right on mailbox
// mailboxExpr: has_mailbox_right, which with shared access off must also find the
// account the owner (who holds every right). All three arguments are SQL written by
// the caller, never user input, and each is used either way, so a statement's
// parameters do not depend on the setting.
func (db *Database) rightSQL(mailboxExpr, accountExpr, right string) string {
	check := fmt.Sprintf("has_mailbox_right(%s, %s, %s)", mailboxExpr, accountExpr, right)
	if db.sharedAccess() {
		return check
	}
	return fmt.Sprintf("(%s AND EXISTS (SELECT 1 FROM mailboxes owned WHERE owned.id = %s AND owned.account_id = %s))",
		check, mailboxExpr, accountExpr)
}

// HasForeignSharedGrants reports whether any live shared mailbox grants a right to
// someone other than its owner: another user, or "anyone". A node with
// [shared_mailboxes] enabled = false hides those mailboxes from their grantees, so
// start-up warns when this holds. It reads from mailbox_acls, which is empty where
// sharing was never used, rather than scanning mailboxes.
func (db *Database) HasForeignSharedGrants(ctx context.Context) (bool, error) {
	var exists bool
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM mailbox_acls a
			JOIN mailboxes m ON m.id = a.mailbox_id
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND (a.account_id IS NULL OR a.account_id != m.account_id)
		)`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check for shared mailbox grants: %w", err)
	}
	return exists, nil
}
