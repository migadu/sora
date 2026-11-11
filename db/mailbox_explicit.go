package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// GetMailboxByNameForRight resolves a named mailbox for an operation whose ACL
// right does not require lookup visibility (e.g. ESEARCH r or CREATE k). Preserve
// any normal namespace winner first; only when no such name exists consider
// hidden shared candidates with the required right, in direct/anyone and ID order.
// A fallback returns identity, owner, UIDVALIDITY and path only; callers must
// recheck authorization because a normal namespace winner may lack the right.
func (db *Database) GetMailboxByNameForRight(ctx context.Context, accountID int64, name string, right ACLRight) (*DBMailbox, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, name)
	if !errors.Is(err, consts.ErrMailboxNotFound) {
		return mailbox, err
	}
	domain, err := db.GetAccountDomain(ctx, accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, consts.ErrMailboxNotFound
	}
	if err != nil {
		return nil, err
	}
	var result DBMailbox
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT id, name, uid_validity, account_id, path
		FROM (
			SELECT m.id, m.name, m.uid_validity, m.account_id, m.path, 1 AS priority
			FROM mailboxes m JOIN mailbox_acls acl ON acl.mailbox_id = m.id
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND LOWER(m.name) = LOWER($2) AND acl.account_id = $1
			  AND position($4 IN acl.rights) > 0
			UNION ALL
			SELECT m.id, m.name, m.uid_validity, m.account_id, m.path, 2 AS priority
			FROM mailboxes m JOIN mailbox_acls acl ON acl.mailbox_id = m.id
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND LOWER(m.name) = LOWER($2) AND m.owner_domain = $3
			  AND acl.identifier = 'anyone' AND position($4 IN acl.rights) > 0
		) candidates
		ORDER BY priority, id LIMIT 1
	`, accountID, name, domain, string(right)).Scan(&result.ID, &result.Name, &result.UIDValidity, &result.AccountID, &result.Path)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, consts.ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve mailbox for explicit ACL right: %w", err)
	}
	return &result, nil
}

// GetSharedMailboxByNameForRight resolves name to a shared mailbox the account can
// act in: its own, else another owner's it can look up, else one it holds right on
// while 'l' hides it. Unlike GetMailboxByNameForRight, a personal mailbox of the
// account's under that name does not answer: it would hide the shared one, and is
// not what a mailbox created inside the shared namespace goes into. As there, the
// result carries identity, owner, UIDVALIDITY and path only, and callers must check
// the right themselves.
func (db *Database) GetSharedMailboxByNameForRight(ctx context.Context, accountID int64, name string, right ACLRight) (*DBMailbox, error) {
	domain, err := db.GetAccountDomain(ctx, accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, consts.ErrMailboxNotFound
	}
	if err != nil {
		return nil, err
	}
	var result DBMailbox
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT id, name, uid_validity, account_id, path
		FROM (
			SELECT m.id, m.name, m.uid_validity, m.account_id, m.path, 0 AS priority
			FROM mailboxes m
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND LOWER(m.name) = LOWER($2) AND m.account_id = $1
			UNION ALL
			SELECT m.id, m.name, m.uid_validity, m.account_id, m.path,
				CASE WHEN position('l' IN acl.rights) > 0 THEN 1 ELSE 3 END AS priority
			FROM mailboxes m JOIN mailbox_acls acl ON acl.mailbox_id = m.id
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND LOWER(m.name) = LOWER($2) AND m.account_id != $1 AND acl.account_id = $1
			  AND (position('l' IN acl.rights) > 0 OR position($4 IN acl.rights) > 0)
			UNION ALL
			SELECT m.id, m.name, m.uid_validity, m.account_id, m.path,
				CASE WHEN position('l' IN acl.rights) > 0 THEN 2 ELSE 4 END AS priority
			FROM mailboxes m JOIN mailbox_acls acl ON acl.mailbox_id = m.id
			WHERE m.is_shared = TRUE AND m.deleted_at IS NULL
			  AND LOWER(m.name) = LOWER($2) AND m.account_id != $1 AND m.owner_domain = $3
			  AND acl.identifier = 'anyone'
			  AND (position('l' IN acl.rights) > 0 OR position($4 IN acl.rights) > 0)
		) candidates
		ORDER BY priority, id LIMIT 1
	`, accountID, name, domain, string(right)).Scan(&result.ID, &result.Name, &result.UIDValidity, &result.AccountID, &result.Path)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, consts.ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve shared mailbox for explicit ACL right: %w", err)
	}
	return &result, nil
}
