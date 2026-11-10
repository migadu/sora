package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// ACLEntry represents a mailbox ACL entry
type ACLEntry struct {
	MailboxID  int64
	AccountID  *int64 // NULL for "anyone" identifier
	Identifier string // Email address or "anyone"
	Rights     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ACLRight represents individual IMAP ACL rights (RFC 4314)
type ACLRight rune

const (
	ACLRightLookup    ACLRight = 'l' // Mailbox is visible to LIST/LSUB
	ACLRightRead      ACLRight = 'r' // SELECT mailbox, FETCH, SEARCH
	ACLRightSeen      ACLRight = 's' // Keep seen/unseen status
	ACLRightWrite     ACLRight = 'w' // Set/clear flags except \Seen and \Deleted
	ACLRightInsert    ACLRight = 'i' // APPEND, COPY into mailbox
	ACLRightPost      ACLRight = 'p' // Send mail to submission address (LMTP)
	ACLRightCreate    ACLRight = 'k' // CREATE child mailboxes
	ACLRightDelete    ACLRight = 'x' // DELETE mailbox
	ACLRightDeleteMsg ACLRight = 't' // Set/clear \Deleted flag
	ACLRightExpunge   ACLRight = 'e' // EXPUNGE messages
	ACLRightAdmin     ACLRight = 'a' // Administer (SETACL/DELETEACL)
)

// AllACLRights contains all valid ACL rights
const AllACLRights = "lrswipkxtea"

// Special ACL identifiers (RFC 4314)
const (
	// AnyoneIdentifier grants rights to all users in the same domain
	// RFC 4314: "anyone" refers to the universal identity (all authenticted users)
	// We scope this to same-domain for security
	AnyoneIdentifier = "anyone"
)

// Refusals from SetMailboxACL: changes that can never succeed, as opposed to a
// failure to carry one out, so callers can tell the client which.
var (
	// ErrMailboxNotShared: only mailboxes in the shared namespace carry grants.
	ErrMailboxNotShared = errors.New("mailbox is not shared")
	// ErrCrossDomainGrant: a shared mailbox is shared only within its owner's domain.
	ErrCrossDomainGrant = errors.New("cannot grant access to user from different domain")
	// ErrOwnerACL: the owner holds every right whatever the ACL says
	// (has_mailbox_right), so the owner's rights cannot be changed.
	ErrOwnerACL = errors.New("the mailbox owner always holds every right")
)

// ErrInvalidACLRight is returned by ValidateACLRights for a character that is not
// one of AllACLRights.
var ErrInvalidACLRight = errors.New("invalid ACL right")

// ACLModification is how SetMailboxACL changes an identifier's rights (RFC 4314 §3.1).
type ACLModification byte

const (
	ACLReplace ACLModification = 0   // the rights replace any the identifier holds
	ACLAdd     ACLModification = '+' // the rights are added to them
	ACLRemove  ACLModification = '-' // the rights are removed from them
)

// unionRights returns the set union of two ACL rights strings, preserving the
// order of first appearance and removing duplicates.
func unionRights(a, b string) string {
	var sb strings.Builder
	seen := make(map[rune]bool, len(a)+len(b))
	for _, r := range a + b {
		if !seen[r] {
			seen[r] = true
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// ValidateACLRights checks if a rights string contains only valid ACL rights
func ValidateACLRights(rights string) error {
	for _, r := range rights {
		if !strings.ContainsRune(AllACLRights, r) {
			return fmt.Errorf("%w: %c", ErrInvalidACLRight, r)
		}
	}
	return nil
}

// IsSpecialIdentifier checks if an identifier is a special ACL identifier
func IsSpecialIdentifier(identifier string) bool {
	return identifier == AnyoneIdentifier
}

// canonicalRights returns the rights in rights in AllACLRights order, each once.
func canonicalRights(rights string) string {
	var sb strings.Builder
	for _, r := range AllACLRights {
		if strings.ContainsRune(rights, r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// aclQuerier is a pgx.Tx or a pool.
type aclQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// aclMailbox is what deciding an ACL change needs to know about the mailbox.
type aclMailbox struct {
	ownerAccountID int64
	isShared       bool
	ownerDomain    string // empty if unknown; only a grant needs it
}

func getACLMailbox(ctx context.Context, q aclQuerier, mailboxID int64, lock string) (aclMailbox, error) {
	var mb aclMailbox
	err := q.QueryRow(ctx, `
		SELECT account_id, COALESCE(is_shared, FALSE), COALESCE(owner_domain, '')
		FROM mailboxes
		WHERE id = $1 AND deleted_at IS NULL
	`+lock, mailboxID).Scan(&mb.ownerAccountID, &mb.isShared, &mb.ownerDomain)
	if errors.Is(err, pgx.ErrNoRows) {
		return mb, fmt.Errorf("%w: %d", consts.ErrMailboxNotFound, mailboxID)
	}
	if err != nil {
		return mb, fmt.Errorf("failed to get mailbox: %w", err)
	}
	return mb, nil
}

// beginACLWrite starts the transaction of an ACL write on mailboxID. The advisory lock
// serialises every ACL write on the mailbox, so a right checked inside the
// transaction cannot be revoked before the write commits. FOR KEY SHARE holds the
// mailbox against the FOR UPDATE that rename and delete take, without waiting for
// deliveries, which only update it.
func (db *Database) beginACLWrite(ctx context.Context, mailboxID int64) (pgx.Tx, aclMailbox, error) {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return nil, aclMailbox{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::int4, hashint8($2::int8))", consts.SoraMailboxACLLockClassID, mailboxID); err != nil {
		tx.Rollback(context.Background())
		return nil, aclMailbox{}, fmt.Errorf("failed to lock mailbox ACL: %w", err)
	}
	mb, err := getACLMailbox(ctx, tx, mailboxID, " FOR KEY SHARE")
	if err != nil {
		tx.Rollback(context.Background())
		return nil, aclMailbox{}, err
	}
	return tx, mb, nil
}

// outsideOwnerDomain reports whether an address is outside a shared mailbox's owner
// domain. It is decided from the text alone, before any lookup, so a refusal on
// these grounds never tells whether the address exists.
func outsideOwnerDomain(mb aclMailbox, identifier string) bool {
	at := strings.LastIndexByte(identifier, '@')
	return mb.isShared && mb.ownerDomain != "" && at >= 0 && !strings.EqualFold(identifier[at+1:], mb.ownerDomain)
}

// resolveGrantee returns who identifier names as a grantee on a shared mailbox:
// "anyone", or an active account in the owner's domain, stored under its primary
// address (RFC 4314 §3.4 lets "multiple forms of an identifier" name one account).
// The domain is compared before the address is looked up, so the answer never tells
// whether an address exists outside the owner's domain.
func resolveGrantee(ctx context.Context, q aclQuerier, mb aclMailbox, identifier string) (accountID *int64, canonical string, err error) {
	// has_mailbox_right applies "anyone" only within the owner domain, so without one
	// no grant would take effect.
	if mb.ownerDomain == "" {
		return nil, "", fmt.Errorf("shared mailbox has no owner domain")
	}
	if identifier == AnyoneIdentifier {
		return nil, AnyoneIdentifier, nil
	}
	at := strings.LastIndexByte(identifier, '@')
	if at < 0 {
		return nil, "", fmt.Errorf("%w: user %s not found", consts.ErrUserNotFound, identifier)
	}
	if outsideOwnerDomain(mb, identifier) {
		return nil, "", fmt.Errorf("%w (owner: %s, grantee: %s)", ErrCrossDomainGrant, mb.ownerDomain, identifier[at+1:])
	}
	var id int64
	var primary, primaryDomain string
	err = q.QueryRow(ctx, `
		SELECT c.account_id, p.address, p.domain
		FROM credentials c
		JOIN accounts a ON a.id = c.account_id AND a.deleted_at IS NULL
		JOIN credentials p ON p.account_id = c.account_id AND p.primary_identity = TRUE
		WHERE LOWER(c.address) = LOWER($1)
	`, identifier).Scan(&id, &primary, &primaryDomain)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("%w: user %s not found", consts.ErrUserNotFound, identifier)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to get grantee info: %w", err)
	}
	if !strings.EqualFold(primaryDomain, mb.ownerDomain) {
		return nil, "", fmt.Errorf("%w (owner: %s, grantee: %s)", ErrCrossDomainGrant, mb.ownerDomain, primaryDomain)
	}
	if id == mb.ownerAccountID {
		return nil, "", ErrOwnerACL
	}
	return &id, primary, nil
}

// aclTarget is the entry an identifier names on a mailbox.
type aclTarget struct {
	ids       []int64 // its rows; more than one only in data from before one row per account
	rights    string  // the rights every one of those rows grants
	accountID *int64  // the account the identifier is an address of, if any
}

// aclTargetFor finds the entry identifier names on mailboxID: "anyone" (exactly), or
// every row of the account the identifier is an address of (in any case, an alias, a
// deleted account too), or, when it is no account's address, rows stored under that
// text. Duplicate rows of one account, left from before one row per account, are
// enforced by whichever has_mailbox_right reads first, so a change starts from the
// rights all of them grant: it can then never add a right the owner did not ask for.
func aclTargetFor(ctx context.Context, tx pgx.Tx, mailboxID int64, identifier string) (aclTarget, error) {
	var target aclTarget
	query, args := `SELECT id, rights FROM mailbox_acls WHERE mailbox_id = $1 AND identifier = 'anyone'`, []any{mailboxID}
	if identifier != AnyoneIdentifier {
		var id int64
		err := tx.QueryRow(ctx, `SELECT account_id FROM credentials WHERE LOWER(address) = LOWER($1)`, identifier).Scan(&id)
		switch {
		case err == nil:
			target.accountID = &id
			query, args = `SELECT id, rights FROM mailbox_acls WHERE mailbox_id = $1 AND account_id = $2`, append(args, id)
		case errors.Is(err, pgx.ErrNoRows):
			query = `SELECT id, rights FROM mailbox_acls WHERE mailbox_id = $1 AND LOWER(identifier) = LOWER($2) AND identifier <> 'anyone'`
			args = append(args, identifier)
		default:
			return target, fmt.Errorf("failed to resolve identifier: %w", err)
		}
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return target, fmt.Errorf("failed to read ACL entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var r string
		if err := rows.Scan(&id, &r); err != nil {
			return target, fmt.Errorf("failed to scan ACL entry: %w", err)
		}
		if len(target.ids) == 0 {
			target.rights = canonicalRights(r)
		} else {
			target.rights = intersectRights(target.rights, r)
		}
		target.ids = append(target.ids, id)
	}
	if err := rows.Err(); err != nil {
		return target, fmt.Errorf("failed to read ACL entries: %w", err)
	}
	return target, nil
}

// intersectRights returns the rights of a that b also holds.
func intersectRights(a, b string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(b, r) {
			return r
		}
		return -1
	}, a)
}

func deleteACLRows(ctx context.Context, tx pgx.Tx, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, "DELETE FROM mailbox_acls WHERE id = ANY($1)", ids); err != nil {
		return fmt.Errorf("failed to revoke access: %w", err)
	}
	return nil
}

// SetMailboxACL applies one SETACL to mailboxID: rights replace, are added to, or are
// removed from those identifier holds, and DELETEACL is a replace with no rights.
// The identifier's entry is the account's whatever spelling or alias names it.
//
// Taking rights away always succeeds, also from a grantee that could no longer be
// granted them (deleted, moved to another domain), and removing what is not there
// leaves the ACL as asked (RFC 4314 §3.2). Only a change that gives rights is checked
// as a grant: the mailbox must be shared and the grantee an active account in the
// owner's domain other than the owner, checked in an order that reveals nothing about
// addresses outside that domain.
//
// grantorAccountID is the account the caller authorised to administer the mailbox,
// or 0 for a trusted caller (the Admin API, sora-admin). Its 'a' right is checked
// again under the ACL lock, so an administrator revoked meanwhile, or before the
// command on a lagging replica, is refused with consts.ErrNotPermitted. Taking rights
// from their own entry is exempt, so an administrator can drop their own 'a' and a
// retry of that does not fail.
func (db *Database) SetMailboxACL(ctx context.Context, mailboxID, grantorAccountID int64, identifier string, mod ACLModification, rights string) error {
	if err := ValidateACLRights(rights); err != nil {
		return err
	}
	tx, mb, err := db.beginACLWrite(ctx, mailboxID)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	target, err := aclTargetFor(ctx, tx, mailboxID, identifier)
	if err != nil {
		return err
	}
	var final string
	switch mod {
	case ACLAdd:
		final = canonicalRights(target.rights + rights)
	case ACLRemove:
		final = strings.Map(func(r rune) rune {
			if strings.ContainsRune(rights, r) {
				return -1
			}
			return r
		}, target.rights)
	default:
		final = canonicalRights(rights)
	}
	// An address outside the owner's domain is answered as any such address: never
	// as the owner, and only "-" and DELETEACL act on an entry it names, so no answer
	// tells whether it is one of the owner's or names an entry at all.
	outside := outsideOwnerDomain(mb, identifier)
	isOwner := !outside && target.accountID != nil && *target.accountID == mb.ownerAccountID
	reduction := len(target.ids) > 0 && !isOwner && intersectRights(final, target.rights) == final &&
		(mod == ACLRemove || !outside)
	ownEntry := target.accountID != nil && *target.accountID == grantorAccountID
	if grantorAccountID != 0 && grantorAccountID != mb.ownerAccountID && !(ownEntry && (final == "" || reduction)) {
		var allowed bool
		if err := tx.QueryRow(ctx, "SELECT has_mailbox_right($1, $2, 'a')", mailboxID, grantorAccountID).Scan(&allowed); err != nil {
			return fmt.Errorf("failed to check admin permission: %w", err)
		}
		if !allowed {
			return fmt.Errorf("%w: no admin right on mailbox %d", consts.ErrNotPermitted, mailboxID)
		}
	}

	switch {
	case final == "":
		err = deleteACLRows(ctx, tx, target.ids)
	case reduction:
		// Only taking rights away: one row keeps what is left.
		if err = deleteACLRows(ctx, tx, target.ids[1:]); err == nil {
			_, err = tx.Exec(ctx, `UPDATE mailbox_acls SET rights = $2, updated_at = now() WHERE id = $1`, target.ids[0], final)
		}
	default:
		err = grantInTx(ctx, tx, mb, mailboxID, identifier, target, final)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// grantInTx stores final as identifier's rights on mailboxID, replacing target's rows.
func grantInTx(ctx context.Context, tx pgx.Tx, mb aclMailbox, mailboxID int64, identifier string, target aclTarget, final string) error {
	if !mb.isShared {
		return ErrMailboxNotShared
	}
	accountID, canonical, err := resolveGrantee(ctx, tx, mb, identifier)
	if err != nil {
		return err
	}
	// One row per account: rows under other spellings go.
	if err := deleteACLRows(ctx, tx, target.ids); err != nil {
		return err
	}
	// A row can still be labelled with an address its account has since lost, one
	// that now names this grantee. Relabel it rather than let this grant take it
	// over: with its account's primary address, or, if a row of that account already
	// has that label, one made unique by the row's id. GetMailboxACLs shows rows
	// under the primary address, so the label is never seen.
	if _, err := tx.Exec(ctx, `
		UPDATE mailbox_acls a SET updated_at = now(), identifier = CASE
			WHEN EXISTS (SELECT 1 FROM mailbox_acls b WHERE b.mailbox_id = $1 AND b.identifier = p.address)
			THEN a.identifier || '#' || a.id ELSE p.address END
		FROM credentials p
		WHERE a.mailbox_id = $1 AND a.identifier = $2 AND a.account_id IS DISTINCT FROM $3
		  AND p.account_id = a.account_id AND p.primary_identity = TRUE
	`, mailboxID, canonical, accountID); err != nil {
		return fmt.Errorf("failed to relabel ACL entry: %w", err)
	}
	var stored int64
	err = tx.QueryRow(ctx, `
		INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (mailbox_id, identifier) DO UPDATE SET rights = EXCLUDED.rights, updated_at = now()
		WHERE mailbox_acls.account_id IS NOT DISTINCT FROM EXCLUDED.account_id
		RETURNING id
	`, mailboxID, accountID, canonical, final).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("ACL entry %q on mailbox %d belongs to another account", canonical, mailboxID)
	}
	if err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}
	return nil
}

// GrantMailboxAccessByIdentifier gives identifier (an address or "anyone") rights on
// the mailbox the owner has under mailboxName. See SetMailboxACL.
func (db *Database) GrantMailboxAccessByIdentifier(ctx context.Context, ownerAccountID int64, identifier string, mailboxName string, rights string) error {
	if err := ValidateACLRights(rights); err != nil {
		return err
	}
	if canonicalRights(rights) == "" {
		return fmt.Errorf("%w: no rights given", ErrInvalidACLRight)
	}
	var mailboxID int64
	err := db.GetWritePool().QueryRow(ctx, `
		SELECT id FROM mailboxes
		WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
	`, ownerAccountID, mailboxName).Scan(&mailboxID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", consts.ErrMailboxNotFound, mailboxName)
		}
		return fmt.Errorf("failed to get mailbox: %w", err)
	}
	return db.SetMailboxACL(ctx, mailboxID, 0, identifier, ACLReplace, rights)
}

// RevokeMailboxAccessByIdentifier removes the entry identifier names on mailboxID
// (see SetMailboxACL), returning consts.ErrDBNotFound when there is none, so a
// caller such as sora-admin can say so.
func (db *Database) RevokeMailboxAccessByIdentifier(ctx context.Context, mailboxID int64, identifier string) error {
	tx, _, err := db.beginACLWrite(ctx, mailboxID)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	target, err := aclTargetFor(ctx, tx, mailboxID, identifier)
	if err != nil {
		return err
	}
	if len(target.ids) == 0 {
		return fmt.Errorf("%w: ACL entry not found for identifier %s", consts.ErrDBNotFound, identifier)
	}
	if err := deleteACLRows(ctx, tx, target.ids); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ACLGrantability is what LISTRIGHTS may offer an identifier on a mailbox.
type ACLGrantability int

const (
	ACLGrantNone  ACLGrantability = iota // nothing can be granted
	ACLGrantAny                          // every right can be granted, each on its own
	ACLGrantOwner                        // the owner, who always holds every right
)

// MailboxACLGrantability tells LISTRIGHTS what SetMailboxACL would let identifier be
// given on mailboxID, by the same checks in the same order, so the two agree and
// LISTRIGHTS reveals no more about which addresses exist than SETACL does:
// consts.ErrUserNotFound only for an address in the owner's domain.
func (db *Database) MailboxACLGrantability(ctx context.Context, mailboxID int64, identifier string) (ACLGrantability, error) {
	pool := db.GetReadPoolWithContext(ctx)
	mb, err := getACLMailbox(ctx, pool, mailboxID, "")
	if err != nil {
		return ACLGrantNone, err
	}
	if identifier == AnyoneIdentifier {
		if mb.isShared && mb.ownerDomain != "" {
			return ACLGrantAny, nil
		}
		return ACLGrantNone, nil
	}
	if outsideOwnerDomain(mb, identifier) {
		return ACLGrantNone, nil
	}
	var isOwner bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM credentials WHERE account_id = $1 AND LOWER(address) = LOWER($2))
	`, mb.ownerAccountID, identifier).Scan(&isOwner); err != nil {
		return ACLGrantNone, fmt.Errorf("failed to check mailbox owner: %w", err)
	}
	if isOwner {
		return ACLGrantOwner, nil
	}
	if !mb.isShared || mb.ownerDomain == "" {
		return ACLGrantNone, nil
	}
	switch _, _, err := resolveGrantee(ctx, pool, mb, identifier); {
	case err == nil:
		return ACLGrantAny, nil
	case errors.Is(err, ErrCrossDomainGrant):
		return ACLGrantNone, nil
	case errors.Is(err, ErrOwnerACL):
		return ACLGrantOwner, nil
	default:
		return ACLGrantNone, err
	}
}

// GetMailboxACLs retrieves all ACL entries for a mailbox, one per grantee: each
// account's rows under the account's current primary address, which is what a
// revoke under that address acts on, with every right any of them grants, and the
// mailbox owner with every right, which it holds whatever a stored row says.
func (db *Database) GetMailboxACLs(ctx context.Context, mailboxID int64) ([]ACLEntry, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT a.mailbox_id, a.account_id, COALESCE(p.address, a.identifier),
			CASE WHEN a.account_id = m.account_id THEN $2 ELSE a.rights END,
			a.created_at, a.updated_at
		FROM mailbox_acls a
		JOIN mailboxes m ON m.id = a.mailbox_id
		LEFT JOIN credentials p ON p.account_id = a.account_id AND p.primary_identity = TRUE
		WHERE a.mailbox_id = $1
		ORDER BY 3, a.id
	`, mailboxID, AllACLRights)
	if err != nil {
		return nil, fmt.Errorf("failed to query ACLs: %w", err)
	}
	defer rows.Close()

	var entries []ACLEntry
	for rows.Next() {
		var entry ACLEntry
		if err := rows.Scan(&entry.MailboxID, &entry.AccountID, &entry.Identifier, &entry.Rights, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ACL entry: %w", err)
		}
		if n := len(entries); n > 0 && entries[n-1].Identifier == entry.Identifier {
			prev := &entries[n-1]
			prev.Rights = canonicalRights(prev.Rights + entry.Rights)
			if entry.UpdatedAt.After(prev.UpdatedAt) {
				prev.UpdatedAt = entry.UpdatedAt
			}
			continue
		}
		entry.Rights = canonicalRights(entry.Rights)
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating ACL entries: %w", err)
	}

	return entries, nil
}

// CheckMailboxPermission checks if a user has a specific right on a mailbox
// Uses the PostgreSQL function for efficient permission checking
func (db *Database) CheckMailboxPermission(ctx context.Context, mailboxID, accountID int64, right ACLRight) (bool, error) {
	var hasRight bool
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT has_mailbox_right($1, $2, $3)
	`, mailboxID, accountID, string(right)).Scan(&hasRight)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	return hasRight, nil
}

// CheckMoveRights evaluates, in a single round trip, the ACL rights MOVE requires:
// insert ('i') on the destination, plus delete-msg ('t') and expunge ('e') on the
// source. has_mailbox_right() already short-circuits to TRUE for the mailbox owner
// (the common case), so this is a single fast query that replaces three sequential
// CheckMailboxPermission calls. When source and destination are the same mailbox the
// caller passes equal ids; the function still returns all three booleans correctly.
func (db *Database) CheckMoveRights(ctx context.Context, srcMailboxID, destMailboxID, accountID int64) (canInsertDest, canDeleteSrc, canExpungeSrc bool, err error) {
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT
			has_mailbox_right($1, $3, 'i'),
			has_mailbox_right($2, $3, 't'),
			has_mailbox_right($2, $3, 'e')
	`, destMailboxID, srcMailboxID, accountID).Scan(&canInsertDest, &canDeleteSrc, &canExpungeSrc)
	if err != nil {
		return false, false, false, fmt.Errorf("failed to check move permissions: %w", err)
	}
	return canInsertDest, canDeleteSrc, canExpungeSrc, nil
}

// CheckMailboxPermissions checks if a user has all specified rights on a mailbox
func (db *Database) CheckMailboxPermissions(ctx context.Context, mailboxID, accountID int64, rights string) (bool, error) {
	for _, r := range rights {
		hasRight, err := db.CheckMailboxPermission(ctx, mailboxID, accountID, ACLRight(r))
		if err != nil {
			return false, err
		}
		if !hasRight {
			return false, nil
		}
	}
	return true, nil
}

// GetUserMailboxRights returns the rights a user has on a specific mailbox
// Returns empty string if user has no access
func (db *Database) GetUserMailboxRights(ctx context.Context, mailboxID, accountID int64) (string, error) {
	// First check if user owns the mailbox (owner always has full access)
	var isOwner bool
	var ownerDomain *string
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT (account_id = $1), owner_domain
		FROM mailboxes
		WHERE id = $2 AND deleted_at IS NULL
	`, accountID, mailboxID).Scan(&isOwner, &ownerDomain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", consts.ErrMailboxNotFound
		}
		return "", fmt.Errorf("failed to check ownership: %w", err)
	}

	// Owners have all rights (both shared and non-shared mailboxes)
	if isOwner {
		return AllACLRights, nil
	}

	// Effective rights are the UNION of the user-specific ACL and any applicable
	// "anyone" ACL. This matches has_mailbox_right(), which grants a right if EITHER
	// entry contains it; MYRIGHTS must report the same set the server enforces.
	// (RFC 4314 §2 leaves the combination of matching identifiers implementation-defined.)
	var userRights string
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT rights
		FROM mailbox_acls
		WHERE mailbox_id = $1 AND account_id = $2
	`, mailboxID, accountID).Scan(&userRights)
	if err != nil && err != pgx.ErrNoRows {
		return "", fmt.Errorf("failed to query user ACL: %w", err)
	}

	// Add "anyone" rights for users in the mailbox owner's domain.
	var anyoneRights string
	if ownerDomain != nil {
		var userDomain string
		derr := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
			SELECT SPLIT_PART(address, '@', 2)
			FROM credentials
			WHERE account_id = $1 AND primary_identity = TRUE
		`, accountID).Scan(&userDomain)
		if derr != nil && derr != pgx.ErrNoRows {
			return "", fmt.Errorf("failed to get user domain: %w", derr)
		}
		if derr == nil && userDomain == *ownerDomain {
			aerr := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
				SELECT rights
				FROM mailbox_acls
				WHERE mailbox_id = $1 AND identifier = $2
			`, mailboxID, AnyoneIdentifier).Scan(&anyoneRights)
			if aerr != nil && aerr != pgx.ErrNoRows {
				return "", fmt.Errorf("failed to query 'anyone' ACL: %w", aerr)
			}
		}
	}

	// Union (empty if the user has neither a direct nor an "anyone" grant).
	return unionRights(userRights, anyoneRights), nil
}
