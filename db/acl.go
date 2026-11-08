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
	ownerDomain    string
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
	if mb.isShared && mb.ownerDomain == "" {
		return mb, fmt.Errorf("shared mailbox %d has no owner domain", mailboxID)
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

// resolveGrantee returns who identifier names as a grantee on a shared mailbox:
// "anyone", or an active account in the owner's domain, stored under its primary
// address (RFC 4314 §3.4 lets "multiple forms of an identifier" name one account).
// The domain is compared before the address is looked up, so the answer never tells
// whether an address exists outside the owner's domain.
func resolveGrantee(ctx context.Context, q aclQuerier, mb aclMailbox, identifier string) (accountID *int64, canonical string, err error) {
	if identifier == AnyoneIdentifier {
		return nil, AnyoneIdentifier, nil
	}
	at := strings.LastIndexByte(identifier, '@')
	if at < 0 {
		return nil, "", fmt.Errorf("%w: user %s not found", consts.ErrUserNotFound, identifier)
	}
	if !strings.EqualFold(identifier[at+1:], mb.ownerDomain) {
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

// aclRowsFor returns the ACL rows on mailboxID that identifier names and the union
// of their rights: every row of the account the identifier is an address of (in any
// case, an alias, a deleted account too), or, when it is no account's address, rows
// stored under that text, such as one written before its address changed.
func aclRowsFor(ctx context.Context, tx pgx.Tx, mailboxID int64, identifier string) ([]int64, string, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, rights FROM mailbox_acls
		WHERE mailbox_id = $1 AND (
			account_id = (SELECT account_id FROM credentials WHERE LOWER(address) = LOWER($2))
			OR (LOWER(identifier) = LOWER($2)
				AND NOT EXISTS (SELECT 1 FROM credentials WHERE LOWER(address) = LOWER($2)))
		)
	`, mailboxID, identifier)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read ACL entries: %w", err)
	}
	defer rows.Close()
	var ids []int64
	var rights string
	for rows.Next() {
		var id int64
		var r string
		if err := rows.Scan(&id, &r); err != nil {
			return nil, "", fmt.Errorf("failed to scan ACL entry: %w", err)
		}
		ids = append(ids, id)
		rights += r
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("failed to read ACL entries: %w", err)
	}
	return ids, canonicalRights(rights), nil
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
// Removing rights that are not there leaves the ACL as asked and succeeds (RFC 4314
// §3.2); only a change that would leave rights can be refused, and on a mailbox
// outside the shared namespace it is, before any address is looked up.
//
// grantorAccountID is the account the caller authorised to administer the mailbox,
// or 0 for a trusted caller (the Admin API, sora-admin). Its 'a' right is checked
// again under the ACL lock, so an administrator revoked meanwhile is refused with
// consts.ErrNotPermitted rather than granting after the revoke.
func (db *Database) SetMailboxACL(ctx context.Context, mailboxID, grantorAccountID int64, identifier string, mod ACLModification, rights string) error {
	if err := ValidateACLRights(rights); err != nil {
		return err
	}
	tx, mb, err := db.beginACLWrite(ctx, mailboxID)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	if grantorAccountID != 0 && grantorAccountID != mb.ownerAccountID {
		var allowed bool
		if err := tx.QueryRow(ctx, "SELECT has_mailbox_right($1, $2, 'a')", mailboxID, grantorAccountID).Scan(&allowed); err != nil {
			return fmt.Errorf("failed to check admin permission: %w", err)
		}
		if !allowed {
			return fmt.Errorf("%w: no admin right on mailbox %d", consts.ErrNotPermitted, mailboxID)
		}
	}

	ids, existing, err := aclRowsFor(ctx, tx, mailboxID, identifier)
	if err != nil {
		return err
	}
	var final string
	switch mod {
	case ACLAdd:
		final = canonicalRights(existing + rights)
	case ACLRemove:
		final = strings.Map(func(r rune) rune {
			if strings.ContainsRune(rights, r) {
				return -1
			}
			return r
		}, existing)
	default:
		final = canonicalRights(rights)
	}

	if final != "" {
		if !mb.isShared {
			return ErrMailboxNotShared
		}
		accountID, canonical, err := resolveGrantee(ctx, tx, mb, identifier)
		if err != nil {
			return err
		}
		// One row per account: earlier rows under other spellings go.
		if err := deleteACLRows(ctx, tx, ids); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
			VALUES ($1, $2, $3, $4, now(), now())
			ON CONFLICT (mailbox_id, identifier)
			DO UPDATE SET account_id = EXCLUDED.account_id, rights = EXCLUDED.rights, updated_at = now()
		`, mailboxID, accountID, canonical, final); err != nil {
			return fmt.Errorf("failed to grant access: %w", err)
		}
	} else if err := deleteACLRows(ctx, tx, ids); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
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
	ids, _, err := aclRowsFor(ctx, tx, mailboxID, identifier)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: ACL entry not found for identifier %s", consts.ErrDBNotFound, identifier)
	}
	if err := deleteACLRows(ctx, tx, ids); err != nil {
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
	var isOwner bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM credentials WHERE account_id = $1 AND LOWER(address) = LOWER($2))
	`, mb.ownerAccountID, identifier).Scan(&isOwner); err != nil {
		return ACLGrantNone, fmt.Errorf("failed to check mailbox owner: %w", err)
	}
	if isOwner {
		return ACLGrantOwner, nil
	}
	if !mb.isShared {
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

// GetMailboxACLs retrieves all ACL entries for a mailbox
func (db *Database) GetMailboxACLs(ctx context.Context, mailboxID int64) ([]ACLEntry, error) {
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT mailbox_id, account_id, identifier, rights, created_at, updated_at
		FROM mailbox_acls
		WHERE mailbox_id = $1
		ORDER BY identifier
	`, mailboxID)
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
	err := db.GetReadPool().QueryRow(ctx, `
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
	err = db.GetReadPool().QueryRow(ctx, `
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
	err := db.GetReadPool().QueryRow(ctx, `
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
	err = db.GetReadPool().QueryRow(ctx, `
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
		derr := db.GetReadPool().QueryRow(ctx, `
			SELECT SPLIT_PART(address, '@', 2)
			FROM credentials
			WHERE account_id = $1 AND primary_identity = TRUE
		`, accountID).Scan(&userDomain)
		if derr != nil && derr != pgx.ErrNoRows {
			return "", fmt.Errorf("failed to get user domain: %w", derr)
		}
		if derr == nil && userDomain == *ownerDomain {
			aerr := db.GetReadPool().QueryRow(ctx, `
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
