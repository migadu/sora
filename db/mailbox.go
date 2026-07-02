package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// DBMailbox represents the database structure of a mailbox
type DBMailbox struct {
	ID          int64
	AccountID   int64  // The owner of the mailbox (important for shared mailboxes)
	Name        string // User-visible, delimiter-separated mailbox name (e.g., "INBOX/Sent")
	UIDValidity uint32
	Subscribed  bool
	HasChildren bool
	Path        string // Hex-encoded path of ancestor IDs
	SpecialUse  string // RFC 6154 special-use attribute (e.g. "\Sent"); empty if none
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func NewDBMailbox(mboxId int64, name string, uidValidity uint32, path string, subscribed, hasChildren bool, createdAt, updatedAt time.Time) DBMailbox {
	return DBMailbox{
		ID:          mboxId,
		Name:        name,
		UIDValidity: uidValidity,
		Path:        path,
		HasChildren: hasChildren,
		Subscribed:  subscribed,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func (db *Database) GetMailboxes(ctx context.Context, AccountID int64, subscribed bool) ([]*DBMailbox, error) {
	// Optimized query using denormalized domain column and better index usage
	// Key optimizations:
	// 1. CTE to materialize user's domain once (eliminates repeated SPLIT_PART calls)
	// 2. Uses credentials.domain column instead of SPLIT_PART(address, '@', 2)
	// 3. Composite indexes on mailbox_acls allow efficient rights filtering
	ownerDomain, err := db.GetAccountDomain(ctx, AccountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []*DBMailbox{}, nil
		}
		return nil, fmt.Errorf("failed to retrieve user domain: %w", err)
	}

	// Optimized query using the injected domain
	query := `
		WITH accessible_mailboxes AS (
			-- 1. All mailboxes owned by user (including shared mailboxes they created)
			SELECT id, name, uid_validity, path, subscribed, special_use, created_at, updated_at, account_id
			FROM mailboxes
			WHERE account_id = $1
			  AND deleted_at IS NULL

			UNION

			-- 2. Shared mailboxes where user has direct ACL access (must have at least 'l' lookup right)
			SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.special_use, m.created_at, m.updated_at, m.account_id
			FROM mailboxes m
			INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
			WHERE m.is_shared = TRUE
			  AND acl.account_id = $1
			  AND position('l' IN acl.rights) > 0
			  AND m.deleted_at IS NULL

			UNION

			-- 3. Shared mailboxes with "anyone" access (same domain, must have 'l' right)
			SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.special_use, m.created_at, m.updated_at, m.account_id
			FROM mailboxes m
			INNER JOIN mailbox_acls anyone_acl ON m.id = anyone_acl.mailbox_id
			WHERE m.is_shared = TRUE
			  AND m.owner_domain = $2
			  AND anyone_acl.identifier = 'anyone'
			  AND position('l' IN anyone_acl.rights) > 0
			  AND m.deleted_at IS NULL
		)
		SELECT
			m.id, m.name, m.uid_validity, m.path,
			-- Subscription state from the name-based subscriptions table (migration
			-- 000046) via a LEFT JOIN: the planner hashes this account's (small)
			-- subscription set once and probes per mailbox, instead of running a
			-- correlated per-row subplan — this scales to accounts with many
			-- mailboxes. The (account_id, LOWER(mailbox_name)) unique index makes the
			-- match at-most-one, so no rows are duplicated.
			(subs.mailbox_name IS NOT NULL) AS subscribed,
			COALESCE(m.special_use, '') AS special_use, m.created_at, m.updated_at, m.account_id,
			-- has_children: does a direct child exist? The child's direct-parent path is
			-- its path minus the final 16-char ancestor segment, matched by equality so the
			-- expression index idx_mailboxes_account_parent_path (migration 000038) applies.
			-- The previous per-row correlated subquery matched children with LIKE on m.path,
			-- whose pattern is a column expression, so PostgreSQL could not use a prefix
			-- index and seq-scanned the account's mailboxes once per row -- O(N^2), which
			-- exceeded the read query_timeout for accounts with tens of thousands of mailboxes.
			EXISTS(SELECT 1 FROM mailboxes child WHERE child.account_id = m.account_id AND LEFT(child.path, LENGTH(child.path) - 16) = m.path AND child.deleted_at IS NULL) AS has_children
		FROM accessible_mailboxes m
		LEFT JOIN subscriptions subs ON subs.account_id = $1 AND LOWER(subs.mailbox_name) = LOWER(m.name)
		WHERE 1=1
	`

	if subscribed {
		query += " AND subs.mailbox_name IS NOT NULL"
	}

	// Add a consistent ordering
	query += " ORDER BY m.name"

	// Prepare the query to fetch all mailboxes for the given user
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, AccountID, ownerDomain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Collect the mailboxes
	var mailboxes []*DBMailbox
	for rows.Next() {
		var mailbox DBMailbox
		var uidValidityInt64 int64

		if err := rows.Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.SpecialUse, &mailbox.CreatedAt, &mailbox.UpdatedAt, &mailbox.AccountID, &mailbox.HasChildren); err != nil {
			return nil, err
		}

		mailbox.UIDValidity = uint32(uidValidityInt64)
		mailboxes = append(mailboxes, &mailbox)
	}

	// Check for any error that occurred during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return mailboxes, nil
}

// GetMailboxesCount returns the number of mailboxes for an account
func (db *Database) GetMailboxesCount(ctx context.Context, AccountID int64) (int, error) {
	var count int
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx,
		"SELECT COUNT(*) FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL",
		AccountID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count mailboxes for account %d: %w", AccountID, err)
	}
	return count, nil
}

// GetMailbox fetches the mailbox
func (db *Database) GetMailbox(ctx context.Context, mailboxID int64, AccountID int64) (*DBMailbox, error) {
	var mailbox DBMailbox
	var uidValidityInt64 int64

	// First, fetch the core mailbox details.
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT id, name, uid_validity, path,
			EXISTS(SELECT 1 FROM subscriptions s WHERE s.account_id = $2 AND LOWER(s.mailbox_name) = LOWER(mailboxes.name)) AS subscribed,
			COALESCE(special_use, ''), created_at, updated_at, account_id
		FROM mailboxes
		WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL
	`, mailboxID, AccountID).Scan(
		&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.SpecialUse, &mailbox.CreatedAt, &mailbox.UpdatedAt, &mailbox.AccountID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to fetch mailbox %d: %w", mailboxID, err)
	}

	mailbox.UIDValidity = uint32(uidValidityInt64)

	// Separately, check if the mailbox has children using an efficient EXISTS query.
	// For shared mailboxes, check using the owner's account_id to get accurate child count.
	// $2 is a bind parameter, so PostgreSQL treats `path LIKE $2 || '%'` as a constant
	// prefix and uses idx_mailboxes_path_prefix (unlike the correlated form in GetMailboxes).
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND LENGTH(path) = LENGTH($2) + 16 AND path LIKE $2 || '%' AND deleted_at IS NULL)
	`, mailbox.AccountID, mailbox.Path).Scan(&mailbox.HasChildren)
	if err != nil {
		logger.Error("Database: failed to check for children of mailbox", "mailbox_id", mailboxID, "err", err)
		return nil, consts.ErrInternalError
	}

	return &mailbox, nil
}

// GetMailboxByName fetches the mailbox for a specific user by name
func (db *Database) GetMailboxByName(ctx context.Context, AccountID int64, name string) (*DBMailbox, error) {
	start := time.Now()
	var err error
	defer func() {
		status := "success"
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				status = "not_found"
			} else {
				status = "error"
			}
		}
		metrics.DBQueryDuration.WithLabelValues("mailbox_get_by_name", "read").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("mailbox_get_by_name", status, "read").Inc()
	}()

	var mailbox DBMailbox
	var uidValidityInt64 int64
	var accountID int64

	ownerDomain, fetchErr := db.GetAccountDomain(ctx, AccountID)
	if fetchErr != nil {
		// Log the error but don't fail immediately, wait for the actual query execution
		if !errors.Is(fetchErr, pgx.ErrNoRows) {
			logger.Error("Database: failed to get account domain for GetMailboxByName", "err", fetchErr)
		}
		ownerDomain = "" // fallback
	}

	// Optimized query using denormalized domain column
	// Use LOWER() on both sides to ensure consistent case-insensitive comparison
	// regardless of database locale (C/POSIX locales don't lowercase non-ASCII in LOWER())
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT id, name, uid_validity, path,
			EXISTS(SELECT 1 FROM subscriptions s WHERE s.account_id = $1 AND LOWER(s.mailbox_name) = LOWER(sub.name)) AS subscribed,
			COALESCE(special_use, ''), created_at, updated_at, account_id FROM (
			-- 1) Owned by user
			SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.special_use, m.created_at, m.updated_at, m.account_id
			FROM mailboxes m
			WHERE m.account_id = $1 AND LOWER(m.name) = LOWER($2)
			  AND m.deleted_at IS NULL

			UNION ALL

			-- 2) Specifically shared to this user explicitly via ACL
			SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.special_use, m.created_at, m.updated_at, m.account_id
			FROM mailbox_acls acl
			JOIN mailboxes m ON m.id = acl.mailbox_id
			WHERE acl.account_id = $1
			  AND position('l' IN acl.rights) > 0
			  AND LOWER(m.name) = LOWER($2)
			  AND m.account_id != $1
			  AND COALESCE(m.is_shared, FALSE) = TRUE
			  AND m.deleted_at IS NULL

			UNION ALL

			-- 3) Publicly shared within the same domain ('anyone' ACL)
			SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.special_use, m.created_at, m.updated_at, m.account_id
			FROM mailbox_acls anyone_acl
			JOIN mailboxes m ON m.id = anyone_acl.mailbox_id
			WHERE anyone_acl.identifier = 'anyone'
			  AND position('l' IN anyone_acl.rights) > 0
			  AND LOWER(m.name) = LOWER($2)
			  AND m.account_id != $1
			  AND COALESCE(m.is_shared, FALSE) = TRUE
			  AND m.owner_domain = $3
			  AND m.deleted_at IS NULL
		) sub
		LIMIT 1
	`, AccountID, name, ownerDomain).Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.SpecialUse, &mailbox.CreatedAt, &mailbox.UpdatedAt, &accountID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrMailboxNotFound
		}
		logger.Error("Database: failed to find mailbox", "name", name, "err", err)
		return nil, consts.ErrInternalError
	}

	mailbox.UIDValidity = uint32(uidValidityInt64)
	mailbox.AccountID = accountID

	// Separately, check if the mailbox has children using an efficient EXISTS query.
	// For shared mailboxes, check using the owner's account_id to get accurate child count.
	// $2 is a bind parameter, so PostgreSQL treats `path LIKE $2 || '%'` as a constant
	// prefix and uses idx_mailboxes_path_prefix (unlike the correlated form in GetMailboxes).
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND LENGTH(path) = LENGTH($2) + 16 AND path LIKE $2 || '%' AND deleted_at IS NULL)
	`, accountID, mailbox.Path).Scan(&mailbox.HasChildren)
	if err != nil {
		logger.Error("Database: failed to check for children of mailbox", "name", name, "err", err)
		return nil, consts.ErrInternalError
	}

	return &mailbox, nil
}

// CreateMailbox creates a mailbox with no RFC 6154 special-use attribute.
func (db *Database) CreateMailbox(ctx context.Context, tx pgx.Tx, AccountID int64, name string, parentID *int64) error {
	return db.createMailbox(ctx, tx, AccountID, name, parentID, "")
}

// CreateMailboxWithSpecialUse creates a mailbox and assigns an RFC 6154 special-use
// attribute in the same INSERT, so the operation is atomic: it can never leave a
// mailbox without its attribute (and LIST never observes a transient attribute-less
// state) if a later step fails. A duplicate attribute for the account surfaces as
// consts.ErrMailboxSpecialUseInUse (mapped to NO [USEATTR] by the caller); a duplicate
// name surfaces as consts.ErrDBUniqueViolation.
func (db *Database) CreateMailboxWithSpecialUse(ctx context.Context, tx pgx.Tx, AccountID int64, name string, parentID *int64, specialUse string) error {
	return db.createMailbox(ctx, tx, AccountID, name, parentID, specialUse)
}

func (db *Database) createMailbox(ctx context.Context, tx pgx.Tx, AccountID int64, name string, parentID *int64, specialUse string) error {
	// Mailbox names are case-insensitive (Option A): the UNIQUE(account_id,
	// LOWER(name)) index rejects any case-variant of an existing name. Folding
	// INBOX additionally guarantees the reserved inbox is stored as the canonical
	// "INBOX" (RFC 3501 §5.1); other names keep their as-typed case.
	name = helpers.CanonicalMailboxName(name)

	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(name, "\t\r\n\x00") {
		logger.Error("Database: attempted to create mailbox with invalid characters", "name", name, "account_id", AccountID)
		return consts.ErrMailboxInvalidName
	}

	// Reject "." / ".." path segments: such names would let the maildir
	// exporter escape its target directory (path traversal) when the hierarchy
	// is materialised on disk.
	if helpers.MailboxNameHasTraversal(name) {
		logger.Error("Database: attempted to create mailbox with path traversal segment", "name", name, "account_id", AccountID)
		return consts.ErrMailboxInvalidName
	}

	// Avoid low uid_validity which may cause issues with some IMAP clients
	// Use nanoseconds to significantly reduce the chance of collision on rapid creation.
	uidValidity := uint32(time.Now().UnixNano())

	// Check if this is a shared mailbox based on name prefix
	// Extract config from context if available
	isShared := false
	var ownerDomain *string
	sharedPrefix := "Shared/" // Default prefix

	// Try to get config from context
	if cfg, ok := ctx.Value(consts.ConfigContextKey).(*config.Config); ok && cfg != nil && cfg.SharedMailboxes.Enabled {
		sharedPrefix = cfg.SharedMailboxes.NamespacePrefix
		// Check if name starts with prefix, or is the prefix itself (without trailing slash)
		prefixWithoutSlash := strings.TrimSuffix(sharedPrefix, "/")
		if strings.HasPrefix(name, sharedPrefix) || name == prefixWithoutSlash {
			isShared = true

			// Extract domain from user's primary credential
			var domain string
			err := tx.QueryRow(ctx, `
				SELECT SPLIT_PART(address, '@', 2)
				FROM credentials
				WHERE account_id = $1 AND primary_identity = TRUE
			`, AccountID).Scan(&domain)
			if err != nil {
				return fmt.Errorf("failed to get user domain for shared mailbox: %w", err)
			}
			ownerDomain = &domain
		}
	}

	// Determine the parent path if parentID is provided
	var parentPath string
	if parentID != nil {
		// Fetch the parent mailbox to get its path
		err := tx.QueryRow(ctx, `
			SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL
		`, *parentID, AccountID).Scan(&parentPath)

		if err != nil {
			if err == pgx.ErrNoRows {
				return consts.ErrMailboxNotFound
			}
			return fmt.Errorf("failed to fetch parent mailbox: %w", err)
		}
	}

	// Assign the special-use attribute in the same INSERT so the mailbox and its
	// attribute are committed atomically (RFC 6154). NULL when none is requested.
	var specialUseParam *string
	if specialUse != "" {
		specialUseParam = &specialUse
	}

	// Insert the mailbox with shared mailbox fields
	var mailboxID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path, is_shared, owner_domain, special_use)
		VALUES ($1, $2, $3, $4, '', $5, $6, $7)
		RETURNING id
	`, AccountID, name, int64(uidValidity), false, isShared, ownerDomain, specialUseParam).Scan(&mailboxID)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23505": // Unique constraint violation
				// Distinguish a duplicate special-use attribute (RFC 6154 §5) from a
				// duplicate name so the caller can return NO [USEATTR] vs [ALREADYEXISTS].
				if pgErr.ConstraintName == "mailboxes_account_special_use_unique" {
					logger.Warn("Database: special-use attribute already assigned", "special_use", specialUse, "account_id", AccountID)
					return consts.ErrMailboxSpecialUseInUse
				}
				logger.Warn("Database: mailbox already exists", "name", name, "account_id", AccountID)
				return consts.ErrDBUniqueViolation
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_account_id_fkey" {
					logger.Error("Database: user does not exist", "account_id", AccountID)
					return consts.ErrDBNotFound
				}
			}
		}
		return fmt.Errorf("failed to create mailbox: %w", err)
	}

	// Update the path now that we have the ID
	mailboxPath := helpers.GetMailboxPath(parentPath, mailboxID)
	_, err = tx.Exec(ctx, `
		UPDATE mailboxes SET path = $1 WHERE id = $2
	`, mailboxPath, mailboxID)

	if err != nil {
		return fmt.Errorf("failed to update mailbox path: %w", err)
	}

	// If shared mailbox, grant creator full rights (or configured default rights)
	// Also inherit ACLs from parent mailbox if one exists (RFC 4314)
	if isShared {
		// If there's a parent mailbox, inherit its ACLs
		if parentID != nil {
			// Copy all ACL entries from parent to child
			_, err = tx.Exec(ctx, `
				INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
				SELECT $1, account_id, identifier, rights, now(), now()
				FROM mailbox_acls
				WHERE mailbox_id = $2
			`, mailboxID, *parentID)
			if err != nil {
				return fmt.Errorf("failed to inherit parent ACLs: %w", err)
			}
			logger.Info("Database: created shared mailbox with inherited ACLs from parent", "name", name, "mailbox_id", mailboxID, "parent_id", *parentID)
		} else {
			// No parent, grant creator full rights (or configured default rights)
			defaultRights := "lrswipkxtea" // Full rights by default
			if cfg, ok := ctx.Value(consts.ConfigContextKey).(*config.Config); ok && cfg != nil && cfg.SharedMailboxes.DefaultRights != "" {
				defaultRights = cfg.SharedMailboxes.DefaultRights
			}

			// Get creator's email for identifier
			var creatorEmail string
			err = tx.QueryRow(ctx, `
				SELECT address FROM credentials
				WHERE account_id = $1 AND primary_identity = TRUE
			`, AccountID).Scan(&creatorEmail)
			if err != nil {
				return fmt.Errorf("failed to get creator email: %w", err)
			}

			_, err = tx.Exec(ctx, `
				INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
				VALUES ($1, $2, $3, $4, now(), now())
			`, mailboxID, AccountID, creatorEmail, defaultRights)
			if err != nil {
				return fmt.Errorf("failed to set creator ACL for shared mailbox: %w", err)
			}
			logger.Info("Database: created shared mailbox", "name", name, "mailbox_id", mailboxID, "account_id", AccountID, "domain", *ownerDomain)
		}
	}

	return nil
}

// SoftDeleteMailbox marks a mailbox deleted (two-phase deletion) so the IMAP DELETE
// command can return immediately instead of synchronously expunging every message
// and rewriting their rows under the per-mailbox lock. Stamping deleted_at hides the
// mailbox from every read path at once (they all filter deleted_at IS NULL); the
// background cleaner later calls DeleteMailbox to do the heavy expunge + row removal.
//
// The caller (server/imap/delete.go) has already verified the mailbox exists, is not
// a special mailbox, has no children, and that the user holds the 'x' (delete) right.
// We re-lock and re-gate here (mirroring DeleteMailbox) so a concurrent
// delivery/expunge/store on the same mailbox is serialized via the same mailbox-row
// lock the other write paths take first (see lockMailboxStats). Because the name
// uniqueness index is partial (WHERE deleted_at IS NULL), stamping deleted_at frees
// the name for an immediate re-CREATE. If a child mailbox somehow appears after the
// caller's leaf check, the cleaner's DeleteMailbox uses subtree (path LIKE) semantics
// and removes it too, so no orphan survives.
func (db *Database) SoftDeleteMailbox(ctx context.Context, tx pgx.Tx, mailboxID int64, AccountID int64) error {
	var isShared bool
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(is_shared, FALSE)
		FROM mailboxes
		WHERE id = $1 AND (account_id = $2 OR COALESCE(is_shared, FALSE) = TRUE) AND deleted_at IS NULL
		FOR UPDATE
	`, mailboxID, AccountID).Scan(&isShared)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consts.ErrMailboxNotFound
		}
		return fmt.Errorf("failed to lock mailbox %d for soft delete: %w", mailboxID, err)
	}

	// For shared mailboxes, enforce the ACL 'x' (delete) right, mirroring DeleteMailbox.
	if isShared {
		hasDeleteRight, err := db.CheckMailboxPermission(ctx, mailboxID, AccountID, ACLRightDelete)
		if err != nil {
			return fmt.Errorf("failed to check delete permission: %w", err)
		}
		if !hasDeleteRight {
			return fmt.Errorf("permission denied: user does not have delete right on shared mailbox")
		}
	}

	tag, err := tx.Exec(ctx, `
		UPDATE mailboxes SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to soft delete mailbox %d: %w", mailboxID, err)
	}
	if tag.RowsAffected() == 0 {
		// Lost a race with a concurrent soft-delete of the same mailbox.
		return consts.ErrMailboxNotFound
	}
	return nil
}

// DeleteMailbox deletes a mailbox for a specific user by id
func (db *Database) DeleteMailbox(ctx context.Context, tx pgx.Tx, mailboxID int64, AccountID int64) error {
	// Check if user has delete permission (ACL 'x' right) for shared mailboxes
	// For personal mailboxes, ownership is sufficient
	var mboxPath string
	var isShared bool
	err := tx.QueryRow(ctx, `
		SELECT path, COALESCE(is_shared, FALSE)
		FROM mailboxes
		WHERE id = $1 AND (account_id = $2 OR COALESCE(is_shared, FALSE) = TRUE)
	`, mailboxID, AccountID).Scan(&mboxPath, &isShared)
	if err != nil {
		if err == pgx.ErrNoRows {
			return consts.ErrMailboxNotFound
		}
		return fmt.Errorf("failed to fetch mailbox for deletion: %w", err)
	}

	// If it's a shared mailbox, check ACL permissions
	if isShared {
		hasDeleteRight, err := db.CheckMailboxPermission(ctx, mailboxID, AccountID, ACLRightDelete)
		if err != nil {
			return fmt.Errorf("failed to check delete permission: %w", err)
		}
		if !hasDeleteRight {
			return fmt.Errorf("permission denied: user does not have delete right on shared mailbox")
		}
	}

	// Find all mailboxes that will be deleted (the target and its children)
	// to acquire locks in a consistent order and prevent deadlocks.
	var mailboxesToDelete []int64
	rows, err := tx.Query(ctx, `SELECT id FROM mailboxes WHERE account_id = $1 AND (id = $2 OR path LIKE $3 || '/%')`, AccountID, mailboxID, mboxPath)
	if err != nil {
		return fmt.Errorf("failed to query mailboxes for deletion lock: %w", err)
	}
	mailboxesToDelete, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		// pgx.CollectRows closes the rows, so we don't need to defer rows.Close()
		return fmt.Errorf("failed to collect mailboxes for deletion lock: %w", err)
	}

	// Sort the IDs to ensure a consistent lock acquisition order across all transactions.
	sort.Slice(mailboxesToDelete, func(i, j int) bool { return mailboxesToDelete[i] < mailboxesToDelete[j] })

	// Lock the mailbox rows (ascending id, deterministic) before marking their
	// messages expunged. This serializes against concurrent EXPUNGE/STORE/MOVE on
	// the same mailboxes (which lock the mailbox row first too — see
	// lockMailboxStats), keeping unseen_count maintenance race-free, and replaces
	// the previous pg_advisory lock to avoid the global advisory-keyspace collision.
	if len(mailboxesToDelete) > 0 {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM mailboxes WHERE id = ANY($1) ORDER BY id FOR UPDATE", mailboxesToDelete); err != nil {
			return fmt.Errorf("failed to acquire locks for mailbox deletion: %w", err)
		}
	}

	// Before deleting the mailboxes, update all messages within them (the one
	// being deleted and all its children) to preserve their mailbox path and mark as expunged.
	// This is crucial for restoring messages later.
	// This single UPDATE using a JOIN is much more efficient than looping.
	_, err = tx.Exec(ctx, `
		UPDATE messages m
		SET mailbox_path = mb.name,
		    expunged_at = now(),
		    expunged_modseq = nextval('messages_modseq')
		FROM mailboxes mb
		WHERE m.mailbox_id = mb.id
		  AND mb.account_id = $1
		  AND (mb.id = $2 OR mb.path LIKE $3 || '/%')
		  AND m.expunged_at IS NULL
	`, AccountID, mailboxID, mboxPath)
	if err != nil {
		logger.Error("Database: failed to set path and mark messages as expunged for mailbox and children", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
	}

	// Delete the mailbox and all its children in one query using path-based approach
	result, err := tx.Exec(ctx, `
		DELETE FROM mailboxes
		WHERE account_id = $1 AND (id = $2 OR path LIKE $3 || '/%')
	`, AccountID, mailboxID, mboxPath)

	if err != nil {
		logger.Error("Database: failed to delete mailbox and children", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// This should not happen if the initial SELECT succeeded, but it's a good safeguard.
		logger.Error("Database: mailbox not found for deletion during final delete step", "mailbox_id", mailboxID)
		return consts.ErrMailboxNotFound
	}

	return nil
}

// HasMailboxWithSpecialUse reports whether the account already has a live mailbox
// carrying the given special-use attribute (RFC 6154 §5 uniqueness pre-check).
func (db *Database) HasMailboxWithSpecialUse(ctx context.Context, accountID int64, attr string) (bool, error) {
	var exists bool
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND special_use = $2 AND deleted_at IS NULL)
	`, accountID, attr).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check special-use uniqueness: %w", err)
	}
	return exists, nil
}

func (db *Database) CreateDefaultMailboxes(ctx context.Context, tx pgx.Tx, AccountID int64) error {
	// OPTIMIZATION: Early exit if INBOX already exists
	// This avoids 5 INSERT attempts on every LMTP delivery when mailboxes already exist
	var inboxExists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND LOWER(name) = 'inbox' AND deleted_at IS NULL)
	`, AccountID).Scan(&inboxExists)
	if err != nil {
		return fmt.Errorf("failed to check for INBOX existence: %w", err)
	}

	// If INBOX exists, assume all default mailboxes exist (they're created together)
	if inboxExists {
		return nil
	}

	// Use a base timestamp and an increment to guarantee unique UIDVALIDITY values
	// for all default mailboxes created in this single transaction.
	baseUidValidity := time.Now().Unix()
	for i, mailboxName := range consts.DefaultMailboxes {
		var mailboxID int64
		uidValidity := uint32(baseUidValidity + int64(i))

		// Use ON CONFLICT to handle existing mailboxes gracefully.
		// The DO UPDATE clause with a no-op is a common way to get RETURNING to work with conflicts.
		err := tx.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path, special_use)
			VALUES ($1, $2, $3, TRUE, '', CASE LOWER($2)
				WHEN 'sent'    THEN '\Sent'
				WHEN 'drafts'  THEN '\Drafts'
				WHEN 'archive' THEN '\Archive'
				WHEN 'junk'    THEN '\Junk'
				WHEN 'trash'   THEN '\Trash'
			END)
			ON CONFLICT (account_id, LOWER(name)) WHERE deleted_at IS NULL DO UPDATE
			SET subscribed = TRUE, -- Ensure default mailboxes are always subscribed
			    -- Fill the special-use attribute if a pre-existing default row lacks
			    -- one (partial provisioning); never clobber an explicitly-set value,
			    -- and only when the attribute is not already held by another mailbox
			    -- (so this cannot violate the (account_id, special_use) unique index).
			    special_use = COALESCE(mailboxes.special_use,
			        CASE WHEN EXCLUDED.special_use IS NULL
			              OR NOT EXISTS (SELECT 1 FROM mailboxes m2
			                             WHERE m2.account_id = mailboxes.account_id
			                               AND m2.special_use = EXCLUDED.special_use
			                               AND m2.deleted_at IS NULL)
			             THEN EXCLUDED.special_use END)
			RETURNING id
		`, AccountID, mailboxName, int64(uidValidity)).Scan(&mailboxID)

		if err != nil {
			return fmt.Errorf("failed to create or find default mailbox '%s': %w", mailboxName, err)
		}

		// Update the path for the mailbox. This is idempotent and safe to run even if the path exists.
		mailboxPath := helpers.GetMailboxPath("", mailboxID) // Default mailboxes are root level.
		_, err = tx.Exec(ctx, `UPDATE mailboxes SET path = $1 WHERE id = $2 AND (path = '' OR path IS NULL)`, mailboxPath, mailboxID)
		if err != nil {
			return fmt.Errorf("failed to update path for default mailbox '%s': %w", mailboxName, err)
		}

		// Default mailboxes are auto-subscribed. The subscriptions table (migration
		// 000046) is the authoritative store, so record the subscription here for
		// accounts provisioned after the migration (existing accounts were backfilled).
		_, err = tx.Exec(ctx, `
			INSERT INTO subscriptions (account_id, mailbox_name)
			VALUES ($1, $2)
			ON CONFLICT (account_id, LOWER(mailbox_name)) DO NOTHING
		`, AccountID, mailboxName)
		if err != nil {
			return fmt.Errorf("failed to subscribe default mailbox '%s': %w", mailboxName, err)
		}
	}
	return nil
}

type MailboxSummary struct {
	UIDNext           int64
	NumMessages       int
	TotalSize         int64
	HighestModSeq     uint64
	RecentCount       int
	UnseenCount       int
	FirstUnseenSeqNum uint32 // Sequence number of the first unseen message
}

func (d *Database) GetMailboxSummary(ctx context.Context, mailboxID int64) (*MailboxSummary, error) {
	start := time.Now()
	var err error
	defer func() {
		status := "success"
		if err != nil {
			if errors.Is(err, consts.ErrMailboxNotFound) {
				status = "not_found"
			} else {
				status = "error"
			}
		}
		metrics.DBQueryDuration.WithLabelValues("mailbox_summary", "read").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("mailbox_summary", status, "read").Inc()
	}()

	// This query is highly optimized to use the mailbox_stats cache table.
	// It avoids expensive COUNT/SUM operations on the large messages table.
	// No transaction needed - two simple SELECTs don't require transactional isolation.
	const summaryQuery = `
		SELECT
			mb.highest_uid + 1,
			COALESCE(ms.message_count, 0),
			COALESCE(ms.total_size, 0),
			COALESCE(ms.highest_modseq, 1),
			COALESCE(ms.unseen_count, 0)
		FROM mailboxes mb
		LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
		WHERE mb.id = $1
	`
	row := d.GetReadPoolWithContext(ctx).QueryRow(ctx, summaryQuery, mailboxID)

	var s MailboxSummary
	err = row.Scan(&s.UIDNext, &s.NumMessages, &s.TotalSize, &s.HighestModSeq, &s.UnseenCount)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Mailbox doesn't exist. Return a specific error so the caller can handle it.
			return nil, consts.ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to get mailbox summary stats: %w", err)
	}

	// FirstUnseenSeqNum computation is extremely expensive (O(N) count).
	// It has been extracted to GetFirstUnseenSeqNum() so that background STATUS
	// commands don't paralyze the DB connection pool.
	s.FirstUnseenSeqNum = 0

	return &s, nil
}

// GetFirstUnseenSeqNum performs the expensive O(N) count translation of the first unseen UID into a sequence number.
// This must only be called for IMAP SELECT/EXAMINE where the IMAP protocol mandates [UNSEEN <seq>].
func (d *Database) GetFirstUnseenSeqNum(ctx context.Context, mailboxID int64) (uint32, error) {
	var firstUnseenUID int64
	query := fmt.Sprintf(`
		SELECT m.uid FROM message_state ms
		JOIN messages m ON ms.message_id = m.id
		WHERE ms.mailbox_id = $1 AND (ms.flags & %d) = 0 AND m.expunged_at IS NULL
		ORDER BY ms.message_id ASC LIMIT 1
	`, FlagSeen)
	err := d.GetReadPoolWithContext(ctx).QueryRow(ctx, query, mailboxID).Scan(&firstUnseenUID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to fetch first unseen UID: %w", err)
	}

	var seqNum uint32
	err = d.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*) + 1 FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		  AND uid < $2
	`, mailboxID, firstUnseenUID).Scan(&seqNum)
	if err != nil {
		return 0, fmt.Errorf("failed to compute sequence number for UID %d: %w", firstUnseenUID, err)
	}
	return seqNum, nil
}

func (d *Database) GetMailboxSummariesBatch(ctx context.Context, mailboxIDs []int64) (map[int64]*MailboxSummary, error) {
	if len(mailboxIDs) == 0 {
		return map[int64]*MailboxSummary{}, nil
	}

	start := time.Now()
	var err error
	defer func() {
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.DBQueryDuration.WithLabelValues("mailbox_summary_batch", "read").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("mailbox_summary_batch", status, "read").Inc()
	}()

	// No transaction needed - single SELECT doesn't require transactional isolation
	const batchQuery = `
		SELECT
			mb.id,
			mb.highest_uid + 1,
			COALESCE(ms.message_count, 0),
			COALESCE(ms.total_size, 0),
			COALESCE(ms.highest_modseq, 1),
			COALESCE(ms.unseen_count, 0)
		FROM mailboxes mb
		LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
		WHERE mb.id = ANY($1)
	`
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, batchQuery, mailboxIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query batch mailbox summaries: %w", err)
	}
	defer rows.Close()

	result := make(map[int64]*MailboxSummary, len(mailboxIDs))
	for rows.Next() {
		var mailboxID int64
		var s MailboxSummary
		if err = rows.Scan(&mailboxID, &s.UIDNext, &s.NumMessages, &s.TotalSize, &s.HighestModSeq, &s.UnseenCount); err != nil {
			return nil, fmt.Errorf("failed to scan batch mailbox summary: %w", err)
		}
		result[mailboxID] = &s
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating batch mailbox summaries: %w", err)
	}

	return result, nil
}

// GetMailboxMessageCountAndSizeSum returns the count and total size of active messages in a mailbox.
// Used by POP3 STAT. Reads from the mailbox_stats cache (O(1)) — consistent with IMAP STATUS, which
// also serves counts from the cache (see GetMailboxSummary). The cache is kept accurate by the stats
// triggers; correctness does not depend on live counting here.
func (d *Database) GetMailboxMessageCountAndSizeSum(ctx context.Context, mailboxID int64) (int, int64, error) {
	var count int
	var size int64
	err := d.GetReadPoolWithContext(ctx).QueryRow(ctx,
		"SELECT message_count, total_size FROM mailbox_stats WHERE mailbox_id = $1",
		mailboxID).Scan(&count, &size)
	if err != nil {
		if err == pgx.ErrNoRows {
			// If no stats row exists (e.g., for a new or empty mailbox), return 0.
			return 0, 0, nil
		}
		return 0, 0, err
	}
	return count, size, nil
}

// SetMailboxSubscribed updates the subscription status of an existing mailbox by
// ID. Subscriptions are stored in the name-based `subscriptions` table (migration
// 000046) — this by-ID helper resolves the mailbox's name and writes there, so
// non-IMAP callers (admin/user API, importer) stay consistent with LSUB/LIST
// (SUBSCRIBED). Unsubscribing a default mailbox is ignored (defaults stay
// permanently subscribed).
func (db *Database) SetMailboxSubscribed(ctx context.Context, tx pgx.Tx, mailboxID int64, AccountID int64, subscribed bool) error {
	// First, check if the mailbox exists and belongs to the user.
	var mboxName string
	err := tx.QueryRow(ctx, "SELECT name FROM mailboxes WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL", mailboxID, AccountID).Scan(&mboxName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consts.ErrMailboxNotFound
		}
		return fmt.Errorf("failed to fetch mailbox %d for subscription update: %w", mailboxID, err)
	}

	// Prevent unsubscribing default mailboxes (they stay permanently subscribed).
	if !subscribed {
		for _, rootFolder := range consts.DefaultMailboxes {
			if strings.EqualFold(mboxName, rootFolder) {
				logger.Debug("Database: ignoring unsubscribe for default mailbox", "mailbox", mboxName)
				return nil
			}
		}
	}

	if subscribed {
		return db.Subscribe(ctx, tx, AccountID, mboxName)
	}
	return db.Unsubscribe(ctx, tx, AccountID, mboxName)
}

func (db *Database) RenameMailbox(ctx context.Context, tx pgx.Tx, mailboxID int64, AccountID int64, newName string, newParentID *int64) error {
	if newName == "" {
		return consts.ErrMailboxInvalidName
	}

	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(newName, "\t\r\n\x00") {
		logger.Error("Database: attempted to rename mailbox to name with invalid characters", "name", newName, "account_id", AccountID)
		return consts.ErrMailboxInvalidName
	}

	// Reject "." / ".." path segments to prevent maildir-export path traversal.
	if helpers.MailboxNameHasTraversal(newName) {
		logger.Error("Database: attempted to rename mailbox to name with path traversal segment", "name", newName, "account_id", AccountID)
		return consts.ErrMailboxInvalidName
	}

	// Check if user has admin permission (ACL 'a' right) for shared mailboxes
	// For personal mailboxes, ownership is sufficient
	var isShared bool
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(is_shared, FALSE)
		FROM mailboxes
		WHERE id = $1 AND (account_id = $2 OR COALESCE(is_shared, FALSE) = TRUE) AND deleted_at IS NULL
	`, mailboxID, AccountID).Scan(&isShared)
	if err != nil {
		if err == pgx.ErrNoRows {
			return consts.ErrMailboxNotFound
		}
		return fmt.Errorf("failed to fetch mailbox for rename: %w", err)
	}

	// If it's a shared mailbox, check ACL permissions
	if isShared {
		hasAdminRight, err := db.CheckMailboxPermission(ctx, mailboxID, AccountID, ACLRightAdmin)
		if err != nil {
			return fmt.Errorf("failed to check admin permission: %w", err)
		}
		if !hasAdminRight {
			return fmt.Errorf("permission denied: user does not have admin right on shared mailbox")
		}
	}

	// Check if the new name already exists within the same transaction to prevent race conditions.
	// Use case-insensitive comparison (LOWER on both sides) to match GetMailboxByName behavior
	// and prevent constraint violations from case-mismatched duplicates.
	// Exclude the mailbox being renamed (id != $3) to allow case-only renames (e.g., "amazon" → "Amazon").
	var existingID int64
	err = tx.QueryRow(ctx, "SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND id != $3 AND deleted_at IS NULL", AccountID, newName, mailboxID).Scan(&existingID)
	if err == nil {
		// A mailbox with the new name was found.
		return consts.ErrMailboxAlreadyExists
	} else if err != pgx.ErrNoRows {
		// An actual error occurred during the check.
		logger.Error("Database: failed to check for existing mailbox", "name", newName, "err", err)
		return consts.ErrInternalError
	}
	// If err is pgx.ErrNoRows, we can proceed.

	// Fetch the mailbox to be moved to get its current state (oldName, oldPath).
	// Lock this row to prevent other operations on it.
	var oldName, oldPath string
	err = tx.QueryRow(ctx, `
		SELECT name, path FROM mailboxes WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL FOR UPDATE
	`, mailboxID, AccountID).Scan(&oldName, &oldPath)
	if err != nil {
		if err == pgx.ErrNoRows {
			return consts.ErrMailboxNotFound
		}
		logger.Error("Database: failed to fetch and lock mailbox to rename", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
	}

	// Validate mailbox path is not empty (data corruption check)
	// An empty path would cause the child UPDATE query to match ALL mailboxes,
	// leading to constraint violations. See production bug 2026-02-10.
	if oldPath == "" {
		logger.Error("Database: mailbox has empty path (data corruption)", "mailbox_id", mailboxID, "name", oldName)
		return fmt.Errorf("mailbox has invalid empty path (data corruption)")
	}

	// Separately, check if the mailbox has children. This avoids using GROUP BY with FOR UPDATE.
	// Use owner's account_id for accurate child count (important for shared mailboxes)
	var hasChildren bool
	var ownerAccountID int64
	err = tx.QueryRow(ctx, `
		SELECT account_id FROM mailboxes WHERE id = $1
	`, mailboxID).Scan(&ownerAccountID)
	if err != nil {
		logger.Error("Database: failed to get mailbox owner", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
	}

	err = tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND path LIKE $2 || '%' AND path != $2 AND deleted_at IS NULL)
	`, ownerAccountID, oldPath).Scan(&hasChildren)
	if err != nil {
		logger.Error("Database: failed to check for children of mailbox", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
	}

	// Determine the path of the new parent.
	var newParentPath string
	if newParentID != nil {
		// A mailbox cannot be its own parent.
		if *newParentID == mailboxID {
			return fmt.Errorf("mailbox %d cannot be its own parent", mailboxID)
		}

		// Lock the parent row as well to prevent it from being deleted/moved during this transaction.
		err = tx.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL FOR UPDATE", *newParentID, AccountID).Scan(&newParentPath)
		if err != nil {
			if err == pgx.ErrNoRows {
				logger.Error("Database: new parent mailbox not found for rename", "parent_id", *newParentID)
				return consts.ErrMailboxNotFound
			}
			logger.Error("Database: failed to fetch new parent path", "parent_id", *newParentID, "err", err)
			return consts.ErrInternalError
		}

		// Also, a mailbox cannot be moved into one of its own children.
		// The new parent's path cannot start with the old path of the mailbox being moved.
		if strings.HasPrefix(newParentPath, oldPath) {
			return fmt.Errorf("cannot move mailbox %d into one of its own sub-mailboxes", mailboxID)
		}
	}
	// If newParentID is nil, newParentPath remains empty, which is correct for a top-level mailbox.

	// Construct the new path
	newPath := helpers.GetMailboxPath(newParentPath, mailboxID)

	// Before updating, check if any child would conflict with existing mailboxes
	if hasChildren {
		delimiter := string(consts.MailboxDelimiter)
		oldPrefix := oldName + delimiter
		newPrefix := newName + delimiter

		// Check if any child's new name would conflict with an existing mailbox
		var conflictCount int
		err = tx.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM mailboxes existing
			WHERE existing.account_id = $1
			  AND existing.deleted_at IS NULL
			  AND EXISTS (
				SELECT 1 FROM mailboxes child
				WHERE child.account_id = $1
				  AND child.path LIKE $2 || '%'
				  AND child.path != $2
				  AND child.deleted_at IS NULL
				  AND existing.name = $3 || SUBSTRING(child.name FROM LENGTH($4) + 1)
			  )
		`, ownerAccountID, oldPath, newPrefix, oldPrefix).Scan(&conflictCount)
		if err != nil {
			logger.Error("Database: failed to check for conflicting child names", "mailbox_id", mailboxID, "err", err)
			return consts.ErrInternalError
		}
		if conflictCount > 0 {
			logger.Error("Database: rename would create conflicting child names", "mailbox_id", mailboxID, "old_name", oldName, "new_name", newName, "conflicts", conflictCount)
			return fmt.Errorf("rename would create conflicting mailbox names (%d conflicts)", conflictCount)
		}
	}

	// Update the target mailbox itself.
	_, err = tx.Exec(ctx, `
		UPDATE mailboxes
		SET name = $1, path = $2, updated_at = now()
		WHERE id = $3
	`, newName, newPath, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to update target mailbox %d: %w", mailboxID, err)
	}

	// Now, update all children of the renamed mailbox if it has any.
	if hasChildren {
		delimiter := string(consts.MailboxDelimiter)
		oldPrefix := oldName + delimiter
		newPrefix := newName + delimiter

		// The path of children only changes if the mailbox is moved to a new parent. For a simple
		// rename, only the 'name' of the children needs to be updated. We use concatenation with
		// SUBSTRING to only replace the prefix, which is safer than a global REPLACE.
		_, err = tx.Exec(ctx, `
			UPDATE mailboxes
			SET
				name = $1 || SUBSTRING(name FROM LENGTH($2) + 1),
				path = CASE
					WHEN $3 != $4 THEN $3 || SUBSTRING(path FROM LENGTH($4) + 1)
					ELSE path
				END,
				updated_at = now()
			WHERE
				account_id = $5 AND
				path LIKE $4 || '%' AND path != $4
		`, newPrefix, oldPrefix, newPath, oldPath, ownerAccountID)

		if err != nil {
			return fmt.Errorf("failed to update child mailboxes: %w", err)
		}

	}

	// Keep the denormalized messages.mailbox_path in sync with the new name(s).
	// This column stores the mailbox NAME and is used by RestoreMessages to route
	// expunged messages back to a mailbox by that name; leaving it pointing at the
	// pre-rename name would resurrect a mailbox under the old name on restore.
	// After the updates above, the renamed mailbox and all of its descendants are
	// exactly the mailboxes whose path is prefixed by newPath (true for both a
	// simple rename, where newPath == oldPath, and a move, where descendant paths
	// were re-prefixed to newPath), so set each affected message's mailbox_path to
	// its mailbox's current name. Expunged rows are included on purpose — they are
	// precisely what RestoreMessages reads. Only mailbox_path changes, so the
	// per-statement stats trigger (which keys on mailbox_id/expunged_at) is a no-op.
	_, err = tx.Exec(ctx, `
		UPDATE messages m
		SET mailbox_path = mb.name
		FROM mailboxes mb
		WHERE m.mailbox_id = mb.id
		  AND mb.account_id = $1
		  AND mb.path LIKE $2 || '%'
		  AND m.mailbox_path IS DISTINCT FROM mb.name
	`, ownerAccountID, newPath)
	if err != nil {
		return fmt.Errorf("failed to sync message mailbox_path after rename of mailbox %d: %w", mailboxID, err)
	}

	// Move the subscription (and its descendants) in the SAME transaction as the
	// rename, so a crash can't leave the mailbox renamed but the subscription
	// orphaned under the old name. Scoped to this account — the common personal
	// rename (owner == subscriber) is fully atomic; moving every accessing user's
	// subscription for a shared-mailbox rename is a separate concern.
	if err := db.RenameSubscriptions(ctx, tx, AccountID, oldName, newName, string(consts.MailboxDelimiter)); err != nil {
		return fmt.Errorf("failed to move subscriptions during rename of mailbox %d: %w", mailboxID, err)
	}

	return nil
}
