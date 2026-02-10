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
	// Modified query to include both personal mailboxes and shared mailboxes with ACL access
	query := `
		SELECT DISTINCT
			m.id, m.name, m.uid_validity, m.path, m.subscribed, m.created_at, m.updated_at, m.account_id,
			EXISTS(SELECT 1 FROM mailboxes child WHERE child.account_id = m.account_id AND LENGTH(child.path) = LENGTH(m.path) + 16 AND child.path LIKE m.path || '%') AS has_children
		FROM mailboxes m
		LEFT JOIN mailbox_acls acl ON m.id = acl.mailbox_id AND acl.account_id = $1
		WHERE
			-- All mailboxes owned by user (including shared mailboxes they created)
			m.account_id = $1
			OR
			-- Shared mailboxes where user has direct ACL access (must have at least 'l' lookup right)
			(COALESCE(m.is_shared, FALSE) = TRUE AND acl.account_id IS NOT NULL AND position('l' IN acl.rights) > 0)
			OR
			-- Shared mailboxes with "anyone" access (same domain, must have 'l' right)
			(COALESCE(m.is_shared, FALSE) = TRUE
			 AND EXISTS (
			   SELECT 1 FROM mailbox_acls a2
			   INNER JOIN credentials c ON c.account_id = $1 AND c.primary_identity = TRUE
			   WHERE a2.mailbox_id = m.id
			     AND a2.identifier = 'anyone'
			     AND position('l' IN a2.rights) > 0
			     AND m.owner_domain = SPLIT_PART(c.address, '@', 2)
			 ))
	`

	if subscribed {
		query += " AND m.subscribed = TRUE"
	}

	// Add a consistent ordering
	query += " ORDER BY m.name"

	// Prepare the query to fetch all mailboxes for the given user
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, AccountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Collect the mailboxes
	var mailboxes []*DBMailbox
	for rows.Next() {
		var mailbox DBMailbox
		var uidValidityInt64 int64

		if err := rows.Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.CreatedAt, &mailbox.UpdatedAt, &mailbox.AccountID, &mailbox.HasChildren); err != nil {
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

// GetMailbox fetches the mailbox
func (db *Database) GetMailbox(ctx context.Context, mailboxID int64, AccountID int64) (*DBMailbox, error) {
	var mailbox DBMailbox
	var uidValidityInt64 int64

	// First, fetch the core mailbox details.
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT id, name, uid_validity, path, subscribed, created_at, updated_at, account_id
		FROM mailboxes
		WHERE id = $1 AND account_id = $2
	`, mailboxID, AccountID).Scan(
		&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.CreatedAt, &mailbox.UpdatedAt, &mailbox.AccountID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to fetch mailbox %d: %w", mailboxID, err)
	}

	mailbox.UIDValidity = uint32(uidValidityInt64)

	// Separately, check if the mailbox has children using an efficient EXISTS query.
	// For shared mailboxes, check using the owner's account_id to get accurate child count
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND LENGTH(path) = LENGTH($2) + 16 AND path LIKE $2 || '%')
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

	// First try to find owned mailbox, then check for shared mailbox with ACL access
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT m.id, m.name, m.uid_validity, m.path, m.subscribed, m.created_at, m.updated_at, m.account_id
		FROM mailboxes m
		LEFT JOIN mailbox_acls acl ON m.id = acl.mailbox_id AND acl.account_id = $1
		WHERE LOWER(m.name) = $2
		  AND (
		    -- Owned mailbox (shared or non-shared, owner always has access)
		    (m.account_id = $1)
		    OR
		    -- Shared mailbox with ACL access (has 'l' right)
		    (COALESCE(m.is_shared, FALSE) = TRUE AND acl.account_id IS NOT NULL AND position('l' IN acl.rights) > 0)
		    OR
		    -- Shared mailbox with "anyone" access (same domain, has 'l' right)
		    (COALESCE(m.is_shared, FALSE) = TRUE
		     AND EXISTS (
		       SELECT 1 FROM mailbox_acls a2
		       INNER JOIN credentials c ON c.account_id = $1 AND c.primary_identity = TRUE
		       WHERE a2.mailbox_id = m.id
		         AND a2.identifier = 'anyone'
		         AND position('l' IN a2.rights) > 0
		         AND m.owner_domain = SPLIT_PART(c.address, '@', 2)
		     ))
		  )
		LIMIT 1
	`, AccountID, strings.ToLower(name)).Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.CreatedAt, &mailbox.UpdatedAt, &accountID)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		logger.Error("Database: failed to find mailbox", "name", name, "err", err)
		return nil, consts.ErrInternalError
	}

	mailbox.UIDValidity = uint32(uidValidityInt64)
	mailbox.AccountID = accountID

	// Separately, check if the mailbox has children using an efficient EXISTS query.
	// For shared mailboxes, check using the owner's account_id to get accurate child count
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND LENGTH(path) = LENGTH($2) + 16 AND path LIKE $2 || '%')
	`, accountID, mailbox.Path).Scan(&mailbox.HasChildren)
	if err != nil {
		logger.Error("Database: failed to check for children of mailbox", "name", name, "err", err)
		return nil, consts.ErrInternalError
	}

	return &mailbox, nil
}

func (db *Database) CreateMailbox(ctx context.Context, tx pgx.Tx, AccountID int64, name string, parentID *int64) error {
	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(name, "\t\r\n\x00") {
		logger.Error("Database: attempted to create mailbox with invalid characters", "name", name, "account_id", AccountID)
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
			SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2
		`, *parentID, AccountID).Scan(&parentPath)

		if err != nil {
			if err == pgx.ErrNoRows {
				return consts.ErrMailboxNotFound
			}
			return fmt.Errorf("failed to fetch parent mailbox: %w", err)
		}
	}

	// Insert the mailbox with shared mailbox fields
	var mailboxID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path, is_shared, owner_domain)
		VALUES ($1, $2, $3, $4, '', $5, $6)
		RETURNING id
	`, AccountID, name, int64(uidValidity), false, isShared, ownerDomain).Scan(&mailboxID)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23505": // Unique constraint violation
				logger.Warn("Database: mailbox already exists", "name", name, "account_id", AccountID)
				return consts.ErrDBUniqueViolation
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_account_id_fkey" {
					logger.Error("Database: user does not exist", "account_id", AccountID)
					return consts.ErrDBNotFound
				}
			}
		}
		return fmt.Errorf("failed to create mailbox: %v", err)
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

func (db *Database) CreateDefaultMailbox(ctx context.Context, tx pgx.Tx, AccountID int64, name string, parentID *int64) error {
	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(name, "\t\r\n\x00") {
		logger.Error("Database: attempted to create default mailbox with invalid characters", "name", name, "account_id", AccountID)
		return consts.ErrMailboxInvalidName
	}

	// Start a transaction
	// Use nanoseconds to significantly reduce the chance of collision on rapid creation.
	uidValidity := uint32(time.Now().UnixNano())

	// Determine the parent path if parentID is provided
	var parentPath string
	if parentID != nil {
		// Fetch the parent mailbox to get its path
		err := tx.QueryRow(ctx, `
			SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2
		`, *parentID, AccountID).Scan(&parentPath)

		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("failed to create default mailbox: parent mailbox with ID %d not found: %w", *parentID, consts.ErrMailboxNotFound)
			}
			return fmt.Errorf("failed to fetch parent mailbox for default creation: %w", err)
		}
	}

	// Try to insert the mailbox into the database
	var mailboxID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, $2, $3, $4, '')
		ON CONFLICT (account_id, name) DO NOTHING
		RETURNING id
	`, AccountID, name, int64(uidValidity), true).Scan(&mailboxID)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_account_id_fkey" {
					logger.Error("Database: user does not exist", "account_id", AccountID)
					return consts.ErrDBNotFound
				}
			}
		}

		// If the mailbox already exists (no rows returned), fetch its ID
		if err == pgx.ErrNoRows {
			err := tx.QueryRow(ctx, `
				SELECT id FROM mailboxes 
				WHERE account_id = $1 AND name = $2
			`, AccountID, name).Scan(&mailboxID)

			if err != nil {
				return fmt.Errorf("failed to get existing mailbox ID: %w", err)
			}
		} else {
			return fmt.Errorf("failed to create mailbox: %v", err)
		}
	}

	// Only update the path if we got a valid mailbox ID
	if mailboxID > 0 {
		// Update the path
		mailboxPath := helpers.GetMailboxPath(parentPath, mailboxID)
		_, err := tx.Exec(ctx, `
			UPDATE mailboxes SET path = $1 WHERE id = $2 AND (path = '' OR path IS NULL)
		`, mailboxPath, mailboxID)

		if err != nil {
			return fmt.Errorf("failed to update mailbox path: %w", err)
		}
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

	// Acquire locks in a deterministic order.
	if len(mailboxesToDelete) > 0 {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(id) FROM unnest($1::bigint[]) AS id", mailboxesToDelete); err != nil {
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

func (db *Database) CreateDefaultMailboxes(ctx context.Context, tx pgx.Tx, AccountID int64) error {
	// OPTIMIZATION: Early exit if INBOX already exists
	// This avoids 5 INSERT attempts on every LMTP delivery when mailboxes already exist
	var inboxExists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND name = 'INBOX')
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
			INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path) VALUES ($1, $2, $3, TRUE, '')
			ON CONFLICT (account_id, name) DO UPDATE
			SET subscribed = TRUE -- Ensure default mailboxes are always subscribed
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

	tx, err := d.GetReadPoolWithContext(ctx).BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// This query is highly optimized to use the mailbox_stats cache table.
	// It avoids expensive COUNT/SUM operations on the large messages table.
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
	row := tx.QueryRow(ctx, summaryQuery, mailboxID)

	var s MailboxSummary
	err = row.Scan(&s.UIDNext, &s.NumMessages, &s.TotalSize, &s.HighestModSeq, &s.UnseenCount)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Mailbox doesn't exist. Return a specific error so the caller can handle it.
			return nil, consts.ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to get mailbox summary stats: %w", err)
	}

	// If we have unseen messages, find the first unseen sequence number in the same transaction
	if s.UnseenCount > 0 {
		// With the message_sequences cache, we can directly look up the sequence number
		// of the first unseen message in a single, efficient query.
		err = tx.QueryRow(ctx, `
			SELECT ms.seqnum FROM messages m
			JOIN message_sequences ms ON m.mailbox_id = ms.mailbox_id AND m.uid = ms.uid
			WHERE m.mailbox_id = $1 AND (m.flags & $2) = 0
			ORDER BY ms.seqnum LIMIT 1
		`, mailboxID, FlagSeen).Scan(&s.FirstUnseenSeqNum)

		if err != nil && err != pgx.ErrNoRows {
			logger.Error("Database: failed to get first unseen sequence number", "mailbox_id", mailboxID, "err", err)
			s.FirstUnseenSeqNum = 0 // Default to 0 on failure
		}
	} else {
		// No unseen messages
		s.FirstUnseenSeqNum = 0
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit GetMailboxSummary transaction: %w", err)
	}

	return &s, nil
}

func (d *Database) GetMailboxMessageCountAndSizeSum(ctx context.Context, mailboxID int64) (int, int64, error) {
	var count int
	var size int64
	// This query is optimized to use the mailbox_stats cache table.
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

// SetSubscribed updates the subscription status of a mailbox, but ignores unsubscribing for root folders.
func (db *Database) SetMailboxSubscribed(ctx context.Context, tx pgx.Tx, mailboxID int64, AccountID int64, subscribed bool) error {
	// First, check if the mailbox exists and belongs to the user.
	var mboxName string
	err := tx.QueryRow(ctx, "SELECT name FROM mailboxes WHERE id = $1 AND account_id = $2", mailboxID, AccountID).Scan(&mboxName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consts.ErrMailboxNotFound
		}
		return fmt.Errorf("failed to fetch mailbox %d for subscription update: %w", mailboxID, err)
	}

	// Prevent subscription changes for default mailboxes.
	for _, rootFolder := range consts.DefaultMailboxes {
		if strings.EqualFold(mboxName, rootFolder) {
			logger.Debug("Database: ignoring subscription status update for root folder", "mailbox", mboxName)
			return nil
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE mailboxes SET subscribed = $1, updated_at = now() WHERE id = $2 AND account_id = $3
	`, subscribed, mailboxID, AccountID)
	if err != nil {
		return fmt.Errorf("failed to update subscription status for mailbox %d: %v", mailboxID, err)
	}

	return nil
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

	// Check if user has admin permission (ACL 'a' right) for shared mailboxes
	// For personal mailboxes, ownership is sufficient
	var isShared bool
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(is_shared, FALSE)
		FROM mailboxes
		WHERE id = $1 AND (account_id = $2 OR COALESCE(is_shared, FALSE) = TRUE)
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
	// Use case-sensitive comparison to match the unique constraint
	var existingID int64
	err = tx.QueryRow(ctx, "SELECT id FROM mailboxes WHERE account_id = $1 AND name = $2", AccountID, newName).Scan(&existingID)
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
		SELECT name, path FROM mailboxes WHERE id = $1 AND account_id = $2 FOR UPDATE
	`, mailboxID, AccountID).Scan(&oldName, &oldPath)
	if err != nil {
		if err == pgx.ErrNoRows {
			return consts.ErrMailboxNotFound
		}
		logger.Error("Database: failed to fetch and lock mailbox to rename", "mailbox_id", mailboxID, "err", err)
		return consts.ErrInternalError
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
		SELECT EXISTS(SELECT 1 FROM mailboxes WHERE account_id = $1 AND path LIKE $2 || '%' AND path != $2)
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
		err = tx.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2 FOR UPDATE", *newParentID, AccountID).Scan(&newParentPath)
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
			  AND EXISTS (
				SELECT 1 FROM mailboxes child
				WHERE child.account_id = $1
				  AND child.path LIKE $2 || '%'
				  AND child.path != $2
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

	return nil
}
