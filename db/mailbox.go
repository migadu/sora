package db

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// DBMailbox represents the database structure of a mailbox
type DBMailbox struct {
	ID          int64
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

func (db *Database) GetMailboxes(ctx context.Context, userID int64, subscribed bool) ([]*DBMailbox, error) {
	query := `
		SELECT 
			id, 
			name, 
			uid_validity, 
			path,  
			subscribed, 
			EXISTS (SELECT 1 FROM mailboxes AS child WHERE child.path LIKE m.path || '%' AND child.path != m.path) AS has_children,
			created_at,
			updated_at
		FROM 
			mailboxes m 
		WHERE 
			account_id = $1`

	if subscribed {
		query += " AND m.subscribed = TRUE"
	}

	// Prepare the query to fetch all mailboxes for the given user
	rows, err := db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Collect the mailboxes
	var mailboxes []*DBMailbox
	for rows.Next() {
		var mailboxID int64
		var mailboxName string
		var hasChildren bool
		var uidValidityInt64 int64
		var path string
		var subscribed bool
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&mailboxID, &mailboxName, &uidValidityInt64, &path, &subscribed, &hasChildren, &createdAt, &updatedAt); err != nil {
			return nil, err
		}

		mailbox := NewDBMailbox(mailboxID, mailboxName, uint32(uidValidityInt64), path, subscribed, hasChildren, createdAt, updatedAt)
		mailboxes = append(mailboxes, &mailbox)
	}

	// Check for any error that occurred during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return mailboxes, nil
}

// GetMailbox fetches the mailbox
func (db *Database) GetMailbox(ctx context.Context, mailboxID int64, userID int64) (*DBMailbox, error) {
	var mailboxName string
	var hasChildren bool
	var uidValidityInt64 int64
	var subscribed bool
	var path string
	var createdAt, updatedAt time.Time

	err := db.Pool.QueryRow(ctx, `
		SELECT 
			id, name, uid_validity, path, subscribed,
			EXISTS (
				SELECT 1
				FROM mailboxes AS child
				WHERE child.path LIKE m.path || '%' AND child.path != m.path
			) AS has_children,
			created_at, updated_at
		FROM mailboxes m
		WHERE id = $1 AND account_id = $2
	`, mailboxID, userID).Scan(&mailboxID, &mailboxName, &uidValidityInt64, &path, &subscribed, &hasChildren, &createdAt, &updatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, err
	}

	mailbox := NewDBMailbox(mailboxID, mailboxName, uint32(uidValidityInt64), path, subscribed, hasChildren, createdAt, updatedAt)
	return &mailbox, nil
}

// GetMailboxByName fetches the mailbox for a specific user by name
func (db *Database) GetMailboxByName(ctx context.Context, userID int64, name string) (*DBMailbox, error) {
	var mailbox DBMailbox

	var uidValidityInt64 int64
	err := db.Pool.QueryRow(ctx, `
		SELECT
			id, name, uid_validity, path, subscribed,
			EXISTS (SELECT 1 FROM mailboxes AS child WHERE child.path LIKE m.path || '%' AND child.path != m.path) AS has_children,
			created_at, updated_at
		FROM mailboxes m
		WHERE account_id = $1 AND LOWER(name) = $2
	`, userID, strings.ToLower(name)).Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.Path, &mailbox.Subscribed, &mailbox.HasChildren, &mailbox.CreatedAt, &mailbox.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		log.Printf("[DB] failed to find mailbox '%s': %v", name, err)
		return nil, consts.ErrInternalError
	}

	mailbox.UIDValidity = uint32(uidValidityInt64)
	return &mailbox, nil
}

func (db *Database) CreateMailbox(ctx context.Context, userID int64, name string, parentID *int64) error {
	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(name, "\t\r\n\x00") {
		log.Printf("[DB] ERROR: attempted to create mailbox with invalid characters: %q for user %d", name, userID)
		return consts.ErrMailboxInvalidName
	}
	
	// Start a transaction
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Avoid low uid_validity which may cause issues with some IMAP clients
	uidValidity := uint32(time.Now().Unix())

	// Determine the parent path if parentID is provided
	var parentPath string
	if parentID != nil {
		// Fetch the parent mailbox to get its path
		err := tx.QueryRow(ctx, `
			SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2
		`, *parentID, userID).Scan(&parentPath)

		if err != nil {
			if err == pgx.ErrNoRows {
				return consts.ErrMailboxNotFound
			}
			return fmt.Errorf("failed to fetch parent mailbox: %w", err)
		}
	}

	// Insert the mailbox
	var mailboxID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, $2, $3, $4, '')
		RETURNING id
	`, userID, name, int64(uidValidity), false).Scan(&mailboxID)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23505": // Unique constraint violation
				log.Printf("[DB] WARNING: mailbox named '%s' already exists for user %d", name, userID)
				return consts.ErrDBUniqueViolation
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_account_id_fkey" {
					log.Printf("[DB] ERROR: user with ID %d does not exist", userID)
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

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (db *Database) CreateDefaultMailbox(ctx context.Context, userID int64, name string, parentID *int64) error {
	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(name, "\t\r\n\x00") {
		log.Printf("[DB] ERROR: attempted to create default mailbox with invalid characters: %q for user %d", name, userID)
		return consts.ErrMailboxInvalidName
	}
	
	// Start a transaction
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	uidValidity := uint32(time.Now().Unix())

	// Determine the parent path if parentID is provided
	var parentPath string
	if parentID != nil {
		// Fetch the parent mailbox to get its path
		err := tx.QueryRow(ctx, `
			SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2
		`, *parentID, userID).Scan(&parentPath)

		if err != nil && err != pgx.ErrNoRows {
			return fmt.Errorf("failed to fetch parent mailbox: %w", err)
		}
	}

	// Try to insert the mailbox into the database
	var mailboxID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, $2, $3, $4, '')
		ON CONFLICT (account_id, name) DO NOTHING
		RETURNING id
	`, userID, name, int64(uidValidity), true).Scan(&mailboxID)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_account_id_fkey" {
					log.Printf("[DB] user with ID %d does not exist", userID)
					return consts.ErrDBNotFound
				}
			}
		}

		// If the mailbox already exists (no rows returned), fetch its ID
		if err == pgx.ErrNoRows {
			err := tx.QueryRow(ctx, `
				SELECT id FROM mailboxes 
				WHERE account_id = $1 AND name = $2
			`, userID, name).Scan(&mailboxID)

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
		_, err = tx.Exec(ctx, `
			UPDATE mailboxes SET path = $1 WHERE id = $2 AND (path = '' OR path IS NULL)
		`, mailboxPath, mailboxID)

		if err != nil {
			return fmt.Errorf("failed to update mailbox path: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteMailbox deletes a mailbox for a specific user by id
func (db *Database) DeleteMailbox(ctx context.Context, mailboxID int64, userID int64) error {
	mbox, err := db.GetMailbox(ctx, mailboxID, userID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to fetch mailbox %d: %v", mailboxID, err)
		return consts.ErrMailboxNotFound
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("[DB] ERROR: failed to begin transaction: %v", err)
		return consts.ErrInternalError
	}
	defer tx.Rollback(ctx) // Ensure the transaction is rolled back if an error occurs

	// Update messages that belong to this mailbox
	_, err = tx.Exec(ctx, `
		UPDATE messages SET 
			mailbox_path = $1 
		WHERE mailbox_id = $2`, mbox.Name, mailboxID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to set path on messages of folder %d : %v", mailboxID, err)
		return consts.ErrInternalError
	}

	// Get all child mailbox IDs to update their messages too
	var childMailboxIDs []int64
	rows, err := tx.Query(ctx, `
		SELECT id FROM mailboxes 
		WHERE account_id = $1 AND path LIKE $2 || '%' AND id != $3
	`, userID, mbox.Path, mailboxID)

	if err != nil {
		log.Printf("[DB] ERROR: failed to fetch child mailboxes: %v", err)
		return consts.ErrInternalError
	}

	for rows.Next() {
		var childID int64
		if err := rows.Scan(&childID); err != nil {
			rows.Close()
			return fmt.Errorf("error scanning child mailbox ID: %w", err)
		}
		childMailboxIDs = append(childMailboxIDs, childID)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating child mailboxes: %w", err)
	}

	// Update messages for all child mailboxes
	for _, childID := range childMailboxIDs {
		var childName string
		err := tx.QueryRow(ctx, `
			SELECT name FROM mailboxes WHERE id = $1
		`, childID).Scan(&childName)

		if err != nil {
			log.Printf("[DB] ERROR: failed to get child mailbox %d name: %v", childID, err)
			continue
		}

		_, err = tx.Exec(ctx, `
			UPDATE messages SET mailbox_path = $1 WHERE mailbox_id = $2
		`, childName, childID)

		if err != nil {
			log.Printf("[DB] ERROR: failed to update messages for child mailbox %d: %v", childID, err)
		}
	}

	// Delete the mailbox and all its children in one query using path-based approach
	result, err := tx.Exec(ctx, `
		DELETE FROM mailboxes 
		WHERE account_id = $1 AND (id = $2 OR path LIKE $3 || '%')
	`, userID, mailboxID, mbox.Path)

	if err != nil {
		log.Printf("[DB] ERROR: failed to delete mailbox %d and its children: %v", mailboxID, err)
		return consts.ErrInternalError
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("[DB] ERROR: mailbox %d not found for deletion", mailboxID)
		return consts.ErrInternalError
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[DB] ERROR: failed to commit transaction: %v\n", err)
		return consts.ErrInternalError
	}

	return nil
}

func (db *Database) CreateDefaultMailboxes(ctx context.Context, userId int64) error {
	for _, mailboxName := range consts.DefaultMailboxes {
		_, err := db.GetMailboxByName(ctx, userId, mailboxName)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				err := db.CreateDefaultMailbox(ctx, userId, mailboxName, nil)
				if err != nil {
					log.Printf("[DB] ERROR: failed to create mailbox %s for user %d: %v\n", mailboxName, userId, err)
					return consts.ErrInternalError
				}
				continue
			}
			log.Printf("[DB] ERROR: failed to get mailbox %s: %v", mailboxName, err)
			return consts.ErrInternalError
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
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `
		SELECT
			mb.highest_uid + 1 AS uid_next,
			COALESCE(COUNT(m.uid) FILTER (WHERE m.expunged_at IS NULL), 0) AS num_messages,
			COALESCE(SUM(m.size) FILTER (WHERE m.expunged_at IS NULL), 0) AS total_size,
			(
				SELECT COALESCE(MAX(GREATEST(m_mod.created_modseq, COALESCE(m_mod.updated_modseq, 0), COALESCE(m_mod.expunged_modseq, 0))), 1)
				FROM messages m_mod
				WHERE m_mod.mailbox_id = $1
			) AS highest_modseq,
			COALESCE(COUNT(m.uid) FILTER (WHERE (m.flags & $2) = 0 AND m.expunged_at IS NULL), 0) AS unseen_count -- $2 is FlagSeen
		FROM mailboxes mb
		LEFT JOIN messages m ON m.mailbox_id = mb.id
		WHERE mb.id = $1
		GROUP BY mb.id, mb.highest_uid;
	`
	row := tx.QueryRow(ctx, query, mailboxID, FlagSeen)

	var s MailboxSummary
	err = row.Scan(&s.UIDNext, &s.NumMessages, &s.TotalSize, &s.HighestModSeq, &s.UnseenCount)

	// If we have unseen messages, find the first unseen sequence number in the same transaction
	if s.UnseenCount > 0 {
		firstUnseenQuery := `
			WITH numbered_messages AS (
				SELECT 
					uid,
					flags,
					row_number() OVER (ORDER BY uid) AS seqnum
				FROM messages
				WHERE mailbox_id = $1 AND expunged_at IS NULL
			)
			SELECT seqnum
			FROM numbered_messages
			WHERE (flags & $2) = 0  -- Where \Seen flag is not set
			ORDER BY seqnum
			LIMIT 1
		`
		err = tx.QueryRow(ctx, firstUnseenQuery, mailboxID, FlagSeen).Scan(&s.FirstUnseenSeqNum)
		if err != nil {
			if err == pgx.ErrNoRows {
				// Shouldn't happen since we have a positive unseen count, but handle it anyway
				s.FirstUnseenSeqNum = 0
			} else {
				log.Printf("[DB] ERROR: failed to get first unseen sequence number: %v", err)
				// Continue with FirstUnseenSeqNum = 0, it's not critical enough to fail the whole operation
				s.FirstUnseenSeqNum = 0
			}
		}
	} else {
		// No unseen messages
		s.FirstUnseenSeqNum = 0
	}
	if err != nil {
		return nil, fmt.Errorf("GetMailboxSummary: %w", err)
	}

	// Double-check the message count with a separate query
	var countCheck int
	countQuery := `
		SELECT COUNT(*) 
		FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL
	`
	err = tx.QueryRow(ctx, countQuery, mailboxID).Scan(&countCheck)

	if err != nil {
		log.Printf("[DB] ERROR: count check failed for mailbox %d: %v", mailboxID, err)
	} else if countCheck != s.NumMessages {
		log.Printf("[DB] WARNING: count mismatch for mailbox %d. Summary reports %d messages, count check reports %d",
			mailboxID, s.NumMessages, countCheck)
		// Use the count check value as it's more reliable
		s.NumMessages = countCheck
	}
	return &s, nil
}

func (d *Database) GetMailboxMessageCountAndSizeSum(ctx context.Context, mailboxID int64) (int, int64, error) {
	var count int
	var size int64
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&count, &size)
	if err != nil {
		return 0, 0, err
	}
	return count, size, nil
}

// SetSubscribed updates the subscription status of a mailbox, but ignores unsubscribing for root folders.
func (db *Database) SetMailboxSubscribed(ctx context.Context, mailboxID int64, userID int64, subscribed bool) error {
	// Update the subscription status only if the mailbox is not a root folder
	mailbox, err := db.GetMailbox(ctx, mailboxID, userID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to fetch mailbox %d: %v", mailboxID, err)
		return consts.ErrMailboxNotFound
	}
	// Check if this is a root folder based on path length (8 chars = root)
	if len(mailbox.Path) == 8 {
		for _, rootFolder := range consts.DefaultMailboxes {
			if strings.EqualFold(mailbox.Name, rootFolder) {
				log.Printf("[DB] WARNING: ignoring subscription status update for root folder %s", mailbox.Name)
				return nil
			}
		}
	}

	_, err = db.Pool.Exec(ctx, `
		UPDATE mailboxes SET subscribed = $1, updated_at = now() WHERE id = $2
	`, subscribed, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to update subscription status for mailbox %d: %v", mailboxID, err)
	}

	return nil
}

func (db *Database) RenameMailbox(ctx context.Context, mailboxID int64, userID int64, newName string, newParentID *int64) error {
	if newName == "" {
		return consts.ErrMailboxInvalidName
	}
	
	// Validate mailbox name doesn't contain problematic characters
	if strings.ContainsAny(newName, "\t\r\n\x00") {
		log.Printf("[DB] ERROR: attempted to rename mailbox to name with invalid characters: %q for user %d", newName, userID)
		return consts.ErrMailboxInvalidName
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("[DB] ERROR: failed to begin transaction for rename: %v", err)
		return consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	// Check if the new name already exists within the same transaction to prevent race conditions.
	var existingID int64
	err = tx.QueryRow(ctx, "SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = $2", userID, strings.ToLower(newName)).Scan(&existingID)
	if err == nil {
		// A mailbox with the new name was found.
		return consts.ErrMailboxAlreadyExists
	} else if err != pgx.ErrNoRows {
		// An actual error occurred during the check.
		log.Printf("[DB] ERROR: failed to check for existing mailbox with name '%s': %v", newName, err)
		return consts.ErrInternalError
	}
	// If err is pgx.ErrNoRows, we can proceed.

	// Fetch the mailbox to be moved to get its current state (oldName, oldPath).
	// Lock this row to prevent other operations on it.
	var oldName, oldPath string
	var hasChildren bool
	err = tx.QueryRow(ctx, `
		SELECT 
			name, path, 
			EXISTS (SELECT 1 FROM mailboxes AS child WHERE child.path LIKE m.path || '%' AND child.path != m.path)
		FROM mailboxes m 
		WHERE id = $1 AND account_id = $2 FOR UPDATE`, mailboxID, userID).Scan(&oldName, &oldPath, &hasChildren)
	if err != nil {
		if err == pgx.ErrNoRows {
			return consts.ErrMailboxNotFound
		}
		log.Printf("[DB] ERROR: failed to fetch mailbox to rename (ID: %d): %v", mailboxID, err)
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
		err = tx.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1 AND account_id = $2 FOR UPDATE", *newParentID, userID).Scan(&newParentPath)
		if err != nil {
			if err == pgx.ErrNoRows {
				log.Printf("[DB] ERROR: new parent mailbox (ID: %d) not found for rename", *newParentID)
				return consts.ErrMailboxNotFound
			}
			log.Printf("[DB] ERROR: failed to fetch new parent path (ID: %d): %v", *newParentID, err)
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

		_, err = tx.Exec(ctx, `
			UPDATE mailboxes
			SET 
				name = $1 || SUBSTRING(name FROM LENGTH($2) + 1),
				path = $3 || SUBSTRING(path FROM LENGTH($4) + 1),
				updated_at = now()
			WHERE 
				account_id = $5 AND 
				path LIKE $4 || '%' AND 
				id != $6
		`, newPrefix, oldPrefix, newPath, oldPath, userID, mailboxID)

		if err != nil {
			return fmt.Errorf("failed to update child mailboxes: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		log.Printf("[DB] ERROR: failed to commit transaction for rename: %v", err)
		return consts.ErrDBCommitTransactionFailed
	}

	return nil
}
