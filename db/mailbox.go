package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/yugabyte/pgx/v5"
)

// DBMailbox represents the database structure of a mailbox
type DBMailbox struct {
	ID          int64
	Name        string // Full path
	UIDValidity uint32
	Subscribed  bool
	HasChildren bool
	ParentID    *int64 // Nullable parent ID for top-level mailboxes
}

func NewDBMailbox(mboxId int64, name string, uidValidity uint32, parentID *int64, subscribed, hasChildren bool) DBMailbox {
	return DBMailbox{
		ID:          mboxId,
		Name:        name,
		UIDValidity: uidValidity,
		ParentID:    parentID,
		HasChildren: hasChildren,
		Subscribed:  subscribed,
	}
}

func (db *Database) GetMailboxes(ctx context.Context, userID int64, subscribed bool) ([]*DBMailbox, error) {
	query := `
		SELECT 
			id, 
			name, 
			uid_validity, 
			parent_id, 
			subscribed, 
			EXISTS (SELECT 1 FROM mailboxes AS child WHERE child.parent_id = m.id) AS has_children 
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
		var parentID *int64

		var dbParentID sql.NullInt64

		var mailboxName string
		var hasChildren bool
		var uidValidityInt64 int64

		var subscribed bool

		if err := rows.Scan(&mailboxID, &mailboxName, &uidValidityInt64, &dbParentID, &subscribed, &hasChildren); err != nil {
			return nil, err
		}

		if dbParentID.Valid {
			i := dbParentID.Int64
			parentID = &i
		}
		mailbox := NewDBMailbox(mailboxID, mailboxName, uint32(uidValidityInt64), parentID, subscribed, hasChildren)
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
	var dbParentID sql.NullInt64
	var mailboxName string
	var hasChildren bool
	var uidValidityInt64 int64
	var subscribed bool

	err := db.Pool.QueryRow(ctx, `
		SELECT 
			id, name, uid_validity, parent_id, subscribed,
			EXISTS (
				SELECT 1
				FROM mailboxes AS child
				WHERE child.parent_id = m.id
			) AS has_children
		FROM mailboxes m
		WHERE id = $1 AND account_id = $2
	`, mailboxID, userID).Scan(&mailboxID, &mailboxName, &uidValidityInt64, &dbParentID, &subscribed, &hasChildren)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, err
	}

	var parentID *int64
	if dbParentID.Valid {
		i := dbParentID.Int64
		parentID = &i
	}

	mailbox := NewDBMailbox(mailboxID, mailboxName, uint32(uidValidityInt64), parentID, subscribed, hasChildren)
	return &mailbox, nil
}

// GetMailboxByFullPath fetches the mailbox for a specific user by full path, working recursively
func (db *Database) GetMailboxByName(ctx context.Context, userID int64, name string) (*DBMailbox, error) {
	var mailbox DBMailbox

	var uidValidityInt64 int64
	err := db.Pool.QueryRow(ctx, `
		SELECT
			id, name, uid_validity, parent_id, subscribed,
			EXISTS (SELECT 1 FROM mailboxes AS child WHERE child.parent_id = m.id) AS has_children
		FROM mailboxes m
		WHERE account_id = $1 AND LOWER(name) = $2
	`, userID, strings.ToLower(name)).Scan(&mailbox.ID, &mailbox.Name, &uidValidityInt64, &mailbox.ParentID, &mailbox.Subscribed, &mailbox.HasChildren)

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
	// Avoid low uid_validity which may cause issues with some IMAP clients
	uidValidity := uint32(time.Now().Unix())
	// Try to insert the mailbox into the database
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO mailboxes (account_id, name, parent_id, uid_validity, subscribed)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, name, parentID, int64(uidValidity), true)

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
				} else if pgErr.ConstraintName == "mailboxes_parent_id_fkey" {
					log.Printf("[DB] ERROR: parent mailbox does not exist")
					return consts.ErrDBNotFound
				}
			}
		}
		return fmt.Errorf("failed to create mailbox: %v", err)
	}
	return nil
}

func (db *Database) CreateDefaultMailbox(ctx context.Context, userID int64, name string, parentID *int64) error {
	uidValidity := uint32(time.Now().Unix())
	// Try to insert the mailbox into the database
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO mailboxes (account_id, name, parent_id, uid_validity, subscribed)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, name, parent_id) DO NOTHING
	`, userID, name, parentID, int64(uidValidity), true)

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
		return fmt.Errorf("failed to create mailbox: %v", err)
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

	_, err = tx.Exec(ctx, `
		UPDATE messages SET 
			mailbox_path = $1 
		WHERE mailbox_id = $2`, mbox.Name, mailboxID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to set path on messages of folder %d : %v", mailboxID, err)
		return consts.ErrInternalError
	}

	result, err := tx.Exec(ctx, `
		DELETE FROM mailboxes WHERE id = $1`, mailboxID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to delete mailbox %d: %v", mailboxID, err)
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
	UIDNext       int64
	NumMessages   int
	TotalSize     int64
	HighestModSeq uint64
	RecentCount   int
	UnseenCount   int
}

func (d *Database) GetMailboxSummary(ctx context.Context, mailboxID int64) (*MailboxSummary, error) {
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `
		SELECT
			COALESCE(MAX(uid) FILTER (WHERE expunged_at IS NULL), 0) + 1 AS uid_next,
			COUNT(*) FILTER (WHERE expunged_at IS NULL) AS num_messages,
			COALESCE(SUM(size) FILTER (WHERE expunged_at IS NULL), 0) AS total_size,
			(
				SELECT COALESCE(MAX(GREATEST(m_mod.created_modseq, COALESCE(m_mod.updated_modseq, 0), COALESCE(m_mod.expunged_modseq, 0))), 1)
				FROM messages m_mod
				WHERE m_mod.mailbox_id = $1
			) AS highest_modseq,
			COUNT(*) FILTER (WHERE (flags & $2) = 0 AND expunged_at IS NULL) AS unseen_count -- $2 is FlagSeen
		FROM messages
		WHERE mailbox_id = $1;
	`
	row := tx.QueryRow(ctx, query, mailboxID, FlagSeen)

	var s MailboxSummary
	err = row.Scan(&s.UIDNext, &s.NumMessages, &s.TotalSize, &s.HighestModSeq, &s.UnseenCount)
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
	if mailbox.ParentID == nil {
		for _, rootFolder := range consts.DefaultMailboxes {
			if strings.EqualFold(mailbox.Name, rootFolder) {
				log.Printf("[DB] WARNING: ignoring subscription status update for root folder %s", mailbox.Name)
				return nil
			}
		}
	}

	_, err = db.Pool.Exec(ctx, `
		UPDATE mailboxes SET subscribed = $1 WHERE id = $2
	`, subscribed, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to update subscription status for mailbox %d: %v", mailboxID, err)
	}

	return nil
}

func (db *Database) RenameMailbox(ctx context.Context, mailboxID int64, userID int64, newName string) error {
	if newName == "" {
		return consts.ErrMailboxInvalidName
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("[DB] ERROR: failed to begin transaction: %v", err)
		return consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	// Fetch the mailbox to rename
	mailbox, err := db.GetMailbox(ctx, mailboxID, userID)
	if err != nil {
		return consts.ErrMailboxNotFound
	}

	// Check if the new name already exists
	_, err = db.GetMailboxByName(ctx, userID, newName)
	if err == nil {
		return consts.ErrMailboxAlreadyExists
	} else if err != consts.ErrMailboxNotFound {
		log.Printf("[DB] ERROR: failed to fetch mailbox %s: %v", newName, err)
		return consts.ErrInternalError
	}

	// Find common name to determine parent between mailbox.name and newName
	parentPath := findCommonPath(mailbox.Name, newName, string(consts.MailboxDelimiter))

	// No common path
	if parentPath == "" {

		parentPathComponents := strings.Split(newName, string(consts.MailboxDelimiter))
		parentPath = strings.Join(parentPathComponents[:len(parentPathComponents)-1], string(consts.MailboxDelimiter))
	}

	// Get the parent mailbox ID
	var parentMailboxID *int64

	if parentPath != "" {
		parentMailbox, err := db.GetMailboxByName(ctx, userID, parentPath)
		if err != nil {
			log.Printf("[DB] ERROR: failed to fetch parent mailbox %s: %v", parentPath, err)
			return consts.ErrInternalError
		}
		parentMailboxID = &parentMailbox.ID
	}

	var parentVal interface{}
	if parentMailboxID == nil {
		// This will become SQL NULL
		parentVal = nil
	} else {
		// Dereference the pointer, store as an int
		parentVal = *parentMailboxID
	}

	// Update the mailbox name and parent ID
	_, err = tx.Exec(ctx, `UPDATE mailboxes SET name = $1, parent_id = $2 WHERE id = $3`,
		newName, parentVal, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to rename mailbox %d: %v", mailboxID, err)
	}

	// Recursively update child mailboxes' parent paths
	if mailbox.HasChildren {
		if err := db.updateParentPathOnMailboxChildren(ctx, tx, mailboxID, newName); err != nil {
			return err
		}
	}

	committed := false
	defer func() {
		if !committed {
			tx.Rollback(ctx)
		}
	}()

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[DB] ERROR: failed to commit transaction: %v", err)
		return consts.ErrDBCommitTransactionFailed
	}
	committed = true

	return nil
}

func (db *Database) updateParentPathOnMailboxChildren(
	ctx context.Context,
	tx pgx.Tx,
	parentMailboxID int64,
	newParentPath string,
) error {
	rows, err := tx.Query(ctx, `
			SELECT 
					id,
					name,
					EXISTS (
							SELECT 1
							FROM mailboxes AS child
							WHERE child.parent_id = m.id
					) AS has_children
			FROM mailboxes m
			WHERE parent_id = $1
	`, parentMailboxID)
	if err != nil {
		return err
	}
	defer rows.Close()

	// First, gather all child info in-memory
	var children []struct {
		id          int64
		name        string
		hasChildren bool
	}

	for rows.Next() {
		var childMailboxID int64
		var childMailboxName string
		var hasChildren bool
		if err := rows.Scan(&childMailboxID, &childMailboxName, &hasChildren); err != nil {
			return err
		}

		children = append(children, struct {
			id          int64
			name        string
			hasChildren bool
		}{
			id:          childMailboxID,
			name:        childMailboxName,
			hasChildren: hasChildren,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, child := range children {
		// Build new path for the child
		oldNameComponents := strings.Split(child.name, string(consts.MailboxDelimiter))
		newName := strings.Join([]string{
			newParentPath,
			oldNameComponents[len(oldNameComponents)-1],
		}, string(consts.MailboxDelimiter))

		ct, err := tx.Exec(ctx, `
					UPDATE mailboxes
					SET name = $1
					WHERE id = $2
						AND parent_id = $3
			`, newName, child.id, parentMailboxID)
		if err != nil {
			return fmt.Errorf("failed to update child mailbox %d: %v", child.id, err)
		}

		if ct.RowsAffected() == 0 {
			log.Printf("[DB] ERROR: child mailbox %d not found for update", child.id)
			continue
		}

		// If the child itself has children, recurse AFTER closing the parent's rows
		if child.hasChildren {
			if err := db.updateParentPathOnMailboxChildren(ctx, tx, child.id, newName); err != nil {
				return err
			}
		}
	}

	return nil
}

// findCommonPath finds the common path between two mailbox names based on the delimiter.
// This is a wrapper around helpers.FindCommonPath for backward compatibility.
func findCommonPath(oldName, newName, delimiter string) string {
	return helpers.FindCommonPath(oldName, newName, delimiter)
}
