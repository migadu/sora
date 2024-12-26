package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
)

// DBMailbox represents the database structure of a mailbox
type DBMailbox struct {
	ID          int
	Name        string // Full path
	UIDValidity uint32
	Subscribed  bool
	// Messages int
	// Recent        int
	// Unseen        int
	HasChildren bool
	ParentID    *int // Nullable parent ID for top-level mailboxes
}

func NewDBMailbox(mboxId int, name string, uidValidity uint32, parentID *int, subscribed, hasChildren bool) DBMailbox {
	return DBMailbox{
		ID:          mboxId,
		Name:        name,
		UIDValidity: uidValidity,
		ParentID:    parentID,
		HasChildren: hasChildren,
		Subscribed:  subscribed,
	}
}

func (db *Database) GetMailboxes(ctx context.Context, userID int, subscribed bool) ([]*DBMailbox, error) {
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
			user_id = $1`

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
		var mailboxID int
		var parentID *int

		var dbParentID sql.NullInt64

		var mailboxName string
		var hasChildren bool
		var uidValidity uint32

		var subscribed bool

		if err := rows.Scan(&mailboxID, &mailboxName, &uidValidity, &dbParentID, &subscribed, &hasChildren); err != nil {
			return nil, err
		}

		if dbParentID.Valid {
			i := int(dbParentID.Int64)
			parentID = &i
		}
		mailbox := NewDBMailbox(mailboxID, mailboxName, uidValidity, parentID, subscribed, hasChildren)
		mailboxes = append(mailboxes, &mailbox)
	}

	// Check for any error that occurred during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return mailboxes, nil
}

// GetMailbox fetches the mailbox
func (db *Database) GetMailbox(ctx context.Context, mailboxID int) (*DBMailbox, error) {
	var dbParentID sql.NullInt32
	var mailboxName string
	var hasChildren bool
	var uidValidity uint32
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
		WHERE id = $1
	`, mailboxID).Scan(&mailboxID, &mailboxName, &uidValidity, &dbParentID, &subscribed, &hasChildren)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, err
	}

	var parentID *int
	if dbParentID.Valid {
		i := int(dbParentID.Int32)
		parentID = &i
	}

	mailbox := NewDBMailbox(mailboxID, mailboxName, uidValidity, parentID, subscribed, hasChildren)
	return &mailbox, nil
}

// GetMailboxByFullPath fetches the mailbox for a specific user by full path, working recursively
func (db *Database) GetMailboxByName(ctx context.Context, userID int, name string) (*DBMailbox, error) {
	var mailbox DBMailbox

	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, uid_validity, parent_id
		FROM mailboxes 
		WHERE user_id = $1 AND LOWER(name) = $2 
	`, userID, strings.ToLower(name)).Scan(&mailbox.ID, &mailbox.Name, &mailbox.UIDValidity, &mailbox.ParentID)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		log.Printf("Failed to find mailbox '%s': %v", name, err)
		return nil, consts.ErrInternalError
	}

	return &mailbox, nil
}

func (db *Database) CreateMailbox(ctx context.Context, userID int, name string, parentID *int) error {
	uidValidity := generateUIDValidity()

	// Try to insert the mailbox into the database
	_, err := db.Pool.Exec(ctx, `
        INSERT INTO mailboxes (user_id, name, parent_id, uid_validity, subscribed) 
        VALUES ($1, $2, $3, $4, $5)
    `, userID, name, parentID, uidValidity, true)

	// Handle errors, including unique constraint and foreign key violations
	if err != nil {
		// Use pgx/v5's pgconn.PgError for error handling
		if pgErr, ok := err.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23505": // Unique constraint violation
				log.Printf("A mailbox named '%s' already exists for user %d", name, userID)
				return consts.ErrDBUniqueViolation
			case "23503": // Foreign key violation
				if pgErr.ConstraintName == "mailboxes_user_id_fkey" {
					log.Printf("User with ID %d does not exist", userID)
					return consts.ErrDBNotFound
				} else if pgErr.ConstraintName == "mailboxes_parent_id_fkey" {
					log.Printf("Parent mailbox does not exist")
					return consts.ErrDBNotFound
				}
			}
		}
		return fmt.Errorf("failed to create mailbox: %v", err)
	}
	return nil
}

// DeleteMailbox deletes a mailbox for a specific user by id
func (db *Database) DeleteMailbox(ctx context.Context, mailboxID int) error {
	//
	// TODO: Implement delayed S3 deletion of messages
	//

	mbox, err := db.GetMailbox(ctx, mailboxID)
	if err != nil {
		log.Printf("Failed to fetch mailbox %d: %v", mailboxID, err)
		return consts.ErrMailboxNotFound
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("failed to begin transaction: %v", err)
		return consts.ErrInternalError
	}
	defer tx.Rollback(ctx) // Ensure the transaction is rolled back if an error occurs

	// Soft delete messages of the mailbox and set mailbox_name (path) for possible restoration
	now := time.Now()
	_, err = tx.Exec(ctx, `
		UPDATE messages SET 
			mailbox_name = $1, 
			deleted_at = $2 
		WHERE mailbox_id = $3`, mbox.Name, now, mailboxID)
	if err != nil {
		log.Printf("Failed to soft delete messages of folder %d : %v", mailboxID, err)
		return consts.ErrInternalError
	}

	result, err := tx.Exec(ctx, `
		DELETE FROM mailboxes WHERE id = $1`, mailboxID)
	if err != nil {
		log.Printf("Failed to delete mailbox %d: %v", mailboxID, err)
		return consts.ErrInternalError
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("Mailbox %d not found for deletion", mailboxID)
		return consts.ErrInternalError
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v\n", err)
		return consts.ErrInternalError
	}

	return nil
}

func (db *Database) CreateDefaultMailboxes(ctx context.Context, userId int) error {
	for _, mailboxName := range consts.DefaultMailboxes {
		_, err := db.GetMailboxByName(ctx, userId, mailboxName)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				err := db.CreateMailbox(ctx, userId, mailboxName, nil)
				if err != nil {
					log.Printf("Failed to create mailbox %s for user %d: %v\n", mailboxName, userId, err)
					return consts.ErrInternalError
				}
				log.Printf("Created missing mailbox %s for user %d", mailboxName, userId)
				continue
			}
			log.Printf("Failed to get mailbox %s: %v", mailboxName, err)
			return consts.ErrInternalError
		}
	}

	return nil
}

func (d *Database) GetMailboxUnseenCount(ctx context.Context, mailboxID int) (int, error) {
	var count int
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND (flags & $2) = 0 AND expunged_at IS NULL", mailboxID, FlagSeen).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (d *Database) GetMailboxRecentCount(ctx context.Context, mailboxID int) (int, error) {
	var count int
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND (flags & $2) = 0 AND expunged_at IS NULL", mailboxID, FlagRecent).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (d *Database) GetMailboxMessageCountAndSizeSum(ctx context.Context, mailboxID int) (int, int64, error) {
	var count int
	var size int64
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&count, &size)
	if err != nil {
		return 0, 0, err
	}
	return count, size, nil
}

func (d *Database) GetMailboxNextUID(ctx context.Context, mailboxID int) (int, error) {
	var uidNext int
	// Query to get the maximum UID or return 1 if there are no messages
	err := d.Pool.QueryRow(ctx, "SELECT COALESCE(MAX(id), 0) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&uidNext)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch next UID: %v", err)
	}
	return uidNext + 1, nil
}

// SetSubscribed updates the subscription status of a mailbox, but ignores unsubscribing for root folders.
func (db *Database) SetMailboxSubscribed(ctx context.Context, mailboxID int, subscribed bool) error {
	// Update the subscription status only if the mailbox is not a root folder
	mailbox, err := db.GetMailbox(ctx, mailboxID)
	if err != nil {
		log.Printf("Failed to fetch mailbox %d: %v", mailboxID, err)
		return consts.ErrMailboxNotFound
	}
	if mailbox.ParentID == nil {
		for _, rootFolder := range consts.DefaultMailboxes {
			if strings.EqualFold(mailbox.Name, rootFolder) {
				log.Printf("Ignoring subscription status update for root folder %s", mailbox.Name)
				return nil
			}
		}
	}

	_, err = db.Pool.Exec(ctx, `
		UPDATE mailboxes SET subscribed = $1 
		WHERE id = $2 AND (parent_id IS NOT NULL OR $1 = TRUE)
	`, subscribed, mailboxID)

	if err != nil {
		return fmt.Errorf("failed to update subscription status for mailbox %d: %v", mailboxID, err)
	}

	return nil
}

func (db *Database) RenameMailbox(ctx context.Context, mailboxID int, userID int, newName string) error {
	if newName == "" {
		return consts.ErrMailboxInvalidName
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	// Fetch the mailbox to rename
	mailbox, err := db.GetMailbox(ctx, mailboxID)
	if err != nil {
		return consts.ErrMailboxNotFound
	}

	// Check if the new name already exists
	_, err = db.GetMailboxByName(ctx, userID, newName)
	if err == nil {
		return consts.ErrMailboxAlreadyExists
	} else if err != consts.ErrMailboxNotFound {
		log.Printf("Failed to fetch mailbox %s: %v", newName, err)
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
	var parentMailboxID *int

	if parentPath != "" {
		parentMailbox, err := db.GetMailboxByName(ctx, userID, parentPath)
		if err != nil {
			log.Printf("Failed to fetch parent mailbox %s: %v", parentPath, err)
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
		log.Printf("Failed to commit transaction: %v", err)
		return consts.ErrDBCommitTransactionFailed
	}
	committed = true

	return nil
}

func (db *Database) updateParentPathOnMailboxChildren(
	ctx context.Context,
	tx pgx.Tx,
	parentMailboxID int,
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
		id          int
		name        string
		hasChildren bool
	}

	for rows.Next() {
		var childMailboxID int
		var childMailboxName string
		var hasChildren bool
		if err := rows.Scan(&childMailboxID, &childMailboxName, &hasChildren); err != nil {
			return err
		}

		children = append(children, struct {
			id          int
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
			log.Printf("Child mailbox %d not found for update", child.id)
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
func findCommonPath(oldName, newName, delimiter string) string {
	// Split the mailbox names into components
	oldParts := strings.Split(oldName, delimiter)
	newParts := strings.Split(newName, delimiter)

	// Determine the shorter length to prevent out-of-range errors
	minLen := len(oldParts)
	if len(newParts) < minLen {
		minLen = len(newParts)
	}

	// Iterate to find the common prefix
	commonParts := []string{}
	for i := 0; i < minLen; i++ {
		if oldParts[i] == newParts[i] {
			commonParts = append(commonParts, oldParts[i])
		} else {
			break
		}
	}

	// If there's no common path, return an empty string
	if len(commonParts) == 0 {
		return ""
	}

	// Reconstruct the common path
	commonPath := strings.Join(commonParts, delimiter)
	return commonPath
}
