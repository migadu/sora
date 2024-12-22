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
	Name        string
	UIDValidity uint32
	Subscribed  bool
	// Messages int
	// Recent        int
	// Unseen        int
	HasChildren bool
	ParentID    *int    // Nullable parent ID for top-level mailboxes
	ParentPath  *string // Nullable parent path for top-level mailboxes
}

func NewDBMailbox(mboxId int, name string, uidValidity uint32, parentID *int, parentPath *string, subscribed, hasChildren bool) DBMailbox {
	return DBMailbox{
		ID:          mboxId,
		Name:        name,
		UIDValidity: uidValidity,
		ParentID:    parentID,
		ParentPath:  parentPath,
		HasChildren: hasChildren,
		Subscribed:  subscribed,
	}
}

func (db *Database) GetMailboxes(ctx context.Context, userID int) ([]*DBMailbox, error) {
	// Prepare the query to fetch all mailboxes for the given user
	rows, err := db.Pool.Query(ctx, `
		SELECT 
			id, name, uid_validity, parent_id, parent_path, subscribed,
			EXISTS (
        SELECT 1 
        FROM mailboxes AS child 
        WHERE child.parent_id = m.id
    	) AS has_children
		FROM mailboxes m
		WHERE user_id = $1
	`, userID)
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
		var dbParentPath sql.NullString
		var parentPath *string

		var mailboxName string
		var hasChildren bool
		var uidValidity uint32

		var subscribed bool

		if err := rows.Scan(&mailboxID, &mailboxName, &uidValidity, &dbParentID, &dbParentPath, &subscribed, &hasChildren); err != nil {
			return nil, err
		}

		if dbParentID.Valid {
			i := int(dbParentID.Int64)
			parentID = &i
		}
		if dbParentPath.Valid {
			s := dbParentPath.String
			parentPath = &s
		}
		mailbox := NewDBMailbox(mailboxID, mailboxName, uidValidity, parentID, parentPath, subscribed, hasChildren)
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
	var parentID int
	var mailboxName, parentPath string
	var hasChildren bool
	var uidValidity uint32
	var subscribed bool

	err := db.Pool.QueryRow(ctx, `
		SELECT 
			id, name, uid_validity, parent_id, parent_path, subscribed 
		FROM mailboxes,
			EXISTS (
				SELECT 1
				FROM mailboxes AS child
				WHERE child.parent_id = m.id
			) AS has_children
		FROM mailboxes
		WHERE id = $1
	`, mailboxID).Scan(&mailboxID, &mailboxName, &uidValidity, &parentID, &parentPath, &subscribed, &hasChildren)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, err
	}

	mailbox := NewDBMailbox(mailboxID, mailboxName, uidValidity, &parentID, &parentPath, subscribed, hasChildren)
	return &mailbox, nil
}

// GetMailboxByFullPath fetches the mailbox for a specific user by full path, working recursively
func (db *Database) GetMailboxByFullPath(ctx context.Context, userID int, pathComponents []string) (*DBMailbox, error) {
	var mailbox DBMailbox
	var err error

	if len(pathComponents) == 0 {
		return nil, consts.ErrMailboxNotFound
	}

	fullPath := strings.Join(pathComponents, string(consts.MailboxDelimiter))
	if len(pathComponents) == 1 {
		mailboxName := strings.ToLower(pathComponents[0])
		err = db.Pool.QueryRow(ctx, `
				SELECT id, name, uid_validity, parent_id, parent_path
				FROM mailboxes 
				WHERE user_id = $1 AND LOWER(name) = $2 AND parent_id IS NULL
			`, userID, mailboxName).Scan(&mailbox.ID, &mailbox.Name, &mailbox.UIDValidity, &mailbox.ParentID, &mailbox.ParentPath)
	} else {
		name := strings.ToLower(pathComponents[len(pathComponents)-1])
		parentPath := strings.ToLower(strings.Join(pathComponents[:len(pathComponents)-1], string(consts.MailboxDelimiter)))
		err = db.Pool.QueryRow(ctx, `
				SELECT id, name, uid_validity, parent_id, parent_path
				FROM mailboxes 
				WHERE user_id = $1 AND LOWER(name) = $2 AND LOWER(parent_path) = $3
			`, userID, name, parentPath).Scan(&mailbox.ID, &mailbox.Name, &mailbox.UIDValidity, &mailbox.ParentID, &mailbox.ParentPath)
	}

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		log.Printf("Failed to find mailbox '%s': %v", fullPath, err)
		return nil, consts.ErrInternalError
	}

	return &mailbox, nil
}

func (db *Database) CreateChildMailbox(ctx context.Context, userID int, name string, parentID int, parentPath string) error {
	uidValidity := generateUIDValidity()

	// Try to insert the mailbox into the database
	_, err := db.Pool.Exec(ctx, `
        INSERT INTO mailboxes (user_id, name, parent_id, parent_path, uid_validity, subscribed) 
        VALUES ($1, $2, $3, $4, $5, $6)
    `, userID, name, parentID, parentPath, uidValidity, true)

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

// CreateMailbox creates a new mailbox for the specified user with the given name
func (db *Database) CreateMailbox(ctx context.Context, userID int, name string) error {
	uidValidity := generateUIDValidity()
	// Try to insert the mailbox into the database
	_, err := db.Pool.Exec(ctx, `
				INSERT INTO mailboxes (user_id, name, uid_validity, subscribed) 
				VALUES ($1, $2, $3, $4)
		`, userID, name, uidValidity, true)

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
func (db *Database) DeleteMailbox(ctx context.Context, mailboxID int, mailboxPath string) error {
	//
	// TODO: Implement delayed S3 deletion of messages
	//

	_, err := db.GetMailbox(ctx, mailboxID)
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

	// Soft delete messages of the mailbox
	now := time.Now()
	_, err = tx.Exec(ctx, `
		UPDATE messages SET 
			mailbox_path = $1, 
			deleted_at = $2 
		WHERE mailbox_id = $3`, mailboxPath, now, mailboxID)
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
		pathComponents := []string{mailboxName}

		_, err := db.GetMailboxByFullPath(ctx, userId, pathComponents)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				err := db.CreateMailbox(ctx, userId, mailboxName)
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

func (db *Database) RenameMailbox(ctx context.Context, mailboxID int, newName string, newParentPath *string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	var newChildParentPath string
	if newParentPath == nil {
		_, err = tx.Exec(ctx, `
		UPDATE mailboxes SET name = $1, parent_path = NULL WHERE id = $2
	`, newName, mailboxID)
		newChildParentPath = newName
	} else {
		_, err = tx.Exec(ctx, `
		UPDATE mailboxes SET name = $1, parent_path = $2 WHERE id = $3
	`, newName, *newParentPath, mailboxID)
		newChildParentPath = *newParentPath + string(consts.MailboxDelimiter) + newName
	}
	if err != nil {
		return fmt.Errorf("failed to rename mailbox %d: %v", mailboxID, err)
	}

	// Recursively update child mailboxes' parent paths
	if err := db.updateParentPathOnMailboxChildren(ctx, tx, mailboxID, newChildParentPath); err != nil {
		return err
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

func (db *Database) updateParentPathOnMailboxChildren(ctx context.Context, tx pgx.Tx, mailboxID int, newParentPath string) error {
	// Update the parent path of direct children
	ct, err := tx.Exec(ctx, `
			UPDATE mailboxes SET parent_path = $1 WHERE parent_id = $2
	`, newParentPath, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to update child mailboxes of %d: %v", mailboxID, err)
	}

	// If there are children, process them
	if ct.RowsAffected() > 0 {
		rows, err := tx.Query(ctx, `
					SELECT id, name FROM mailboxes WHERE parent_id = $1
			`, mailboxID)
		if err != nil {
			return err
		}
		defer rows.Close() // Ensure rows are closed after processing

		// Create a list of child mailboxes to process after closing the rows
		var children []struct {
			id   int
			name string
		}

		// Collect all children before proceeding with further queries
		for rows.Next() {
			var childMailboxID int
			var childName string
			if err := rows.Scan(&childMailboxID, &childName); err != nil {
				return err
			}

			// Add the child to the list for later processing
			children = append(children, struct {
				id   int
				name string
			}{childMailboxID, childName})
		}

		// Check for errors during row iteration
		if err := rows.Err(); err != nil {
			return err
		}

		// Process the child mailboxes after rows have been fully consumed
		for _, child := range children {
			newChildParentPath := newParentPath + string(consts.MailboxDelimiter) + child.name

			// Recursive call to update child mailboxes, using the same transaction
			if err := db.updateParentPathOnMailboxChildren(ctx, tx, child.id, newChildParentPath); err != nil {
				return err
			}
		}
	}

	return nil
}
