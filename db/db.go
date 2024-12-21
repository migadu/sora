package db

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"golang.org/x/crypto/bcrypt"
)

//go:embed schema.sql
var schema string

// Database holds the SQL connection
type Database struct {
	Pool *pgxpool.Pool
}

// Mailbox represents the database structure of a mailbox
type Mailbox struct {
	ID          int
	Name        string
	UIDValidity uint32
	Subscribed  bool
	Messages    int
	Recent      int
	Unseen      int
	ParentID    *int    // Nullable parent ID for top-level mailboxes
	ParentPath  *string // Nullable parent path for top-level mailboxes
}

type MessageUpdate struct {
	ID           int
	SeqNum       int
	BitwiseFlags int
	IsExpunge    bool
	FlagsChanged bool
}

// generateUidValidity generates a unique UIDVALIDITY value based on the current time in nanoseconds
func generateUIDValidity() uint32 {
	return uint32(time.Now().Unix()) // Unix timestamp in seconds, which fits in uint32
}

// NewDatabase initializes a new SQL database connection
func NewDatabase(ctx context.Context, host, port, user, password, dbname string) (*Database, error) {
	// Construct the connection string
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, dbname)

	// Log the connection string for debugging (without the password)
	log.Printf("Connecting to database: postgres://%s@%s:%s/%s?sslmode=disable",
		user, host, port, dbname)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatalf("Unable to parse connection string: %v", err)
	}

	// Set up custom tracer for query logging
	config.ConnConfig.Tracer = &CustomTracer{}

	// Create a connection pool
	dbPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	// Verify the connection
	if err := dbPool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}

	db := &Database{
		Pool: dbPool,
	}

	if err := db.migrate(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

// Close closes the database connection
func (db *Database) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// migrate creates necessary tables
func (db *Database) migrate(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx, schema)
	return err
}

// Authenticate verifies the provided username and password, and returns the user ID if successful
func (db *Database) Authenticate(ctx context.Context, userID int, password string) error {
	var hashedPassword string

	err := db.Pool.QueryRow(ctx, "SELECT password FROM users WHERE id = $1", userID).Scan(&hashedPassword)
	if err != nil {
		if err == pgx.ErrNoRows {
			return errors.New("user not found")
		}
		log.Printf("FATAL Failed to fetch user %d: %v", userID, err)
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return errors.New("invalid password")
	}

	return nil
}

func (db *Database) InsertUser(ctx context.Context, username, password string) error {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Upsert user into the database (insert or update if the username already exists)
	_, err = db.Pool.Exec(ctx, `
        INSERT INTO users (username, password)
        VALUES ($1, $2)
        ON CONFLICT (username) DO UPDATE
        SET password = EXCLUDED.password
    `, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to upsert test user: %v", err)
	}

	log.Println("User created successfully")

	return nil
}

func (db *Database) GetMailboxes(ctx context.Context, userID int) ([]Mailbox, error) {
	// Prepare the query to fetch all mailboxes for the given user
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, uid_validity, parent_id, parent_path FROM mailboxes WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Collect the mailboxes
	var mailboxes []Mailbox
	for rows.Next() {
		var mailbox Mailbox
		if err := rows.Scan(&mailbox.ID, &mailbox.Name, &mailbox.UIDValidity, &mailbox.ParentID, &mailbox.ParentPath); err != nil {
			return nil, err
		}
		mailboxes = append(mailboxes, mailbox)
	}

	// Check for any error that occurred during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return mailboxes, nil
}

// GetSubscribedMailboxes retrieves only subscribed mailboxes for a user
func (db *Database) GetSubscribedMailboxes(ctx context.Context, userID int) ([]Mailbox, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, parent_id, parent_path, subscribed FROM mailboxes WHERE user_id = $1 AND subscribed = true
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mailboxes []Mailbox
	for rows.Next() {
		var mailbox Mailbox
		if err := rows.Scan(&mailbox.ID, &mailbox.Name, &mailbox.ParentID, &mailbox.ParentPath, &mailbox.Subscribed); err != nil {
			return nil, err
		}
		mailboxes = append(mailboxes, mailbox)
	}

	return mailboxes, nil
}

// HasChildren checks if the given mailbox ID has any children (subfolders).
func (db *Database) MailboxHasChildren(ctx context.Context, mailboxID int) (bool, error) {
	var count int
	err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM mailboxes WHERE parent_id = $1", mailboxID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetMailbox fetches the mailbox
func (db *Database) GetMailbox(ctx context.Context, mailboxID int) (*Mailbox, error) {
	mailbox := &Mailbox{}
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, uid_validity, parent_id, parent_path FROM mailboxes WHERE id = $1
	`, mailboxID).Scan(&mailbox.ID, &mailbox.Name, &mailbox.UIDValidity, &mailbox.ParentID, &mailbox.ParentPath)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrMailboxNotFound
		}
		return nil, err
	}

	return mailbox, nil
}

// GetMailboxByFullPath fetches the mailbox for a specific user by full path, working recursively
func (db *Database) GetMailboxByFullPath(ctx context.Context, userID int, pathComponents []string) (*Mailbox, error) {
	var mailbox Mailbox
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

// CreateDefaultMailboxesInDB creates default mailboxes for a user if they don't exist
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

func (d *Database) GetMailboxMessageCount(ctx context.Context, mailboxID int) (int, error) {
	var count int
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
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
func (db *Database) SetSubscribed(ctx context.Context, mailboxID int, subscribed bool) error {
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

// -- Messages --

func (d *Database) GetMessageCount(ctx context.Context, mailboxID int) (int, int64, error) {
	var count int
	var size int64
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&count, &size)
	if err != nil {
		return 0, 0, err
	}
	return count, size, nil
}

func (d *Database) GetRecentMessageCount(ctx context.Context, mailboxID int) (int, error) {
	var count int
	err := d.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND flags & 1 = 0 AND expunged_at IS NULL", mailboxID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (d *Database) InsertMessageCopy(ctx context.Context, destMailboxID int, srcMessageUID imap.UID, s3UploadFunc func(imap.UID) error) (int, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return 0, consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	var newMsgID int
	err = tx.QueryRow(ctx, `
		INSERT INTO messages 
			(mailbox_id, s3_uuid, message_id, flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, text_body, text_body_tsv)
		SELECT 
			$2, s3_uuid, message_id, flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, text_body, text_body_tsv	
		FROM 
			messages
		WHERE 
			id = $1
		RETURNING id
	`, srcMessageUID, destMailboxID).Scan(&newMsgID)

	// TODO: this should not be a fatal error
	if err != nil {
		// If unique constraint violation, return an error
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			log.Print("Message with same id already exists in mailbox")
			return 0, consts.ErrDBUniqueViolation
		}
		log.Printf("Failed to insert message into database: %v", err)
		return 0, consts.ErrDBInsertFailed
	}

	err = s3UploadFunc(imap.UID(newMsgID))
	if err != nil {
		return 0, consts.ErrS3UploadFailed
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return 0, consts.ErrDBCommitTransactionFailed
	}

	return newMsgID, nil
}

func (d *Database) InsertMessage(ctx context.Context, mailboxID int, uuidKey uuid.UUID, messageID string, flags []imap.Flag, internalDate time.Time, size int64, subject string, plaintextBody *string, sentDate time.Time, inReplyTo []string, s3Buffer *bytes.Buffer, bodyStructure *imap.BodyStructure, recipients *[]Recipient, s3UploadFunc func(uuid.UUID, *bytes.Buffer, int64) error) (int, error) {
	bodyStructureData, err := helpers.SerializeBodyStructureGob(bodyStructure)
	if err != nil {
		log.Printf("Failed to serialize BodyStructure: %v", err)
		return 0, consts.ErrSerializationFailed
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return 0, consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	// Convert the inReplyTo slice to a space-separated string
	inReplyToStr := strings.Join(inReplyTo, " ")
	bitwiseFlags := FlagsToBitwise(flags)
	var id int
	err = tx.QueryRow(ctx, `
			INSERT INTO messages (mailbox_id, message_id, s3_uuid, flags, internal_date, size, text_body, text_body_tsv, subject, sent_date, in_reply_to, body_structure) 
			VALUES ($1, $2, $3, $4, $5, $6, $7, to_tsvector('simple', $8), $9, $10, $11, $12) 
			RETURNING id
	`, mailboxID, messageID, uuidKey, bitwiseFlags, internalDate, size, *plaintextBody, *plaintextBody, subject, sentDate, inReplyToStr, bodyStructureData).Scan(&id)

	if err != nil {
		// If unique constraint violation, return an error
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			log.Printf("Message with ID %s already exists in mailbox %d", messageID, mailboxID)
			return 0, consts.ErrDBUniqueViolation
		}
		log.Printf("Failed to insert message into database: %v", err)
		return 0, consts.ErrDBInsertFailed
	}

	// Insert recipients into the database
	for _, recipient := range *recipients {
		_, err = tx.Exec(ctx, `
				INSERT INTO recipients (message_id, address_type, name, email_address)
				VALUES ($1, $2, $3, $4)
			`, id, recipient.AddressType, recipient.Name, recipient.EmailAddress)
		if err != nil {
			log.Printf("Failed to insert recipient: %v", err)
			return 0, consts.ErrDBInsertFailed
		}
	}

	err = s3UploadFunc(uuidKey, s3Buffer, size)
	if err != nil {
		log.Printf("Failed to upload message %d to S3: %v", id, err)
		return 0, consts.ErrS3UploadFailed
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		// TODO: Delete the message from S3
		return 0, consts.ErrDBCommitTransactionFailed
	}

	return id, nil
}

func (db *Database) MoveMessages(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int) (map[int]int, error) {
	// Map to store the original message ID to new UID mapping
	messageUIDMap := make(map[int]int)

	// Ensure the destination mailbox exists
	_, err := db.GetMailbox(ctx, destMailboxID)
	if err != nil {
		log.Printf("Failed to fetch mailbox %d: %v", destMailboxID, err)
		return nil, consts.ErrMailboxNotFound
	}

	// Begin a transaction
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return nil, consts.ErrInternalError
	}
	defer tx.Rollback(ctx) // Rollback if any error occurs

	// Move the messages and assign new UIDs in the destination mailbox
	query := `
		WITH inserted_messages AS (
			-- Insert the selected rows into the destination mailbox
			INSERT INTO messages (
					s3_uuid, 
					message_id, 
					in_reply_to, 
					subject, 
					sent_date, 
					internal_date, 
					flags, 
					size, 
					body_structure, 
					text_body, 
					text_body_tsv, 
					mailbox_id, 
					mailbox_path, 
					deleted_at, 
					flags_changed_at
			)
			SELECT
					s3_uuid, 
					message_id, 
					in_reply_to, 
					subject, 
					sent_date, 
					internal_date, 
					flags, 
					size, 
					body_structure, 
					text_body, 
					text_body_tsv, 
					$2 AS mailbox_id,  -- Assign to the new mailbox
					mailbox_path, 
					NULL AS deleted_at, 
					NOW() AS flags_changed_at
			FROM messages
			WHERE mailbox_id = $1 AND id = ANY($3)
			RETURNING id
	),
	numbered_messages AS (
			-- Generate new UIDs based on row numbers
			SELECT id, 
						ROW_NUMBER() OVER (ORDER BY id) + (SELECT COALESCE(MAX(id), 0) FROM messages WHERE mailbox_id = $2) AS uid
			FROM inserted_messages
	)
	-- Delete the original messages from the source mailbox
	DELETE FROM messages
	WHERE mailbox_id = $1 AND id = ANY($3)
	RETURNING id;
	`

	// Execute the query
	rows, err := tx.Query(ctx, query, srcMailboxID, destMailboxID, ids)
	if err != nil {
		log.Printf("Failed to move messages: %v", err)
		return nil, fmt.Errorf("failed to move messages: %v", err)
	}
	defer rows.Close()

	// Iterate through the moved messages to map original ID to the new UID
	for rows.Next() {
		var messageID, newUID int
		if err := rows.Scan(&messageID, &newUID); err != nil {
			return nil, fmt.Errorf("failed to scan message ID and UID: %v", err)
		}
		messageUIDMap[messageID] = newUID
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return nil, consts.ErrInternalError
	}

	return messageUIDMap, nil
}

func (db *Database) GetMessageBodyStructure(ctx context.Context, messageID int) (*imap.BodyStructure, error) {
	var bodyStructureBytes []byte

	err := db.Pool.QueryRow(ctx, `
			SELECT body_structure
			FROM messages
			WHERE id = $1 AND expunged_at IS NULL
	`, messageID).Scan(&bodyStructureBytes)
	if err != nil {
		return nil, err
	}

	// Deserialize the JSON string back into BodyStructure
	return helpers.DeserializeBodyStructureGob(bodyStructureBytes)
}

// GetMessagesBySeqSet fetches messages from the database based on the NumSet and mailbox ID.
// This works for both sequence numbers (SeqSet) and UIDs (UIDSet).
func (db *Database) GetMessagesBySeqSet(ctx context.Context, mailboxID int, numSet imap.NumSet) ([]Message, error) {
	var messages []Message

	var query string
	var args []interface{}

	switch set := numSet.(type) {
	case imap.SeqSet:
		nums, _ := set.Nums()
		if len(nums) == 0 {
			// Handle empty SeqSet as requesting all messages
			query = `
            SELECT id, s3_uuid, flags, internal_date, size, body_structure
            FROM messages
            WHERE mailbox_id = $1 AND expunged_at IS NULL
        `
			args = []interface{}{mailboxID}
		} else {
			query = `
						SELECT id, s3_uuid, flags, internal_date, size, body_structure
						FROM messages
						WHERE mailbox_id = $1 AND id = ANY($2) AND expunged_at IS NULL
				`
			args = []interface{}{mailboxID, nums}
		}

	case imap.UIDSet:
		query = `
			SELECT id, s3_uuid, flags, internal_date, size, body_structure
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		`
		args = []interface{}{mailboxID}
		for _, uidRange := range set {
			if uidRange.Start != 0 {
				args = append(args, uint32(uidRange.Start))
				query += fmt.Sprintf(" AND id >= $%d", len(args))
			}
			if uidRange.Stop != 0 {
				args = append(args, uint32(uidRange.Stop))
				query += fmt.Sprintf(" AND id <= $%d", len(args))
			}
		}

	default:
		return nil, fmt.Errorf("unsupported NumSet type")
	}

	// Execute the query
	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	defer rows.Close()

	// Scan the results and append to the messages slice
	for rows.Next() {
		var msg Message
		var bodyStructureBytes []byte
		if err := rows.Scan(&msg.ID, &msg.S3UUID, &msg.BitwiseFlags, &msg.InternalDate, &msg.Size, &bodyStructureBytes); err != nil {
			return nil, fmt.Errorf("failed to scan message: %v", err)
		}
		bodyStructure, err := helpers.DeserializeBodyStructureGob(bodyStructureBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize BodyStructure: %v", err)
		}
		msg.BodyStructure = *bodyStructure
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error fetching messages: %v", err)
	}

	return messages, nil
}

func (db *Database) SetMessageFlags(ctx context.Context, messageID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)
	err := db.Pool.QueryRow(ctx, "UPDATE messages SET flags = $1, flags_changed_at = $2 WHERE id = $3 RETURNING flags", flags, time.Now(), messageID).Scan(&updatedFlagsBitwise)
	if err != nil {
		return nil, err
	}
	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) AddMessageFlags(ctx context.Context, messageID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)
	err := db.Pool.QueryRow(ctx, "UPDATE messages SET flags = flags | $1, flags_changed_at = $2 WHERE id = $3 RETURNING flags", flags, time.Now(), messageID).Scan(&updatedFlagsBitwise)
	if err != nil {
		return nil, err
	}
	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) RemoveMessageFlags(ctx context.Context, messageID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)
	// Negate the flags to remove
	negatedFlags := ^flags
	err := db.Pool.QueryRow(ctx, "UPDATE messages SET flags = flags & $1, flags_changed_at = $2 WHERE id = $3 RETURNING flags", negatedFlags, time.Now(), messageID).Scan(&updatedFlagsBitwise)
	if err != nil {
		return nil, err
	}
	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) ExpungeMessagesByUIDs(ctx context.Context, mailboxID int, uids []uint32) error {
	_, err := db.Pool.Exec(ctx, `
			UPDATE messages SET expunged_at = NOW() WHERE mailbox_id = $1 AND id = ANY($3)
			UPDATE messages SET expunged_at = NOW() WHERE 
	`, mailboxID, uids)
	if err != nil {
		return err
	}
	return nil
}

// --- Recipients ---CREATE TABLE recipients (
func (db *Database) GetMessageEnvelope(ctx context.Context, UID int) (*imap.Envelope, error) {
	var envelope imap.Envelope

	var inReplyTo string

	err := db.Pool.QueryRow(ctx, `
        SELECT 
            internal_date, subject, in_reply_to, message_id 
        FROM 
            messages
        WHERE 
            id = $1
    `, UID).Scan(
		&envelope.Date,
		&envelope.Subject,
		&inReplyTo,
		&envelope.MessageID,
	)
	if err != nil {
		log.Printf("Failed to fetch envelope fields: %v", err)
		return nil, err
	}

	// Split the In-Reply-To header into individual message IDs
	envelope.InReplyTo = strings.Split(inReplyTo, " ")

	// Query the recipients from the database
	rows, err := db.Pool.Query(ctx, `
        SELECT address_type, name, email_address
        FROM recipients
        WHERE message_id = $1
    `, UID)
	if err != nil {
		log.Printf("Failed to fetch recipients: %v", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var addressType, name, emailAddress string
		if err := rows.Scan(&addressType, &name, &emailAddress); err != nil {
			return nil, fmt.Errorf("error scanning recipient row: %w", err)
		}

		parts := strings.Split(emailAddress, "@")
		mailboxPart, hostNamePart := parts[0], parts[1]

		address := imap.Address{
			Name:    name,
			Mailbox: mailboxPart,
			Host:    hostNamePart,
		}

		switch addressType {
		case "to":
			envelope.To = append(envelope.To, address)
		case "cc":
			envelope.Cc = append(envelope.Cc, address)
		case "bcc":
			envelope.Bcc = append(envelope.Bcc, address)
		case "reply-to":
			envelope.ReplyTo = append(envelope.ReplyTo, address)
		case "from":
			envelope.From = append(envelope.From, address)
		default:
			log.Printf("Warning: Unhandled address type: %s", addressType)
		}
	}

	if err := rows.Err(); err != nil { // Check for errors from iterating over rows
		return nil, fmt.Errorf("error iterating over recipient rows: %w", err)
	}

	return &envelope, nil
}

func (db *Database) GetMessagesWithCriteria(ctx context.Context, mailboxID int, numKind imapserver.NumKind, criteria *imap.SearchCriteria) ([]Message, error) {

	// Start building the query using a common table expression (CTE) to calculate sequence numbers
	baseQuery := `
		WITH message_seqs AS (
			SELECT 
				id,
				ROW_NUMBER() OVER (ORDER BY internal_date ASC) AS seq_num
			FROM 
				messages
			WHERE 
				mailbox_id = $1 
				AND expunged_at IS NULL
		)`
	args := []interface{}{mailboxID}

	// Start building the main query based on the CTE
	query := "SELECT id FROM message_seqs WHERE 1=1"
	pos := 2 // Start from 2 since mailbox_id is $1

	// Handle sequence number or UID search
	if numKind == imapserver.NumKindSeq && len(criteria.SeqNum) > 0 {
		seqNums, _ := criteria.SeqNum[0].Nums()
		query += fmt.Sprintf(" AND seq_num = ANY($%d)", pos)
		args = append(args, seqNums)
		pos++
	} else if numKind == imapserver.NumKindUID && len(criteria.UID) > 0 {
		uids, _ := criteria.UID[0].Nums()
		query += fmt.Sprintf(" AND id = ANY($%d)", pos)
		args = append(args, uids)
		pos++
	}

	// Handle date filters
	if !criteria.Since.IsZero() {
		query += fmt.Sprintf(" AND internal_date >= $%d", pos)
		args = append(args, criteria.Since)
		pos++
	}
	if !criteria.Before.IsZero() {
		query += fmt.Sprintf(" AND internal_date <= $%d", pos)
		args = append(args, criteria.Before)
		pos++
	}
	if !criteria.SentSince.IsZero() {
		query += fmt.Sprintf(" AND sent_date >= $%d", pos)
		args = append(args, criteria.SentSince)
		pos++
	}
	if !criteria.SentBefore.IsZero() {
		query += fmt.Sprintf(" AND sent_date <= $%d", pos)
		args = append(args, criteria.SentBefore)
		pos++
	}

	// Handle subject search from the `messages` table
	for _, header := range criteria.Header {
		switch strings.ToLower(header.Key) {
		case "subject":
			query += fmt.Sprintf(" AND LOWER(subject) LIKE $%d", pos)
			args = append(args, "%"+strings.ToLower(header.Value)+"%")
			pos++
		}
	}

	// Handle recipient search from the `recipients` table
	for _, header := range criteria.Header {
		switch strings.ToLower(header.Key) {
		case "to", "cc", "bcc", "reply-to":
			query += fmt.Sprintf(" AND id IN (SELECT message_id FROM recipients WHERE LOWER(address_type) = $%d AND LOWER(email_address) LIKE $%d)", pos, pos+1)
			args = append(args, strings.ToLower(header.Key), "%"+strings.ToLower(header.Value)+"%")
			pos += 2
		}
	}

	if criteria.Body != nil {
		for _, bodyCriteria := range criteria.Body {
			query += fmt.Sprintf(" AND text_body_tsv @@ plainto_tsquery($%d)", pos)
			args = append(args, bodyCriteria)
			pos++
		}
	}

	// Handle flags
	if len(criteria.Flag) > 0 {
		for _, flag := range criteria.Flag {
			query += fmt.Sprintf(" AND (flags & $%d) != 0", pos)
			args = append(args, FlagToBitwise(flag)) // Convert the flag to its bitwise value
			pos++
		}
	}
	if len(criteria.NotFlag) > 0 {
		for _, flag := range criteria.NotFlag {
			query += fmt.Sprintf(" AND (flags & $%d) = 0", pos)
			args = append(args, FlagToBitwise(flag)) // Convert the flag to its bitwise value
			pos++
		}
	}

	// Handle message size
	if criteria.Larger > 0 {
		query += fmt.Sprintf(" AND size > $%d", pos)
		args = append(args, criteria.Larger)
		pos++
	}
	if criteria.Smaller > 0 {
		query += fmt.Sprintf(" AND size < $%d", pos)
		args = append(args, criteria.Smaller)
		pos++
	}

	// Finalize the query
	query += " ORDER BY id"

	rows, err := db.Pool.Query(ctx, baseQuery+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var message Message
		err := rows.Scan(&message.ID)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}

	// Check if there was any error during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

func (db *Database) GetMessagesByFlag(ctx context.Context, mailboxID int, flag imap.Flag) ([]Message, error) {
	// Convert the IMAP flag to its corresponding bitwise value
	bitwiseFlag := FlagToBitwise(flag)
	rows, err := db.Pool.Query(ctx, `
		SELECT id FROM messages WHERE mailbox_id = $1 AND (flags & $2) != 0 AND expunged_at IS NULL
	`, mailboxID, bitwiseFlag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

func (db *Database) GetMailboxUpdates(ctx context.Context, mailboxID int, since time.Time) ([]MessageUpdate, int, error) {
	// Define a slice to hold the message updates
	var updates []MessageUpdate

	// Fetch messages added, flagged, or expunged since the last poll
	rows, err := db.Pool.Query(ctx, `
		SELECT id, ROW_NUMBER() OVER (ORDER BY internal_date ASC) AS seq_num, flags, deleted_at, flags_changed_at 
		FROM messages 
		WHERE 
			mailbox_id = $1 
			AND (internal_date > $2 OR flags_changed_at > $2 OR deleted_at > $2)
			AND expunged_at IS NULL
		ORDER BY 
			seq_num ASC
	`, mailboxID, since)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query mailbox updates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var update MessageUpdate
		var deletedAt sql.NullTime
		var flagsChangedAt sql.NullTime

		// Scan the row values
		if err := rows.Scan(&update.ID, &update.SeqNum, &update.BitwiseFlags, &deletedAt, &flagsChangedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan mailbox updates: %w", err)
		}

		// Determine if the message is expunged
		update.IsExpunge = deletedAt.Valid

		// Determine if the flags have changed
		update.FlagsChanged = flagsChangedAt.Valid && flagsChangedAt.Time.After(since)

		// Append the update to the list
		updates = append(updates, update)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating through mailbox updates: %w", err)
	}

	// Fetch the current number of non-expunged messages in the mailbox
	var numMessages int
	err = db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL
	`, mailboxID).Scan(&numMessages)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count messages in mailbox: %w", err)
	}

	return updates, numMessages, nil
}

func (db *Database) GetUserIDByAddress(ctx context.Context, username string) (int, error) {
	var userId int
	username = strings.ToLower(username)
	err := db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE username = $1", username).Scan(&userId)
	if err != nil {
		if err == pgx.ErrNoRows {
			return -1, consts.ErrUserNotFound
		}
		return -1, err
	}
	return userId, nil
}

func (db *Database) ListMessages(ctx context.Context, mailboxID int) ([]Message, error) {
	var messages []Message

	query := `
			SELECT id, size, s3_uuid
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
			ORDER BY id
	`
	rows, err := db.Pool.Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.Size, &msg.S3UUID); err != nil {
			return nil, fmt.Errorf("failed to scan message: %v", err)
		}
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error fetching messages: %v", err)
	}

	return messages, nil
}
