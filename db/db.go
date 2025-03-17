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

// containsFlag checks if a slice of flags contains a specific flag
func (db *Database) containsFlag(flags []imap.Flag, flag imap.Flag) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

// uidNext     int
// readOnly    bool
// lastPollAt  time.Time
// numMessages int

type MessageUpdate struct {
	UID          imap.UID
	SeqNum       uint32
	BitwiseFlags int
	IsExpunge    bool
}

type MailboxPoll struct {
	Updates     []MessageUpdate
	NumMessages uint32
	ModSeq      uint64
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

func (d *Database) InsertMessageCopy(ctx context.Context, srcMessageUID imap.UID, srcMailboxID, destMailboxID int, s3UploadFunc func(imap.UID) error) (imap.UID, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return 0, consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	// Lock the message row for update
	_, err = tx.Exec(ctx, `
		SELECT FROM 
			messages 
		WHERE 
			uid = $1 AND
			mailbox_id = $2
		FOR UPDATE;`, srcMessageUID, srcMailboxID)
	if err != nil {
		log.Printf("Failed to lock message row: %v", err)
		return 0, consts.ErrDBQueryFailed
	}

	var highestUID int
	// Lock the mailbox row for update
	err = tx.QueryRow(ctx, `
		SELECT 
			highest_uid 
		FROM 
			mailboxes 
		WHERE 
			id = $1 
		FOR UPDATE;`, destMailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to fetch highest UID: %v", err)
		return 0, consts.ErrDBQueryFailed
	}

	// Update the highest UID
	err = tx.QueryRow(ctx, `
		UPDATE 
			mailboxes 
		SET 
			highest_uid = highest_uid + 1 
		WHERE 
			id = $1 
		RETURNING highest_uid`, destMailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to update highest UID: %v", err)
		return 0, consts.ErrDBUpdateFailed
	}

	var newMsgUID imap.UID
	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(mailbox_id, uid, storage_uuid, message_id, flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, text_body, text_body_tsv, created_modseq)
		SELECT
			$1, $2, storage_uuid, message_id, flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, text_body, text_body_tsv, nextval('messages_modseq')
		FROM
			messages
		WHERE
			mailbox_id = $3 AND
			uid = $4
		RETURNING uid
	`, destMailboxID, highestUID, srcMailboxID, srcMessageUID).Scan(&newMsgUID)

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

	err = s3UploadFunc(newMsgUID)
	if err != nil {
		return 0, consts.ErrS3UploadFailed
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return 0, consts.ErrDBCommitTransactionFailed
	}

	return newMsgUID, nil
}

type InsertMessageOptions struct {
	MailboxID     int
	UUIDKey       uuid.UUID
	MessageID     string
	Flags         []imap.Flag
	InternalDate  time.Time
	Size          int64
	Subject       string
	PlaintextBody *string
	SentDate      time.Time
	InReplyTo     []string
	S3Buffer      *bytes.Buffer
	BodyStructure *imap.BodyStructure
	Recipients    []Recipient
	S3UploadFunc  func(uuid.UUID, *bytes.Buffer, int64) error
}

func (d *Database) InsertMessage(ctx context.Context, options *InsertMessageOptions) (int, error) {
	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
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

	var highestUID int
	// Lock the mailbox row for update
	err = tx.QueryRow(ctx, `SELECT highest_uid FROM mailboxes WHERE id = $1 FOR UPDATE;`, options.MailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to fetch highest UID: %v", err)
		return 0, consts.ErrDBQueryFailed
	}

	// Update the highest UID
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to update highest UID: %v", err)
		return 0, consts.ErrDBUpdateFailed
	}

	// Convert the inReplyTo slice to a space-separated string
	inReplyToStr := strings.Join(options.InReplyTo, " ")
	bitwiseFlags := FlagsToBitwise(options.Flags)
	var id int
	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(mailbox_id, uid, message_id, storage_uuid, flags, internal_date, size, text_body, text_body_tsv, subject, sent_date, in_reply_to, body_structure, created_modseq)
		VALUES
			(@mailbox_id, @uid, @message_id, @storage_uuid, @flags, @internal_date, @size, @text_body, to_tsvector('simple', @text_body), @subject, @sent_date, @in_reply_to, @body_structure, nextval('messages_modseq'))
		RETURNING id
	`, pgx.NamedArgs{
		"mailbox_id":     options.MailboxID,
		"uid":            highestUID,
		"message_id":     options.MessageID,
		"storage_uuid":   options.UUIDKey,
		"flags":          bitwiseFlags,
		"internal_date":  options.InternalDate,
		"size":           options.Size,
		"text_body":      options.PlaintextBody,
		"subject":        options.Subject,
		"sent_date":      options.SentDate,
		"in_reply_to":    inReplyToStr,
		"body_structure": bodyStructureData,
	}).Scan(&id)

	if err != nil {
		// If unique constraint violation, return an error
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			log.Printf("Message with ID %s already exists in mailbox %d", options.MessageID, options.MailboxID)
			return 0, consts.ErrDBUniqueViolation
		}
		log.Printf("Failed to insert message into database: %v", err)
		return 0, consts.ErrDBInsertFailed
	}

	// Insert recipients into the database
	for _, recipient := range options.Recipients {
		_, err = tx.Exec(ctx, `
				INSERT INTO recipients (message_id, address_type, name, email_address)
				VALUES ($1, $2, $3, $4)
			`, id, recipient.AddressType, recipient.Name, recipient.EmailAddress)
		if err != nil {
			log.Printf("Failed to insert recipient: %v", err)
			return 0, consts.ErrDBInsertFailed
		}
	}

	err = options.S3UploadFunc(options.UUIDKey, options.S3Buffer, options.Size)
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
					storage_uuid, 
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
					flags_changed_at,
					created_modseq
			)
			SELECT
					storage_uuid, 
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
					NOW() AS flags_changed_at,
					nextval('messages_modseq')
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

func (db *Database) GetMessageBodyStructure(ctx context.Context, messageUID imap.UID, mailboxID int) (*imap.BodyStructure, error) {
	var bodyStructureBytes []byte

	err := db.Pool.QueryRow(ctx, `
			SELECT 
				body_structure
			FROM 
				messages
			WHERE 
				uid = $1 AND 
				mailbox_id = $2 AND
				expunged_at IS NULL`, messageUID, mailboxID).Scan(&bodyStructureBytes)
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

	query := `
		SELECT * FROM (
			SELECT uid, mailbox_id, storage_uuid, flags, internal_date, size, body_structure,
				row_number() OVER (ORDER BY id) AS seqnum
			FROM messages
			WHERE
				mailbox_id = $1 AND
				expunged_at IS NULL
		) AS sub WHERE false
	`
	args := []interface{}{mailboxID}

	switch set := numSet.(type) {
	case imap.SeqSet:
		for _, seqRange := range set {
			query += " OR (true"
			if seqRange.Start != 0 {
				args = append(args, seqRange.Start)
				query += fmt.Sprintf(" AND seqnum >= $%d", len(args))
			}
			if seqRange.Stop != 0 {
				args = append(args, seqRange.Stop)
				query += fmt.Sprintf(" AND seqnum <= $%d", len(args))
			}
			query += ")"
		}
	case imap.UIDSet:
		for _, uidRange := range set {
			query += " OR (true"
			if uidRange.Start != 0 {
				args = append(args, uint32(uidRange.Start))
				query += fmt.Sprintf(" AND uid >= $%d", len(args))
			}
			if uidRange.Stop != 0 {
				args = append(args, uint32(uidRange.Stop))
				query += fmt.Sprintf(" AND uid <= $%d", len(args))
			}
			query += ")"
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
		if err := rows.Scan(&msg.UID, &msg.MailboxID, &msg.StorageUUID, &msg.BitwiseFlags, &msg.InternalDate, &msg.Size, &bodyStructureBytes, &msg.Seq); err != nil {
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

func (db *Database) SetMessageFlags(ctx context.Context, messageID imap.UID, mailboxID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)
	deletedAt := sql.NullTime{}
	if db.containsFlag(newFlags, imap.FlagDeleted) {
		deletedAt = sql.NullTime{Time: time.Now(), Valid: true}
	}
	err := db.Pool.QueryRow(ctx, `
		UPDATE messages
		SET flags = $1, flags_changed_at = $2, deleted_at = $3, updated_modseq = nextval('messages_modseq')
		WHERE uid = $4 AND mailbox_id = $5
		RETURNING flags
	`, flags, time.Now(), deletedAt, messageID, mailboxID).Scan(&updatedFlagsBitwise)
	if err != nil {
		return nil, err
	}
	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) AddMessageFlags(ctx context.Context, messageUID imap.UID, mailboxID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)

	// Check if the deleted flag is being added
	if db.containsFlag(newFlags, imap.FlagDeleted) {
		err := db.Pool.QueryRow(ctx, `
			UPDATE
				messages
			SET
				flags = flags | $1,
				flags_changed_at = $2,
				deleted_at = $3,
				updated_modseq = nextval('messages_modseq')
			WHERE
				uid = $4 AND
				mailbox_id = $5
			RETURNING flags`, flags, time.Now(), time.Now(), messageUID, mailboxID).Scan(&updatedFlagsBitwise)
		if err != nil {
			return nil, err
		}
	} else {
		err := db.Pool.QueryRow(ctx, `
			UPDATE
				messages
			SET
				flags = flags | $1,
				flags_changed_at = $2,
				updated_modseq = nextval('messages_modseq')
			WHERE
				uid = $3 AND
				mailbox_id = $4
			RETURNING flags`, flags, time.Now(), messageUID, mailboxID).Scan(&updatedFlagsBitwise)
		if err != nil {
			return nil, err
		}
	}

	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) RemoveMessageFlags(ctx context.Context, messageID imap.UID, mailboxID int, newFlags []imap.Flag) (*[]imap.Flag, error) {
	var updatedFlagsBitwise int
	flags := FlagsToBitwise(newFlags)
	negatedFlags := ^flags

	if db.containsFlag(newFlags, imap.FlagDeleted) {
		err := db.Pool.QueryRow(ctx, `
		UPDATE
			messages
		SET
			flags = flags & $1,
			flags_changed_at = $2,
			deleted_at = NULL,
			updated_modseq = nextval('messages_modseq')
		WHERE 
			uid = $3 AND
			mailbox_id = $4
		RETURNING flags`, negatedFlags, time.Now(), messageID, mailboxID).Scan(&updatedFlagsBitwise)
		if err != nil {
			return nil, err
		}
	} else {
		err := db.Pool.QueryRow(ctx, `
		UPDATE
			messages
		SET
			flags = flags & $1,
			flags_changed_at = $2,
			updated_modseq = nextval('messages_modseq')
		WHERE
			uid = $3 AND
			mailbox_id = $4
		RETURNING flags`, negatedFlags, time.Now(), messageID, mailboxID).Scan(&updatedFlagsBitwise)
		if err != nil {
			return nil, err
		}
	}
	updatedFlags := BitwiseToFlags(updatedFlagsBitwise)
	return &updatedFlags, nil
}

func (db *Database) ExpungeMessageUIDs(ctx context.Context, mailboxID int, uids ...imap.UID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE mailbox_id = $1 AND uid = ANY($2)
	`, mailboxID, uids)
	if err != nil {
		return err
	}
	return nil
}

// --- Recipients ---CREATE TABLE recipients (
func (db *Database) GetMessageEnvelope(ctx context.Context, UID imap.UID, mailboxID int) (*imap.Envelope, error) {
	var envelope imap.Envelope

	var inReplyTo string

	var messageId int
	err := db.Pool.QueryRow(ctx, `
        SELECT 
            id, internal_date, subject, in_reply_to, message_id 
        FROM 
            messages
        WHERE 
            uid = $1 AND
						mailbox_id = $2 AND
						expunged_at IS NULL
    `, UID, mailboxID).Scan(
		&messageId,
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
        SELECT 
					address_type, name, email_address
        FROM 
					recipients
        WHERE 
					message_id = $1
    `, messageId)
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
				uid,
				ROW_NUMBER() OVER (ORDER BY id) AS seq_num
			FROM
				messages
			WHERE
				mailbox_id = $1 AND
				expunged_at IS NULL
		)`
	args := []interface{}{mailboxID}

	// Start building the main query based on the CTE
	query := "SELECT uid FROM message_seqs WHERE 1=1"

	// Handle sequence number or UID search
	if numKind == imapserver.NumKindSeq && len(criteria.SeqNum) > 0 {
		seqNums, _ := criteria.SeqNum[0].Nums()
		args = append(args, seqNums)
		query += fmt.Sprintf(" AND seq_num = ANY($%d)", len(args))
	} else if numKind == imapserver.NumKindUID && len(criteria.UID) > 0 {
		uids, _ := criteria.UID[0].Nums()
		args = append(args, uids)
		query += fmt.Sprintf(" AND id = ANY($%d)", len(args))
	}

	// Handle date filters
	if !criteria.Since.IsZero() {
		args = append(args, criteria.Since)
		query += fmt.Sprintf(" AND internal_date >= $%d", len(args))
	}
	if !criteria.Before.IsZero() {
		args = append(args, criteria.Before)
		query += fmt.Sprintf(" AND internal_date <= $%d", len(args))
	}
	if !criteria.SentSince.IsZero() {
		args = append(args, criteria.SentSince)
		query += fmt.Sprintf(" AND sent_date >= $%d", len(args))
	}
	if !criteria.SentBefore.IsZero() {
		args = append(args, criteria.SentBefore)
		query += fmt.Sprintf(" AND sent_date <= $%d", len(args))
	}

	// Handle subject search from the `messages` table
	for _, header := range criteria.Header {
		switch strings.ToLower(header.Key) {
		case "subject":
			args = append(args, "%"+strings.ToLower(header.Value)+"%")
			query += fmt.Sprintf(" AND LOWER(subject) LIKE $%d", len(args))
		}
	}

	// Handle recipient search from the `recipients` table
	for _, header := range criteria.Header {
		switch strings.ToLower(header.Key) {
		case "to", "cc", "bcc", "reply-to":
			args = append(args, strings.ToLower(header.Key), "%"+strings.ToLower(header.Value)+"%")
			query += fmt.Sprintf(" AND id IN (SELECT message_id FROM recipients WHERE LOWER(address_type) = $%d AND LOWER(email_address) LIKE $%d)", len(args)-1, len(args))
		}
	}

	if criteria.Body != nil {
		for _, bodyCriteria := range criteria.Body {
			args = append(args, bodyCriteria)
			query += fmt.Sprintf(" AND text_body_tsv @@ plainto_tsquery($%d)", len(args))
		}
	}

	// Handle flags
	if len(criteria.Flag) > 0 {
		for _, flag := range criteria.Flag {
			args = append(args, FlagToBitwise(flag)) // Convert the flag to its bitwise value
			query += fmt.Sprintf(" AND (flags & $%d) != 0", len(args))
		}
	}
	if len(criteria.NotFlag) > 0 {
		for _, flag := range criteria.NotFlag {
			args = append(args, FlagToBitwise(flag)) // Convert the flag to its bitwise value
			query += fmt.Sprintf(" AND (flags & $%d) = 0", len(args))
		}
	}

	// Handle message size
	if criteria.Larger > 0 {
		args = append(args, criteria.Larger)
		query += fmt.Sprintf(" AND size > $%d", len(args))
	}
	if criteria.Smaller > 0 {
		args = append(args, criteria.Smaller)
		query += fmt.Sprintf(" AND size < $%d", len(args))
	}

	// Finalize the query
	query += " ORDER BY uid"

	rows, err := db.Pool.Query(ctx, baseQuery+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var message Message
		err := rows.Scan(&message.UID)
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
		SELECT uid FROM messages WHERE mailbox_id = $1 AND (flags & $2) != 0 AND expunged_at IS NULL
	`, mailboxID, bitwiseFlag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.UID); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

func (db *Database) PollMailbox(ctx context.Context, mailboxID int, sinceModSeq uint64) (*MailboxPoll, error) {
	// Use a transaction to ensure we have a consistent view of the mailbox
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Fetch messages updated or expunged since last poll
	rows, err := tx.Query(ctx, `
		SELECT id, seq_num, flags, expunged_modseq FROM (
			SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS seq_num, flags, created_modseq, updated_modseq, expunged_modseq
			FROM messages
			WHERE mailbox_id = $1 AND (expunged_modseq IS NULL OR expunged_modseq > $2)
		)
		WHERE
			(created_modseq <= $2 AND updated_modseq > $2 AND expunged_modseq IS NULL) OR
			(created_modseq <= $2 AND expunged_modseq > $2)
		ORDER BY
			seq_num DESC
	`, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query mailbox updates: %w", err)
	}
	defer rows.Close()

	var updates []MessageUpdate
	for rows.Next() {
		var (
			update         MessageUpdate
			expungedModSeq *int64
		)

		if err := rows.Scan(&update.UID, &update.SeqNum, &update.BitwiseFlags, &expungedModSeq); err != nil {
			return nil, fmt.Errorf("failed to scan mailbox updates: %w", err)
		}

		update.IsExpunge = expungedModSeq != nil

		updates = append(updates, update)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through mailbox updates: %w", err)
	}

	// Fetch the current number of non-expunged messages in the mailbox
	var numMessages uint32
	err = tx.QueryRow(ctx, `
		SELECT
			COUNT(*)
		FROM
			messages
		WHERE
			mailbox_id = $1 AND
			expunged_at IS NULL
	`, mailboxID).Scan(&numMessages)
	if err != nil {
		return nil, fmt.Errorf("failed to count messages in mailbox: %w", err)
	}

	var currentModSeq uint64
	err = tx.QueryRow(ctx, `SELECT last_value FROM messages_modseq`).Scan(&currentModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current modseq: %w", err)
	}

	return &MailboxPoll{
		Updates:     updates,
		NumMessages: numMessages,
		ModSeq:      currentModSeq,
	}, nil
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
			SELECT 
				uid, size, storage_uuid
			FROM 
				messages
			WHERE 
				mailbox_id = $1 AND 
				expunged_at IS NULL
			ORDER BY uid`
	rows, err := db.Pool.Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.UID, &msg.Size, &msg.StorageUUID); err != nil {
			return nil, fmt.Errorf("failed to scan message: %v", err)
		}
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error fetching messages: %v", err)
	}

	return messages, nil
}
