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

// uidNext     int
// readOnly    bool
// lastPollAt  time.Time
// numMessages int

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

// // GetSubscribedMailboxes retrieves only subscribed mailboxes for a user
// func (db *Database) GetSubscribedMailboxes(ctx context.Context, userID int) ([]DBMailbox, error) {
// 	rows, err := db.Pool.Query(ctx, `
// 		SELECT id, name, parent_id, parent_path, subscribed FROM mailboxes WHERE user_id = $1 AND subscribed = true
// 	`, userID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer rows.Close()

// 	var mailboxes []DBMailbox
// 	for rows.Next() {
// 		var mailboxID, parentID int
// 		var mailboxName, parentPath string
// 		var hasChildren bool
// 		var uidValidity uint32

// 		if err := rows.Scan(&mailboxID, &mailboxName, &uidValidity, &parentID, &parentPath, &hasChildren); err != nil {
// 			return nil, err
// 		}

// 		mailboxes = append(mailboxes, NewDBMailbox())
// 	}

// 	return mailboxes, nil
// }

// HasChildren checks if the given mailbox ID has any children (subfolders).
// func (db *Database) MailboxHasChildren(ctx context.Context, mailboxID int) (bool, error) {
// 	var count int
// 	err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM mailboxes WHERE parent_id = $1", mailboxID).Scan(&count)
// 	if err != nil {
// 		return false, err
// 	}
// 	return count > 0, nil
// }

// -- Messages --

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

	query := `
		SELECT * FROM (
			SELECT id, s3_uuid, flags, internal_date, size, body_structure,
				row_number() OVER (ORDER BY id) AS seqnum
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		) AS sub WHERE true
	`
	args := []interface{}{mailboxID}

	switch set := numSet.(type) {
	case imap.SeqSet:
		for _, seqRange := range set {
			if seqRange.Start != 0 {
				args = append(args, seqRange.Start)
				query += fmt.Sprintf(" AND seqnum >= $%d", len(args))
			}
			if seqRange.Stop != 0 {
				args = append(args, seqRange.Stop)
				query += fmt.Sprintf(" AND seqnum <= $%d", len(args))
			}
		}
	case imap.UIDSet:
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
		if err := rows.Scan(&msg.ID, &msg.S3UUID, &msg.BitwiseFlags, &msg.InternalDate, &msg.Size, &bodyStructureBytes, &msg.Seq); err != nil {
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
