package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

func (d *Database) InsertMessageCopy(ctx context.Context, srcMessageUID imap.UID, srcMailboxID int64, destMailboxID int64, destMailboxName string) (imap.UID, error) {
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

	var highestUID int64
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

	// Log the destination mailbox name for debugging
	log.Printf("Copying message to mailbox '%s'", destMailboxName)

	// Get the updated_modseq of the source message to use for the created_modseq of the copy
	var srcUpdatedModSeq int64 // This variable is fetched but not directly used for created_modseq in the INSERT below.
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(updated_modseq, created_modseq) 
		FROM messages 
		WHERE mailbox_id = $1 AND uid = $2
	`, srcMailboxID, srcMessageUID).Scan(&srcUpdatedModSeq)
	if err != nil {
		log.Printf("Failed to get source message modseq: %v", err)
		return 0, consts.ErrDBQueryFailed
	}

	var newMsgUID imap.UID
	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, content_hash, message_id, flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, uploaded, recipients_json, created_modseq)
		SELECT
			account_id, $1, $2, $3, content_hash, message_id, flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, uploaded, recipients_json, nextval('messages_modseq')
		FROM
			messages
		WHERE
			mailbox_id = $4 AND
			uid = $5
		RETURNING uid
	`, destMailboxID, destMailboxName, highestUID, srcMailboxID, srcMessageUID).Scan(&newMsgUID)

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

	// No explicit copy into message_contents is needed here.
	// Since content_hash is the same, the entry in message_contents (if it exists for this hash)
	// would have been created by the original InsertMessage (or a previous copy)
	// due to the ON CONFLICT (content_hash) DO NOTHING clause in InsertMessage.

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return 0, consts.ErrDBCommitTransactionFailed
	}

	return newMsgUID, nil
}

type InsertMessageOptions struct {
	UserID      int64
	MailboxID   int64
	MailboxName string
	ContentHash string
	MessageID   string
	// CustomFlags are handled by splitting options.Flags in InsertMessage
	Flags         []imap.Flag
	InternalDate  time.Time
	Size          int64
	Subject       string
	PlaintextBody string
	SentDate      time.Time
	InReplyTo     []string
	BodyStructure *imap.BodyStructure
	Recipients    []helpers.Recipient
	RawHeaders    string
}

func (d *Database) InsertMessage(ctx context.Context, options *InsertMessageOptions, upload PendingUpload) (messageID int64, uid int64, err error) {
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	if saneMessageID == "" {
		log.Printf("MessageID is empty after sanitization, generating a new one without modifying the message.")
		// Generate a new message ID if not provided
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), options.MailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		log.Printf("Failed to serialize BodyStructure: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	if options.InternalDate.IsZero() {
		options.InternalDate = time.Now()
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return 0, 0, consts.ErrDBBeginTransactionFailed
	}
	defer tx.Rollback(ctx)

	var highestUID int64

	// Lock mailbox and get current UID
	err = tx.QueryRow(ctx, `SELECT highest_uid FROM mailboxes WHERE id = $1 FOR UPDATE;`, options.MailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to fetch highest UID: %v", err)
		return 0, 0, consts.ErrDBQueryFailed
	}

	// Bump UID
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("Failed to update highest UID: %v", err)
		return 0, 0, consts.ErrDBUpdateFailed
	}

	recipientsJSON, err := json.Marshal(options.Recipients)
	if err != nil {
		log.Printf("Failed to marshal recipients: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	inReplyToStr := strings.Join(options.InReplyTo, " ")

	systemFlagsToSet, customKeywordsToSet := SplitFlags(options.Flags)
	bitwiseFlags := FlagsToBitwise(systemFlagsToSet)

	var customKeywordsJSON []byte
	if len(customKeywordsToSet) == 0 {
		customKeywordsJSON = []byte("[]")
	} else {
		customKeywordsJSON, err = json.Marshal(customKeywordsToSet)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to marshal custom keywords for InsertMessage: %w", err)
		}
	}

	var messageRowId int64

	// Sanitize inputs
	saneSubject := helpers.SanitizeUTF8(options.Subject)
	saneInReplyToStr := helpers.SanitizeUTF8(inReplyToStr)
	sanePlaintextBody := helpers.SanitizeUTF8(options.PlaintextBody)

	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, created_modseq)
		VALUES
			(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @flags, @custom_flags, @internal_date, @size, @subject, @sent_date, @in_reply_to, @body_structure, @recipients_json, nextval('messages_modseq'))
		RETURNING id
	`, pgx.NamedArgs{
		"account_id":      options.UserID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    options.MailboxName,
		"uid":             highestUID,
		"message_id":      saneMessageID,
		"content_hash":    options.ContentHash,
		"flags":           bitwiseFlags,
		"custom_flags":    customKeywordsJSON,
		"internal_date":   options.InternalDate,
		"size":            options.Size,
		"subject":         saneSubject,
		"sent_date":       options.SentDate,
		"in_reply_to":     saneInReplyToStr,
		"body_structure":  bodyStructureData,
		"recipients_json": recipientsJSON,
	}).Scan(&messageRowId)

	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			// Unique constraint violation. Check if it's due to message_id and if we can return the existing message.
			// The saneMessageID was used in the INSERT attempt.

			log.Printf("Unique constraint violation for MessageID '%s' in MailboxID %d. Attempting to find existing message.", saneMessageID, options.MailboxID)
			var existingID, existingUID int64
			// Query within the same transaction. If we return successfully from here,
			// the defer tx.Rollback(ctx) will roll back the attempted INSERT and UID bump.
			queryErr := tx.QueryRow(ctx,
				`SELECT id, uid FROM messages 
					 WHERE account_id = $1 AND mailbox_id = $2 AND message_id = $3 AND expunged_at IS NULL`,
				options.UserID, options.MailboxID, saneMessageID).Scan(&existingID, &existingUID)

			if queryErr == nil {
				log.Printf("Found existing message for MessageID '%s' in MailboxID %d. Returning existing ID: %d, UID: %d. Current transaction will be rolled back.", saneMessageID, options.MailboxID, existingID, existingUID)
				return existingID, existingUID, nil // Return existing message details
			} else if errors.Is(queryErr, pgx.ErrNoRows) {
				// This is unexpected: unique constraint fired, but we can't find the row by message_id.
				// Could be a conflict on UID or another unique constraint.
				log.Printf("Unique constraint violation for MailboxID %d (MessageID '%s'), but no existing non-expunged message found by this MessageID. Falling back to unique violation error. Lookup error: %v", options.MailboxID, saneMessageID, queryErr)
			} else {
				// Error during the lookup query
				log.Printf("Error querying for existing message after unique constraint violation (MailboxID %d, MessageID '%s'): %v. Falling back to unique violation error.", options.MailboxID, saneMessageID, queryErr)
			}

			// Fallback to returning the original unique violation error if MessageID was empty or lookup failed.
			log.Printf("Original unique constraint violation error for MailboxID %d, MessageID '%s': %v", options.MailboxID, saneMessageID, err)
			return 0, 0, consts.ErrDBUniqueViolation // Original error
		}
		log.Printf("Failed to insert message into database: %v", err)
		return 0, 0, consts.ErrDBInsertFailed
	}

	// Insert into message_contents, using the message's content_hash as the key.
	// If a message_contents entry for this content_hash already exists, do nothing.
	// This handles deduplication of text_body for messages with identical content_hash.
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, headers_tsv)
		VALUES ($1, $2, to_tsvector('simple', $2), $3, to_tsvector('simple', $3))
		ON CONFLICT (content_hash) DO NOTHING
	`, options.ContentHash, sanePlaintextBody, options.RawHeaders)
	if err != nil {
		log.Printf("Failed to insert message content for content_hash %s: %v", options.ContentHash, err)
		return 0, 0, consts.ErrDBInsertFailed // Transaction will rollback
	}

	_, err = tx.Exec(ctx, `
	INSERT INTO pending_uploads (instance_id, content_hash, size, created_at)
	VALUES ($1, $2, $3, $4) ON CONFLICT (content_hash) DO NOTHING`,
		upload.InstanceID,
		options.ContentHash,
		upload.Size,
		time.Now(),
	)

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		return 0, 0, consts.ErrDBCommitTransactionFailed
	}

	return messageRowId, highestUID, nil
}
