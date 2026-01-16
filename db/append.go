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
	"github.com/migadu/sora/pkg/metrics"
)

// CopyMessages copies multiple messages from a source mailbox to a destination mailbox within a given transaction.
// It returns a map of old UIDs to new UIDs.
func (db *Database) CopyMessages(ctx context.Context, tx pgx.Tx, uids *[]imap.UID, srcMailboxID, destMailboxID int64, AccountID int64) (map[imap.UID]imap.UID, error) {
	messageUIDMap := make(map[imap.UID]imap.UID)
	if srcMailboxID == destMailboxID {
		return nil, fmt.Errorf("source and destination mailboxes cannot be the same")
	}

	// The caller is responsible for beginning and committing/rolling back the transaction.

	// Get the source message IDs and UIDs
	rows, err := tx.Query(ctx, `SELECT id, uid FROM messages WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL ORDER BY uid`, srcMailboxID, uids)
	if err != nil {
		return nil, consts.ErrInternalError
	}
	defer rows.Close()

	var messageIDs []int64
	var sourceUIDsForMap []imap.UID
	for rows.Next() {
		var messageID int64
		var sourceUID imap.UID
		if err := rows.Scan(&messageID, &sourceUID); err != nil {
			return nil, fmt.Errorf("failed to scan message ID and UID: %w", err)
		}
		messageIDs = append(messageIDs, messageID)
		sourceUIDsForMap = append(sourceUIDsForMap, sourceUID)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through source messages: %w", err)
	}

	if len(messageIDs) == 0 {
		return messageUIDMap, nil // No messages to copy
	}

	// Atomically increment highest_uid for the number of messages being copied.
	var newHighestUID int64
	numToCopy := int64(len(messageIDs))
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $1 WHERE id = $2 RETURNING highest_uid`, numToCopy, destMailboxID).Scan(&newHighestUID)
	if err != nil {
		return nil, consts.ErrDBUpdateFailed
	}

	// Calculate the new UIDs for the copied messages.
	var newUIDs []int64
	startUID := newHighestUID - numToCopy + 1
	for i, sourceUID := range sourceUIDsForMap {
		newUID := startUID + int64(i)
		newUIDs = append(newUIDs, newUID)
		messageUIDMap[sourceUID] = imap.UID(newUID)
	}

	// Fetch destination mailbox name within the same transaction
	var destMailboxName string
	if err := tx.QueryRow(ctx, "SELECT name FROM mailboxes WHERE id = $1", destMailboxID).Scan(&destMailboxName); err != nil {
		return nil, fmt.Errorf("failed to get destination mailbox name: %w", err)
	}

	// Delete any expunged messages in the destination mailbox that have the same message_id
	// as the messages we're about to copy. This prevents unique constraint violations.
	deleteResult, err := tx.Exec(ctx, `
		DELETE FROM messages
		WHERE mailbox_id = $1
		  AND message_id IN (SELECT message_id FROM messages WHERE id = ANY($2))
	`, destMailboxID, messageIDs)
	if err != nil {
		log.Printf("Database: ERROR - failed to delete conflicting tombstones in destination mailbox: %v", err)
		return nil, fmt.Errorf("failed to delete conflicting tombstones: %w", err)
	}
	if deleteResult.RowsAffected() > 0 {
		log.Printf("Database: deleted %d conflicting message(s) from destination mailbox before copy", deleteResult.RowsAffected())
	}

	// Batch insert the copied messages
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (
			account_id, content_hash, uploaded, message_id, in_reply_to, 
			subject, sent_date, internal_date, flags, custom_flags, size, 
			body_structure, recipients_json, s3_domain, s3_localpart,
			subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort,
			mailbox_id, mailbox_path, flags_changed_at, created_modseq, uid
		)
		SELECT 
			m.account_id, m.content_hash, m.uploaded, m.message_id, m.in_reply_to,
			m.subject, m.sent_date, m.internal_date, m.flags | $5, m.custom_flags, m.size,
			m.body_structure, m.recipients_json, m.s3_domain, m.s3_localpart,
			m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort,
			$1 AS mailbox_id,
			$2 AS mailbox_path, -- Use the fetched destination mailbox name
			NOW() AS flags_changed_at,
			nextval('messages_modseq'),
			d.new_uid
		FROM messages m
		JOIN unnest($3::bigint[], $4::bigint[]) AS d(message_id, new_uid) ON m.id = d.message_id
	`, destMailboxID, destMailboxName, messageIDs, newUIDs, FlagRecent)
	if err != nil {
		return nil, fmt.Errorf("failed to batch copy messages: %w", err)
	}

	return messageUIDMap, nil
}

type InsertMessageOptions struct {
	AccountID   int64
	MailboxID   int64
	MailboxName string
	S3Domain    string
	S3Localpart string
	ContentHash string
	MessageID   string
	// CustomFlags are handled by splitting options.Flags in InsertMessage
	Flags                []imap.Flag
	InternalDate         time.Time
	Size                 int64
	Subject              string
	PlaintextBody        string
	SentDate             time.Time
	InReplyTo            []string
	BodyStructure        *imap.BodyStructure
	Recipients           []helpers.Recipient
	RawHeaders           string
	PreservedUID         *uint32       // Optional: preserved UID from import
	PreservedUIDValidity *uint32       // Optional: preserved UIDVALIDITY from import
	FTSRetention         time.Duration // Optional: FTS retention period to skip old messages
}

func (d *Database) InsertMessage(ctx context.Context, tx pgx.Tx, options *InsertMessageOptions, upload PendingUpload) (messageID int64, uid int64, err error) {
	start := time.Now()
	defer func() {
		status := "success"
		if err != nil {
			// Check for duplicate key violation
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				status = "duplicate"
			} else {
				status = "error"
			}
		}
		metrics.DBQueryDuration.WithLabelValues("message_insert", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("message_insert", status, "write").Inc()
	}()

	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	if saneMessageID == "" {
		log.Printf("Database: messageID is empty after sanitization, generating a new one without modifying the message.")
		// Generate a new message ID if not provided
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), options.MailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		log.Printf("Database: failed to serialize BodyStructure: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	if options.InternalDate.IsZero() {
		options.InternalDate = time.Now()
	}

	var highestUID int64
	var uidToUse int64

	// Check UIDVALIDITY before deciding whether to use preserved UID
	if options.PreservedUID != nil && options.PreservedUIDValidity != nil {
		// Check if any messages already exist in this mailbox
		var hasMessages bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM messages
				WHERE mailbox_id = $1
				AND expunged_at IS NULL
				LIMIT 1
			)`, options.MailboxID).Scan(&hasMessages)
		if err != nil {
			log.Printf("Database: failed to check for existing messages: %v", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			log.Printf("Database: failed to query current UIDVALIDITY: %v", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					log.Printf("Database: UIDVALIDITY mismatch for mailbox %d: current=%d, requested=%d. Ignoring preserved UID, delivering normally.",
						options.MailboxID, currentUIDValidity, *options.PreservedUIDValidity)
				}

				// Clear preserved values to use normal auto-increment
				options.PreservedUID = nil
				options.PreservedUIDValidity = nil
			}
			// If UIDVALIDITY matches, continue with UID preservation
		} else {
			// First preserved message - set UIDVALIDITY (overriding auto-generated value)
			if currentUIDValidity != *options.PreservedUIDValidity {
				_, err = tx.Exec(ctx, `
					UPDATE mailboxes
					SET uid_validity = $2
					WHERE id = $1`,
					options.MailboxID, *options.PreservedUIDValidity)
				if err != nil {
					log.Printf("Database: failed to update UIDVALIDITY: %v", err)
					return 0, 0, consts.ErrDBUpdateFailed
				}
				log.Printf("Database: set UIDVALIDITY for mailbox %d from %d to %d (first preserved message)",
					options.MailboxID, currentUIDValidity, *options.PreservedUIDValidity)
			}
		}
	}

	// Now assign UID (either preserved or auto-increment based on above logic)
	if options.PreservedUID != nil {
		uidToUse = int64(*options.PreservedUID)

		// Update highest_uid if preserved UID is higher (handles out-of-order)
		err = tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = GREATEST(highest_uid, $2)
			WHERE id = $1
			RETURNING highest_uid`,
			options.MailboxID, uidToUse).Scan(&highestUID)
		if err != nil {
			log.Printf("Database: failed to update highest UID with preserved UID: %v", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			log.Printf("Database: failed to update highest UID: %v", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
		uidToUse = highestUID
	}

	// Deduplication: Check if message with same message_id already exists (regardless of content_hash)
	// The unique constraint is on (message_id, mailbox_id, expunged_at IS NULL), so we must check
	// for any existing message with this message_id to avoid unique violations.
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, options.MessageID).Scan(&existingUID, &existingContentHash)
	if err == nil {
		// Message with same message_id already exists
		if existingContentHash == options.ContentHash {
			// True duplicate (same Message-ID + same content) - skip insert
			log.Printf("Database: duplicate message detected (message_id=%s, content_hash=%s) in mailbox %d, skipping insert. Existing UID=%d",
				options.MessageID, options.ContentHash, options.MailboxID, existingUID)
		} else {
			// Same Message-ID but different content - this shouldn't happen in normal mail flow
			// but can occur during import if maildir has duplicates with same Message-ID header
			log.Printf("Database: message with same Message-ID but different content detected (message_id=%s, existing_hash=%s, new_hash=%s) in mailbox %d. Skipping insert to avoid unique violation. Existing UID=%d",
				options.MessageID, existingContentHash[:12], options.ContentHash[:12], options.MailboxID, existingUID)
		}
		return 0, existingUID, nil // Return 0 for messageID, existing UID
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		log.Printf("Database: failed to check for duplicate message: %v", err)
		return 0, 0, consts.ErrDBQueryFailed
	}
	// err == pgx.ErrNoRows means no duplicate found, continue with insert

	recipientsJSON, err := json.Marshal(options.Recipients)
	if err != nil {
		log.Printf("Database: failed to marshal recipients: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting.
	var subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort string
	// Use RFC 5256 subject normalization (strips Re:, Fwd:, etc. prefixes)
	subjectSort = helpers.SanitizeSubjectForSort(options.Subject)

	var fromFound, toFound, ccFound bool
	for _, r := range options.Recipients {
		switch r.AddressType {
		case "from":
			if !fromFound {
				fromNameSort = strings.ToLower(r.Name)
				fromEmailSort = strings.ToLower(r.EmailAddress)
				fromFound = true
			}
		case "to":
			if !toFound {
				toNameSort = strings.ToLower(r.Name)
				toEmailSort = strings.ToLower(r.EmailAddress)
				toFound = true
			}
		case "cc":
			if !ccFound {
				ccEmailSort = strings.ToLower(r.EmailAddress)
				ccFound = true
			}
		}
		if fromFound && toFound && ccFound {
			break
		}
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
	saneRawHeaders := helpers.SanitizeUTF8(options.RawHeaders)

	// Delete any expunged messages in the mailbox that have the same message_id
	// This prevents unique constraint violations when appending messages that were previously expunged
	deleteResult, err := tx.Exec(ctx, `
		DELETE FROM messages
		WHERE mailbox_id = $1
		  AND message_id = $2
	`, options.MailboxID, saneMessageID)
	if err != nil {
		log.Printf("Database: ERROR - failed to delete conflicting tombstones: %v", err)
		return 0, 0, fmt.Errorf("failed to delete conflicting tombstones: %w", err)
	}
	if deleteResult.RowsAffected() > 0 {
		log.Printf("Database: deleted %d conflicting message(s) from mailbox before append", deleteResult.RowsAffected())
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		VALUES
			(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @s3_domain, @s3_localpart, @flags, @custom_flags, @internal_date, @size, @subject, @sent_date, @in_reply_to, @body_structure, @recipients_json, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort)
		RETURNING id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    options.MailboxName,
		"s3_domain":       options.S3Domain,
		"s3_localpart":    options.S3Localpart,
		"uid":             uidToUse,
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
		"subject_sort":    subjectSort,
		"from_name_sort":  fromNameSort,
		"from_email_sort": fromEmailSort,
		"to_name_sort":    toNameSort,
		"to_email_sort":   toEmailSort,
		"cc_email_sort":   ccEmailSort,
	}).Scan(&messageRowId)

	if err != nil {
		// Check for a unique constraint violation specifically on the message_id.
		// Note: We check both old constraint name and new index name for backward compatibility during rolling deploys.
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			log.Printf("Database: unique constraint violation for MessageID '%s' in MailboxID %d. Returning error to caller.", saneMessageID, options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		log.Printf("Database: failed to insert message into database: %v", err)
		return 0, 0, consts.ErrDBInsertFailed
	}

	// Insert into message_contents. ON CONFLICT DO NOTHING handles content deduplication.
	// We always store headers for FTS. For the body, if the message is older than the FTS
	// retention period, we store NULL to save space but still generate the TSV for searching.
	var textBodyArg any = sanePlaintextBody
	if options.FTSRetention > 0 && options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		textBodyArg = nil
	}

	// For old messages, textBodyArg is NULL, but sanePlaintextBody is used for TSV generation.
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, headers_tsv)
		VALUES ($1, $2, to_tsvector('simple', $3), $4, to_tsvector('simple', $4))
		ON CONFLICT (content_hash) DO NOTHING
	`, options.ContentHash, textBodyArg, sanePlaintextBody, saneRawHeaders)
	if err != nil {
		log.Printf("Database: failed to insert message content for content_hash %s: %v", options.ContentHash, err)
		return 0, 0, consts.ErrDBInsertFailed // Transaction will rollback
	}

	_, err = tx.Exec(ctx, `
	INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
	VALUES ($1, $2, $3, $4, $5) ON CONFLICT (content_hash, account_id) DO NOTHING`,
		upload.InstanceID,
		upload.ContentHash,
		upload.Size,
		time.Now(),
		upload.AccountID,
	)
	if err != nil {
		log.Printf("Database: failed to insert into pending_uploads for content_hash %s: %v", upload.ContentHash, err)
		return 0, 0, consts.ErrDBInsertFailed // Transaction will rollback
	}

	return messageRowId, uidToUse, nil
}

func (d *Database) InsertMessageFromImporter(ctx context.Context, tx pgx.Tx, options *InsertMessageOptions) (messageID int64, uid int64, err error) {
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	if saneMessageID == "" {
		log.Printf("Database: messageID is empty after sanitization, generating a new one without modifying the message.")
		// Generate a new message ID if not provided
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), options.MailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		log.Printf("Database: failed to serialize BodyStructure: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	if options.InternalDate.IsZero() {
		options.InternalDate = time.Now()
	}

	var highestUID int64
	var uidToUse int64

	// Check UIDVALIDITY before deciding whether to use preserved UID
	if options.PreservedUID != nil && options.PreservedUIDValidity != nil {
		// Check if any messages already exist in this mailbox
		var hasMessages bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM messages
				WHERE mailbox_id = $1
				AND expunged_at IS NULL
				LIMIT 1
			)`, options.MailboxID).Scan(&hasMessages)
		if err != nil {
			log.Printf("Database: failed to check for existing messages: %v", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			log.Printf("Database: failed to query current UIDVALIDITY: %v", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					log.Printf("Database: UIDVALIDITY mismatch for mailbox %d: current=%d, requested=%d. Ignoring preserved UID, delivering normally.",
						options.MailboxID, currentUIDValidity, *options.PreservedUIDValidity)
				}

				// Clear preserved values to use normal auto-increment
				options.PreservedUID = nil
				options.PreservedUIDValidity = nil
			}
			// If UIDVALIDITY matches, continue with UID preservation
		} else {
			// First preserved message - set UIDVALIDITY (overriding auto-generated value)
			if currentUIDValidity != *options.PreservedUIDValidity {
				_, err = tx.Exec(ctx, `
					UPDATE mailboxes
					SET uid_validity = $2
					WHERE id = $1`,
					options.MailboxID, *options.PreservedUIDValidity)
				if err != nil {
					log.Printf("Database: failed to update UIDVALIDITY: %v", err)
					return 0, 0, consts.ErrDBUpdateFailed
				}
				log.Printf("Database: set UIDVALIDITY for mailbox %d from %d to %d (first preserved message)",
					options.MailboxID, currentUIDValidity, *options.PreservedUIDValidity)
			}
		}
	}

	// Now assign UID (either preserved or auto-increment based on above logic)
	if options.PreservedUID != nil {
		uidToUse = int64(*options.PreservedUID)

		// Update highest_uid if preserved UID is higher (handles out-of-order)
		err = tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = GREATEST(highest_uid, $2)
			WHERE id = $1
			RETURNING highest_uid`,
			options.MailboxID, uidToUse).Scan(&highestUID)
		if err != nil {
			log.Printf("Database: failed to update highest UID with preserved UID: %v", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		// The UPDATE statement implicitly locks the row, making a prior SELECT FOR UPDATE redundant
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			log.Printf("Database: failed to update highest UID: %v", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
		uidToUse = highestUID
	}

	// Deduplication: Check if message with same message_id already exists (regardless of content_hash)
	// The unique constraint is on (message_id, mailbox_id, expunged_at IS NULL), so we must check
	// for any existing message with this message_id to avoid unique violations.
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, options.MessageID).Scan(&existingUID, &existingContentHash)
	if err == nil {
		// Message with same message_id already exists
		if existingContentHash == options.ContentHash {
			// True duplicate (same Message-ID + same content) - skip insert
			log.Printf("Database: duplicate message detected (message_id=%s, content_hash=%s) in mailbox %d, skipping insert. Existing UID=%d",
				options.MessageID, options.ContentHash, options.MailboxID, existingUID)
		} else {
			// Same Message-ID but different content - this shouldn't happen in normal mail flow
			// but can occur during import if maildir has duplicates with same Message-ID header
			log.Printf("Database: message with same Message-ID but different content detected (message_id=%s, existing_hash=%s, new_hash=%s) in mailbox %d. Skipping insert to avoid unique violation. Existing UID=%d",
				options.MessageID, existingContentHash[:12], options.ContentHash[:12], options.MailboxID, existingUID)
		}
		return 0, existingUID, nil // Return 0 for messageID, existing UID
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		log.Printf("Database: failed to check for duplicate message: %v", err)
		return 0, 0, consts.ErrDBQueryFailed
	}
	// err == pgx.ErrNoRows means no duplicate found, continue with insert

	recipientsJSON, err := json.Marshal(options.Recipients)
	if err != nil {
		log.Printf("Database: failed to marshal recipients: %v", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting.
	var subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort string
	// Use RFC 5256 subject normalization (strips Re:, Fwd:, etc. prefixes)
	subjectSort = helpers.SanitizeSubjectForSort(options.Subject)

	var fromFound, toFound, ccFound bool
	for _, r := range options.Recipients {
		switch r.AddressType {
		case "from":
			if !fromFound {
				fromNameSort = strings.ToLower(r.Name)
				fromEmailSort = strings.ToLower(r.EmailAddress)
				fromFound = true
			}
		case "to":
			if !toFound {
				toNameSort = strings.ToLower(r.Name)
				toEmailSort = strings.ToLower(r.EmailAddress)
				toFound = true
			}
		case "cc":
			if !ccFound {
				ccEmailSort = strings.ToLower(r.EmailAddress)
				ccFound = true
			}
		}
		if fromFound && toFound && ccFound {
			break
		}
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
	saneRawHeaders := helpers.SanitizeUTF8(options.RawHeaders)

	err = tx.QueryRow(ctx, `
		INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		VALUES
			(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @s3_domain, @s3_localpart, @flags, @custom_flags, @internal_date, @size, @subject, @sent_date, @in_reply_to, @body_structure, @recipients_json, true, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort)
		RETURNING id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    options.MailboxName,
		"s3_domain":       options.S3Domain,
		"s3_localpart":    options.S3Localpart,
		"uid":             uidToUse,
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
		"subject_sort":    subjectSort,
		"from_name_sort":  fromNameSort,
		"from_email_sort": fromEmailSort,
		"to_name_sort":    toNameSort,
		"to_email_sort":   toEmailSort,
		"cc_email_sort":   ccEmailSort,
	}).Scan(&messageRowId)

	if err != nil {
		// Check for a unique constraint violation specifically on the message_id.
		// Note: We check both old constraint name and new index name for backward compatibility during rolling deploys.
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			log.Printf("Database: unique constraint violation for MessageID '%s' in MailboxID %d. Returning error to caller.", saneMessageID, options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		log.Printf("Database: failed to insert message into database: %v", err)
		return 0, 0, consts.ErrDBInsertFailed
	}

	// Insert into message_contents. ON CONFLICT DO NOTHING handles content deduplication.
	// We always store headers for FTS. For the body, if the message is older than the FTS
	// retention period, we store NULL to save space but still generate the TSV for searching.
	var textBodyArg any = sanePlaintextBody
	if options.FTSRetention > 0 && options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		textBodyArg = nil
	}

	// For old messages, textBodyArg is NULL, but sanePlaintextBody is used for TSV generation.
	_, err = tx.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, headers_tsv)
		VALUES ($1, $2, to_tsvector('simple', $3), $4, to_tsvector('simple', $4))
		ON CONFLICT (content_hash) DO NOTHING
	`, options.ContentHash, textBodyArg, sanePlaintextBody, saneRawHeaders)
	if err != nil {
		log.Printf("Database: failed to insert message content for content_hash %s: %v", options.ContentHash, err)
		return 0, 0, consts.ErrDBInsertFailed // Transaction will rollback
	}

	return messageRowId, uidToUse, nil
}
