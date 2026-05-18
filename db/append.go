package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// truncateHash safely truncates a hash string for logging purposes
func truncateHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

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

	// Batch insert the copied messages.
	// RFC 3501 §2.3.2: \Recent is a session flag and must NOT be stored
	// persistently.  Preserve only the source message's existing flags.
	_, err = tx.Exec(ctx, `
		WITH src_data AS (
			SELECT 
				m.account_id, m.content_hash, m.uploaded, m.message_id, m.in_reply_to,
				m.subject, m.sent_date, m.internal_date, m.size,
				m.body_structure, m.recipients_json, m.s3_domain, m.s3_localpart,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort,
				m.id AS original_id,
				d.new_uid
			FROM messages m
			JOIN unnest($3::bigint[], $4::bigint[]) AS d(message_id, new_uid) ON m.id = d.message_id
		),
		inserted AS (
			INSERT INTO messages (
				account_id, content_hash, uploaded, message_id, in_reply_to, 
				subject, sent_date, internal_date, size, 
				body_structure, recipients_json, s3_domain, s3_localpart,
				subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort,
				mailbox_id, mailbox_path, created_modseq, uid
			)
			SELECT 
				account_id, content_hash, uploaded, message_id, in_reply_to,
				subject, sent_date, internal_date, size,
				body_structure, recipients_json, s3_domain, s3_localpart,
				subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort,
				$1 AS mailbox_id,
				$2 AS mailbox_path,
				nextval('messages_modseq'),
				new_uid
			FROM src_data
			RETURNING id, uid
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT i.id, $1, ms.flags, ms.custom_flags, NOW(), nextval('messages_modseq')
		FROM inserted i
		JOIN src_data s ON s.new_uid = i.uid
		JOIN message_state ms ON ms.message_id = s.original_id
	`, destMailboxID, destMailboxName, messageIDs, newUIDs)
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
	FTSRetention         time.Duration // Optional: skip creating messages_fts entirely for messages older than this
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

	// Sanitize user-controlled text fields that go into PostgreSQL text columns.
	// S3Domain, S3Localpart, and ContentHash are system-generated and don't need sanitization.
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	saneMailboxName := helpers.SanitizeUTF8(options.MailboxName)

	if saneMessageID == "" {
		logger.Info("Database: messageID is empty after sanitization, generating a new one without modifying the message")
		// Generate a new message ID if not provided
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), saneMailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		logger.Error("Database: failed to serialize BodyStructure", "err", err)
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
			logger.Error("Database: failed to check for existing messages", "err", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			logger.Error("Database: failed to query current UIDVALIDITY", "err", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					logger.Warn("Database: UIDVALIDITY mismatch, ignoring preserved UID and delivering normally",
						"mailbox_id", options.MailboxID, "current", currentUIDValidity, "requested", *options.PreservedUIDValidity)
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
					logger.Error("Database: failed to update UIDVALIDITY", "err", err)
					return 0, 0, consts.ErrDBUpdateFailed
				}
				logger.Info("Database: set UIDVALIDITY for first preserved message",
					"mailbox_id", options.MailboxID, "from", currentUIDValidity, "to", *options.PreservedUIDValidity)
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
			logger.Error("Database: failed to update highest UID with preserved UID", "err", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID", "err", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
		uidToUse = highestUID
	}

	// Check for existing EXACT duplicate message
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND content_hash = $3
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, saneMessageID, options.ContentHash).Scan(&existingUID, &existingContentHash)

	if err == nil {
		// True duplicate (same Message-ID + same content_hash) - skip insert
		logger.Info("Database: duplicate message detected, skipping insert", "message_id", saneMessageID, "content_hash", options.ContentHash, "mailbox_id", options.MailboxID, "existing_uid", existingUID)
		return 0, existingUID, consts.ErrMessageExists
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		logger.Error("Database: failed to check for duplicate message", "err", err)
		return 0, 0, consts.ErrDBQueryFailed
	}
	// err == pgx.ErrNoRows means no exact duplicate found, continue with insert

	// Sanitize recipients defensively before JSON marshaling.
	// json.Marshal encodes NULL bytes as \u0000, which PostgreSQL JSONB rejects (SQLSTATE 22P05).
	saneRecipients := make([]helpers.Recipient, len(options.Recipients))
	for i, r := range options.Recipients {
		saneRecipients[i] = helpers.Recipient{
			Name:         helpers.SanitizeUTF8(r.Name),
			EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
			AddressType:  r.AddressType,
		}
	}

	recipientsJSON, err := json.Marshal(saneRecipients)
	if err != nil {
		logger.Error("Database: failed to marshal recipients", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting.
	var subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort string
	// Use RFC 5256 subject normalization (strips Re:, Fwd:, etc. prefixes)
	// SanitizeSubjectForSort calls SanitizeUTF8 internally.
	subjectSort = helpers.SanitizeSubjectForSort(options.Subject)

	var fromFound, toFound, ccFound bool
	for _, r := range saneRecipients {
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

	err = tx.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
			VALUES
				(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @s3_domain, @s3_localpart, @internal_date, @size, @subject, @sent_date, @in_reply_to, @body_structure, @recipients_json, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort)
			RETURNING id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, @mailbox_id, @flags, @custom_flags, NOW(), nextval('messages_modseq') FROM inserted
		RETURNING message_id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    saneMailboxName,
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
		// Check for a unique constraint violation
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx" ||
				pgErr.ConstraintName == "idx_messages_mailbox_id_uid") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			logger.Error("Database: unique constraint violation, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		// Log the actual error details for debugging
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			logger.Error("Database: failed to insert message into database",
				"err", err,
				"pg_code", pgErr.Code,
				"pg_message", pgErr.Message,
				"pg_detail", pgErr.Detail,
				"pg_constraint", pgErr.ConstraintName)
		} else {
			logger.Error("Database: failed to insert message into database", "err", err)
		}
		return 0, 0, consts.ErrDBInsertFailed
	}

	// Check if content is already uploaded for this account (content deduplication).
	// If so, mark this message as uploaded immediately without creating a pending_upload.
	//
	// IMPORTANT: Only consider non-expunged messages. Expunged messages may be pending
	// S3 cleanup — if we dedup against them, the new message gets marked uploaded=TRUE
	// without any S3 upload, and the cleaner then deletes the S3 object, leaving the
	// new message referencing a non-existent object (404 NoSuchKey on fetch).
	var alreadyUploaded bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM messages
			WHERE content_hash = $1
			  AND account_id = $2
			  AND uploaded = TRUE
			  AND expunged_at IS NULL
			LIMIT 1
		)
	`, options.ContentHash, upload.AccountID).Scan(&alreadyUploaded)
	if err != nil {
		logger.Error("Database: failed to check if content already uploaded", "content_hash", upload.ContentHash, "err", err)
		return 0, 0, consts.ErrDBQueryFailed
	}

	if alreadyUploaded {
		// Content already exists in S3 for this account - mark this message as uploaded immediately
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET uploaded = TRUE
			WHERE id = $1
		`, messageRowId)
		if err != nil {
			logger.Error("Database: failed to mark message as uploaded (dedup)", "content_hash", upload.ContentHash, "err", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
		logger.Info("Database: message marked as uploaded via content deduplication",
			"content_hash", truncateHash(options.ContentHash), "account_id", upload.AccountID)
	} else {
		// Content not yet uploaded - create pending_upload
		_, err = tx.Exec(ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (content_hash, account_id) DO NOTHING`,
			upload.InstanceID,
			upload.ContentHash,
			upload.Size,
			time.Now(),
			upload.AccountID,
		)
		if err != nil {
			logger.Error("Database: failed to insert into pending_uploads", "content_hash", upload.ContentHash, "err", err)
			return 0, 0, consts.ErrDBInsertFailed // Transaction will rollback
		}
		logger.Info("Database: pending_upload created",
			"content_hash", truncateHash(options.ContentHash), "account_id", upload.AccountID)
	}

	// ---- FTS STAGING QUEUE (best-effort, non-fatal) ----
	// Insert into messages_fts AFTER the critical message row and pending_upload
	// are secured. This safely enqueues the raw payloads for the background daemon
	// to asynchronously perform the expensive to_tsvector() conversion. If this fails, the message is still
	// delivered and uploaded to S3 — it just won't be FTS-searchable.
	//
	// Skip messages_fts entirely when the message is already past the FTS retention
	// window. Creating the row would only add immediate work for the cleanup worker.
	if options.FTSRetention == 0 || options.SentDate.IsZero() || !options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		// Decide what to store in messages_fts.
		// Skip very large bodies (>64KB) — the full content is always available in S3.
		// text_body is staged in messages_fts, then processed by fts_worker.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		var textBodyArg any = sanePlaintextBody

		if len(sanePlaintextBody) > maxStoredBodySize {
			truncLen := maxStoredBodySize
			for truncLen > 0 && !utf8.RuneStart(sanePlaintextBody[truncLen]) {
				truncLen--
			}
			textBodyArg = sanePlaintextBody[:truncLen]
			logger.Info("Database: truncating text_body for FTS indexing to 64KB for very large message",
				"content_hash", truncateHash(options.ContentHash), "original_size_bytes", len(sanePlaintextBody))
			metrics.LargeBodyStorageSkipped.Inc()
		}

		textBodyStr, _ := textBodyArg.(string)
		if textBodyStr != "" {
			_, saveErr := tx.Exec(ctx, "SAVEPOINT fts_insert")
			if saveErr == nil {
				_, err = tx.Exec(ctx, `
					INSERT INTO messages_fts (content_hash, text_body, sent_date)
					VALUES ($1, $2, $3)
					ON CONFLICT (content_hash) DO NOTHING
				`, options.ContentHash, textBodyArg, options.SentDate)
				if err != nil {
					tx.Exec(ctx, "ROLLBACK TO SAVEPOINT fts_insert")
					logger.Warn("Database: failed to insert message fts payload (non-fatal, message will be unsearchable)",
						"content_hash", truncateHash(options.ContentHash), "err", err)
				} else {
					tx.Exec(ctx, "RELEASE SAVEPOINT fts_insert")
				}
			} else {
				logger.Warn("Database: failed to create savepoint for fts_insert", "err", saveErr)
			}
		}
	}

	return messageRowId, uidToUse, nil
}

func (d *Database) InsertMessageFromImporter(ctx context.Context, tx pgx.Tx, options *InsertMessageOptions) (messageID int64, uid int64, err error) {
	// Sanitize user-controlled text fields that go into PostgreSQL text columns.
	// S3Domain, S3Localpart, and ContentHash are system-generated and don't need sanitization.
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	saneMailboxName := helpers.SanitizeUTF8(options.MailboxName)

	if saneMessageID == "" {
		logger.Info("Database: messageID is empty after sanitization, generating a new one without modifying the message")
		// Generate a new message ID if not provided
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), saneMailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		logger.Error("Database: failed to serialize BodyStructure", "err", err)
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
			logger.Error("Database: failed to check for existing messages", "err", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			logger.Error("Database: failed to query current UIDVALIDITY", "err", err)
			return 0, 0, consts.ErrDBQueryFailed
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					logger.Warn("Database: UIDVALIDITY mismatch, ignoring preserved UID and delivering normally",
						"mailbox_id", options.MailboxID, "current", currentUIDValidity, "requested", *options.PreservedUIDValidity)
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
					logger.Error("Database: failed to update UIDVALIDITY", "err", err)
					return 0, 0, consts.ErrDBUpdateFailed
				}
				logger.Info("Database: set UIDVALIDITY for first preserved message",
					"mailbox_id", options.MailboxID, "from", currentUIDValidity, "to", *options.PreservedUIDValidity)
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
			logger.Error("Database: failed to update highest UID with preserved UID", "err", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		// The UPDATE statement implicitly locks the row, making a prior SELECT FOR UPDATE redundant
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID", "err", err)
			return 0, 0, consts.ErrDBUpdateFailed
		}
		uidToUse = highestUID
	}

	// Deduplication: Check if an EXACT duplicate exists (use sanitized message ID to match what's stored)
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND content_hash = $3
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, saneMessageID, options.ContentHash).Scan(&existingUID, &existingContentHash)
	if err == nil {
		// True duplicate (same Message-ID + same content) - skip insert
		logger.Info("Database: duplicate message detected, skipping insert", "message_id", saneMessageID, "content_hash", options.ContentHash, "mailbox_id", options.MailboxID, "existing_uid", existingUID)
		// Return unique violation error so importer can count it as skipped
		return 0, existingUID, consts.ErrDBUniqueViolation
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		logger.Error("Database: failed to check for duplicate message", "err", err)
		return 0, 0, consts.ErrDBQueryFailed
	}
	// err == pgx.ErrNoRows means no exact duplicate found, continue with insert

	// Sanitize recipients defensively before JSON marshaling.
	// json.Marshal encodes NULL bytes as \u0000, which PostgreSQL JSONB rejects (SQLSTATE 22P05).
	saneRecipients := make([]helpers.Recipient, len(options.Recipients))
	for i, r := range options.Recipients {
		saneRecipients[i] = helpers.Recipient{
			Name:         helpers.SanitizeUTF8(r.Name),
			EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
			AddressType:  r.AddressType,
		}
	}

	recipientsJSON, err := json.Marshal(saneRecipients)
	if err != nil {
		logger.Error("Database: failed to marshal recipients", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting.
	var subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort string
	// Use RFC 5256 subject normalization (strips Re:, Fwd:, etc. prefixes)
	// SanitizeSubjectForSort calls SanitizeUTF8 internally.
	subjectSort = helpers.SanitizeSubjectForSort(options.Subject)

	var fromFound, toFound, ccFound bool
	for _, r := range saneRecipients {
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

	err = tx.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
			VALUES
				(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @s3_domain, @s3_localpart, @internal_date, @size, @subject, @sent_date, @in_reply_to, @body_structure, @recipients_json, true, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort)
			RETURNING id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, @mailbox_id, @flags, @custom_flags, NOW(), nextval('messages_modseq') FROM inserted
		RETURNING message_id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    saneMailboxName,
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
		// Check for a unique constraint violation
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx" ||
				pgErr.ConstraintName == "idx_messages_mailbox_id_uid") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			logger.Error("Database: unique constraint violation, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		// Log the actual error details for debugging
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			logger.Error("Database: failed to insert message into database",
				"err", err,
				"pg_code", pgErr.Code,
				"pg_message", pgErr.Message,
				"pg_detail", pgErr.Detail,
				"pg_constraint", pgErr.ConstraintName)
		} else {
			logger.Error("Database: failed to insert message into database", "err", err)
		}
		return 0, 0, consts.ErrDBInsertFailed
	}

	// Skip messages_fts entirely when the message is already past the FTS retention
	// window. Creating the row would only add immediate work for the cleanup worker.
	if options.FTSRetention == 0 || options.SentDate.IsZero() || !options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		// Decide what to store in messages_fts.
		// Skip very large bodies (>64KB) — the full content is always available in S3.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		var textBodyArg any = sanePlaintextBody

		if len(sanePlaintextBody) > maxStoredBodySize {
			truncLen := maxStoredBodySize
			for truncLen > 0 && !utf8.RuneStart(sanePlaintextBody[truncLen]) {
				truncLen--
			}
			textBodyArg = sanePlaintextBody[:truncLen]
			logger.Info("Database: truncating text_body for FTS indexing to 64KB for very large message",
				"content_hash", truncateHash(options.ContentHash), "original_size_bytes", len(sanePlaintextBody))
			metrics.LargeBodyStorageSkipped.Inc()
		}

		// Only insert when there is actual content. A missing messages_fts row is
		// expected for old/large messages and is handled gracefully downstream (unsearchable).
		textBodyStr, _ := textBodyArg.(string)
		if textBodyStr != "" {
			_, saveErr := tx.Exec(ctx, "SAVEPOINT fts_insert")
			if saveErr == nil {
				_, err = tx.Exec(ctx, `
					INSERT INTO messages_fts (content_hash, text_body, sent_date)
					VALUES ($1, $2, $3)
					ON CONFLICT (content_hash) DO NOTHING
				`, options.ContentHash, textBodyArg, options.SentDate)
				if err != nil {
					tx.Exec(ctx, "ROLLBACK TO SAVEPOINT fts_insert")
					logger.Warn("Database: failed to insert message fts payload (non-fatal, message will be unsearchable)",
						"content_hash", truncateHash(options.ContentHash), "err", err)
				} else {
					tx.Exec(ctx, "RELEASE SAVEPOINT fts_insert")
				}
			} else {
				logger.Warn("Database: failed to create savepoint for fts_insert", "err", saveErr)
			}
		}
	}

	return messageRowId, uidToUse, nil
}

// InsertMessagesBatch performs a high-performance bulk insert of messages.
//
// Requirements:
// - All messages MUST belong to the same MailboxID and AccountID
// - Recommended batch size: 100-1000 messages (larger batches have diminishing returns)
// - Duplicates are automatically filtered before insert
//
// Returns:
// - messageIDs: Row IDs of successfully inserted messages
// - uids: Assigned UIDs (same length as messageIDs)
// - contentHashes: Content hashes of successfully inserted messages (same length as messageIDs)
// - error: Non-nil if batch fails (all-or-nothing semantics)
func (d *Database) InsertMessagesBatch(
	ctx context.Context,
	tx pgx.Tx,
	options []*InsertMessageOptions,
	uploads []PendingUpload,
) ([]int64, []int64, []string, error) {
	if len(options) == 0 {
		return nil, nil, nil, nil
	}

	mailboxID := options[0].MailboxID
	accountID := options[0].AccountID
	isImporter := len(uploads) == 0 // Importers don't pass pending uploads

	// 1. Validate that all options belong to the same mailbox and account
	for _, opt := range options {
		if opt.MailboxID != mailboxID {
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: mixed MailboxIDs in batch (expected %d, got %d)", mailboxID, opt.MailboxID)
		}
		if opt.AccountID != accountID {
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: mixed AccountIDs in batch (expected %d, got %d)", accountID, opt.AccountID)
		}
	}

	// 2. Pre-sanitize and process options
	type processedMessage struct {
		Opt                *InsertMessageOptions
		Upload             *PendingUpload
		SaneMessageID      string
		SaneMailboxName    string
		SaneSubject        string
		SanePlaintextBody  string
		SaneInReplyToStr   string
		BodyStructureData  []byte
		RecipientsJSON     []byte
		CustomKeywordsJSON []byte
		BitwiseFlags       int32
		SubjectSort        string
		FromNameSort       string
		FromEmailSort      string
		ToNameSort         string
		ToEmailSort        string
		CcEmailSort        string
		AssignedUID        int64
	}

	processed := make([]*processedMessage, 0, len(options))
	messageIDs := make([]string, 0, len(options))
	contentHashes := make([]string, 0, len(options))

	for i, opt := range options {
		saneMessageID := helpers.SanitizeUTF8(opt.MessageID)
		saneMailboxName := helpers.SanitizeUTF8(opt.MailboxName)
		if saneMessageID == "" {
			saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano()+int64(i), saneMailboxName)
		}

		bodyStructureData, err := helpers.SerializeBodyStructureGob(opt.BodyStructure)
		if err != nil {
			logger.Error("Database: failed to serialize BodyStructure in batch", "err", err)
			continue // Skip this message, but process others
		}

		if opt.InternalDate.IsZero() {
			opt.InternalDate = time.Now()
		}

		saneRecipients := make([]helpers.Recipient, len(opt.Recipients))
		for j, r := range opt.Recipients {
			saneRecipients[j] = helpers.Recipient{
				Name:         helpers.SanitizeUTF8(r.Name),
				EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
				AddressType:  r.AddressType,
			}
		}

		recipientsJSON, err := json.Marshal(saneRecipients)
		if err != nil {
			logger.Error("Database: failed to marshal recipients in batch", "err", err)
			continue
		}

		subjectSort := helpers.SanitizeSubjectForSort(opt.Subject)
		var fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort string
		var fromFound, toFound, ccFound bool
		for _, r := range saneRecipients {
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

		inReplyToStr := strings.Join(opt.InReplyTo, " ")
		systemFlagsToSet, customKeywordsToSet := SplitFlags(opt.Flags)
		bitwiseFlags := FlagsToBitwise(systemFlagsToSet)

		var customKeywordsJSON []byte
		if len(customKeywordsToSet) == 0 {
			customKeywordsJSON = []byte("[]")
		} else {
			customKeywordsJSON, err = json.Marshal(customKeywordsToSet)
			if err != nil {
				logger.Error("Database: failed to marshal custom keywords in batch", "err", err)
				continue
			}
		}

		var uploadPtr *PendingUpload
		if !isImporter && i < len(uploads) {
			uploadPtr = &uploads[i]
		}

		processed = append(processed, &processedMessage{
			Opt:                opt,
			Upload:             uploadPtr,
			SaneMessageID:      saneMessageID,
			SaneMailboxName:    saneMailboxName,
			SaneSubject:        helpers.SanitizeUTF8(opt.Subject),
			SanePlaintextBody:  helpers.SanitizeUTF8(opt.PlaintextBody),
			SaneInReplyToStr:   helpers.SanitizeUTF8(inReplyToStr),
			BodyStructureData:  bodyStructureData,
			RecipientsJSON:     recipientsJSON,
			CustomKeywordsJSON: customKeywordsJSON,
			BitwiseFlags:       int32(bitwiseFlags),
			SubjectSort:        subjectSort,
			FromNameSort:       fromNameSort,
			FromEmailSort:      fromEmailSort,
			ToNameSort:         toNameSort,
			ToEmailSort:        toEmailSort,
			CcEmailSort:        ccEmailSort,
		})
		messageIDs = append(messageIDs, saneMessageID)
		contentHashes = append(contentHashes, opt.ContentHash)
	}

	if len(processed) == 0 {
		return nil, nil, nil, nil
	}

	// 3. Deduplication (Find exact duplicates in one query)
	rows, err := tx.Query(ctx, `
		SELECT message_id, content_hash FROM messages 
		WHERE mailbox_id = $1 
		AND (message_id, content_hash) IN (SELECT * FROM UNNEST($2::text[], $3::text[]))
		AND expunged_at IS NULL
	`, mailboxID, messageIDs, contentHashes)

	if err != nil && err != pgx.ErrNoRows {
		return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed to check duplicates: %w", err)
	}

	duplicateSet := make(map[string]bool)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var msgID, hash string
			if err := rows.Scan(&msgID, &hash); err == nil {
				duplicateSet[msgID+"||"+hash] = true
			}
		}
	}

	// Filter out duplicates
	uniqueProcessed := make([]*processedMessage, 0, len(processed))
	for _, p := range processed {
		key := p.SaneMessageID + "||" + p.Opt.ContentHash
		if duplicateSet[key] {
			logger.Info("Database: duplicate message detected in batch, skipping", "message_id", p.SaneMessageID, "content_hash", p.Opt.ContentHash)
			continue
		}
		uniqueProcessed = append(uniqueProcessed, p)
	}

	if len(uniqueProcessed) == 0 {
		return nil, nil, nil, nil
	}

	// 4. Content Deduplication (Find already uploaded S3 hashes)
	uploadedHashesSet := make(map[string]bool)
	if !isImporter {
		uHashes := make([]string, 0, len(uniqueProcessed))
		for _, p := range uniqueProcessed {
			uHashes = append(uHashes, p.Opt.ContentHash)
		}
		uRows, err := tx.Query(ctx, `
			SELECT DISTINCT content_hash FROM messages
			WHERE account_id = $1 AND uploaded = TRUE AND content_hash = ANY($2) AND expunged_at IS NULL
		`, accountID, uHashes)
		if err == nil {
			defer uRows.Close()
			for uRows.Next() {
				var hash string
				if err := uRows.Scan(&hash); err == nil {
					uploadedHashesSet[hash] = true
				}
			}
		}
	}

	// 5. Bulk UID Allocation
	// Handle preserved UIDVALIDITY first
	if isImporter && uniqueProcessed[0].Opt.PreservedUID != nil && uniqueProcessed[0].Opt.PreservedUIDValidity != nil {
		var hasMessages bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL LIMIT 1)`, mailboxID).Scan(&hasMessages)
		var currentUIDValidity uint32
		_ = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, mailboxID).Scan(&currentUIDValidity)

		preservedValidity := *uniqueProcessed[0].Opt.PreservedUIDValidity
		if hasMessages && currentUIDValidity != preservedValidity {
			// UIDVALIDITY mismatch, fallback to normal append for all
			if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(mailboxID, true); !logged {
				logger.Warn("Database: UIDVALIDITY mismatch in batch, ignoring preserved UIDs", "mailbox_id", mailboxID)
			}
			for _, p := range uniqueProcessed {
				p.Opt.PreservedUID = nil
			}
		} else if !hasMessages && currentUIDValidity != preservedValidity {
			_, _ = tx.Exec(ctx, `UPDATE mailboxes SET uid_validity = $2 WHERE id = $1`, mailboxID, preservedValidity)
			logger.Info("Database: set UIDVALIDITY for first preserved message in batch", "mailbox_id", mailboxID)
		}
	}

	// Allocate UIDs
	var autoIncrementCount int
	var highestUID int64
	var maxPreservedUID int64

	for _, p := range uniqueProcessed {
		if p.Opt.PreservedUID != nil {
			u := int64(*p.Opt.PreservedUID)
			p.AssignedUID = u
			if u > maxPreservedUID {
				maxPreservedUID = u
			}
		} else {
			autoIncrementCount++
		}
	}

	if maxPreservedUID > 0 {
		_ = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = GREATEST(highest_uid, $2) WHERE id = $1 RETURNING highest_uid`, mailboxID, maxPreservedUID).Scan(&highestUID)
	}

	if autoIncrementCount > 0 {
		_ = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $2 WHERE id = $1 RETURNING highest_uid`, mailboxID, autoIncrementCount).Scan(&highestUID)
		// Distribute newly allocated UIDs (from lowest to highest)
		currentAutoUID := highestUID - int64(autoIncrementCount) + 1
		for _, p := range uniqueProcessed {
			if p.Opt.PreservedUID == nil {
				p.AssignedUID = currentAutoUID
				currentAutoUID++
			}
		}
	}

	// 6. Execute Inserts via pgx.Batch
	batch := &pgx.Batch{}

	for _, p := range uniqueProcessed {
		uploaded := isImporter || uploadedHashesSet[p.Opt.ContentHash]

		batch.Queue(`
			WITH inserted AS (
				INSERT INTO messages
					(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, in_reply_to, body_structure, recipients_json, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
				VALUES
					($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, nextval('messages_modseq'), $17, $18, $19, $20, $21, $22)
				RETURNING id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT id, $2, $23, $24, NOW(), nextval('messages_modseq') FROM inserted
			RETURNING message_id
		`,
			p.Opt.AccountID, mailboxID, p.SaneMailboxName, p.AssignedUID, p.SaneMessageID, p.Opt.ContentHash,
			p.Opt.S3Domain, p.Opt.S3Localpart, p.Opt.InternalDate, p.Opt.Size, p.SaneSubject, p.Opt.SentDate,
			p.SaneInReplyToStr, p.BodyStructureData, p.RecipientsJSON, uploaded, p.SubjectSort,
			p.FromNameSort, p.FromEmailSort, p.ToNameSort, p.ToEmailSort, p.CcEmailSort,
			p.BitwiseFlags, p.CustomKeywordsJSON,
		)

		if !uploaded && p.Upload != nil {
			batch.Queue(`
				INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
				VALUES ($1, $2, $3, NOW(), $4)
				ON CONFLICT (content_hash) DO NOTHING
			`, p.Upload.InstanceID, p.Upload.ContentHash, p.Upload.Size, p.Upload.AccountID)
		}

		if p.Opt.FTSRetention == 0 || !p.Opt.SentDate.IsZero() && p.Opt.SentDate.Before(time.Now().Add(-p.Opt.FTSRetention)) {
			// Skip FTS
		} else {
			const maxStoredBodySize = 64 * 1024 // 64 KB
			var textBodyArg any = p.SanePlaintextBody

			if len(p.SanePlaintextBody) > maxStoredBodySize {
				truncLen := maxStoredBodySize
				for truncLen > 0 && !utf8.RuneStart(p.SanePlaintextBody[truncLen]) {
					truncLen--
				}
				textBodyArg = p.SanePlaintextBody[:truncLen]
				metrics.LargeBodyStorageSkipped.Inc()
			}

			textBodyStr, _ := textBodyArg.(string)
			if textBodyStr != "" {
				batch.Queue(`
					INSERT INTO messages_fts (content_hash, text_body, sent_date)
					VALUES ($1, $2, $3)
					ON CONFLICT (content_hash) DO NOTHING
				`, p.Opt.ContentHash, textBodyArg, p.Opt.SentDate)
			}
		}
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()

	var insertedRowIDs []int64
	var insertedUIDs []int64
	var insertedHashes []string

	// pgx.Batch guarantees results are returned in the same order as queued
	for _, p := range uniqueProcessed {
		var rowID int64
		err := br.QueryRow().Scan(&rowID)
		if err != nil {
			// If unique constraint violation occurs during batch execution, we fail the batch
			if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
				return nil, nil, nil, consts.ErrDBUniqueViolation
			}
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed execution: %w", err)
		}
		insertedRowIDs = append(insertedRowIDs, rowID)
		insertedUIDs = append(insertedUIDs, p.AssignedUID)
		insertedHashes = append(insertedHashes, p.Opt.ContentHash)

		uploaded := isImporter || uploadedHashesSet[p.Opt.ContentHash]
		if !uploaded && p.Upload != nil {
			_, err = br.Exec() // pending_uploads
			if err != nil {
				return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed pending_upload: %w", err)
			}
		}

		if p.Opt.FTSRetention == 0 || !p.Opt.SentDate.IsZero() && p.Opt.SentDate.Before(time.Now().Add(-p.Opt.FTSRetention)) {
			// Skip FTS
		} else {
			textBodyStr, _ := p.SanePlaintextBody, false
			if len(p.SanePlaintextBody) > 64*1024 {
				textBodyStr = "..." // Mocked just to check if we queued it
			}
			if textBodyStr != "" {
				_, err = br.Exec() // messages_fts
				if err != nil {
					return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed messages_fts: %w", err)
				}
			}
		}
	}

	return insertedRowIDs, insertedUIDs, insertedHashes, nil
}

// InsertMessageFromImporterBatch is a wrapper for InsertMessagesBatch tailored for sora-admin import
func (d *Database) InsertMessagesFromImporterBatch(ctx context.Context, tx pgx.Tx, options []*InsertMessageOptions) ([]int64, []int64, []string, error) {
	return d.InsertMessagesBatch(ctx, tx, options, nil)
}
