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
	FTSRetention         time.Duration // Optional: skip creating message_contents entirely for messages older than this
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
	saneRawHeaders := helpers.SanitizeUTF8(options.RawHeaders)

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
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
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

	// ---- FTS INDEXING (best-effort, non-fatal) ----
	// Insert into message_contents AFTER the critical message row and pending_upload
	// are secured. This runs with a capped sub-context so the to_tsvector() trigger
	// cannot exhaust the write timeout budget. If this fails, the message is still
	// delivered and uploaded to S3 — it just won't be FTS-searchable.
	//
	// Skip message_contents entirely when the message is already past the FTS retention
	// window. Creating the row would only add immediate work for the cleanup worker.
	if options.FTSRetention == 0 || options.SentDate.IsZero() || !options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		// Decide what to store in message_contents.
		// Skip very large bodies/headers (>64KB) — the full content is always available in S3.
		// text_body is immediately cleared by the trigger after computing text_body_tsv,
		// so it is never actually persisted in the database.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		// Note: sanePlaintextBody and saneRawHeaders are already sanitized via SanitizeUTF8

		// Prevent PostgreSQL to_tsvector DOS vulnerability (context deadline exceeded)
		// by deleting excessively long tokens (e.g. base64 blobs, hex dumps) that cause O(N^2)
		// parsing behavior in the text search engine. FTS is only useful for human words anyway.
		safeFtsBody := helpers.RemoveLongTokens(sanePlaintextBody, 128)
		safeFtsHeaders := helpers.RemoveLongTokens(saneRawHeaders, 128)

		var textBodyArg any = safeFtsBody
		var headersArg any = safeFtsHeaders

		if len(safeFtsBody) > maxStoredBodySize {
			truncLen := maxStoredBodySize
			for truncLen > 0 && !utf8.RuneStart(safeFtsBody[truncLen]) {
				truncLen--
			}
			textBodyArg = safeFtsBody[:truncLen]
			logger.Info("Database: truncating text_body for FTS indexing to 64KB for very large message",
				"content_hash", truncateHash(options.ContentHash), "original_size_bytes", len(sanePlaintextBody))
			metrics.LargeBodyStorageSkipped.Inc()
		}
		if len(saneRawHeaders) > maxStoredBodySize {
			logger.Info("Database: skipping headers storage for very large headers",
				"content_hash", truncateHash(options.ContentHash), "size_bytes", len(saneRawHeaders))
			headersArg = ""
			metrics.LargeBodyStorageSkipped.Inc()
		}

		// Only insert when there is actual content. A missing message_contents row is
		// expected for old/large messages and is handled gracefully downstream (unsearchable).
		headersStr, _ := headersArg.(string)
		if textBodyArg != nil || headersStr != "" {
			// Use a SAVEPOINT to isolate the FTS INSERT. If the to_tsvector() trigger
			// times out or causes an error, ROLLBACK TO SAVEPOINT restores the transaction
			// to a clean state so the COMMIT succeeds with the critical data intact.
			// Without this, a cancelled query puts PostgreSQL in "aborted" state and the
			// COMMIT silently becomes a ROLLBACK, losing the message row.
			_, spErr := tx.Exec(ctx, "SAVEPOINT fts_insert")
			if spErr != nil {
				logger.Warn("Database: failed to create savepoint for FTS insert (non-fatal)",
					"content_hash", truncateHash(options.ContentHash), "err", spErr)
			} else {
				// Give FTS its own independent 10s budget. We rely exclusively on PostgreSQL's
				// server-side statement_timeout. We MUST use context.Background() here because
				// if a Go context deadline is exceeded during a pgx operation, pgx assumes the
				// connection is stuck and ungracefully closes the underlying TCP connection!
				// This bubbles up as "conn closed" and breaks the parent LMTP session.
				ftsCtx := context.Background()

				// Set PostgreSQL's statement_timeout as the enforcer.
				_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 10000") // 10 seconds

				// Prevent lock contention pile-ups during parallel LMTP delivery to multiple
				// recipients by taking a non-blocking advisory lock on the content_hash.
				// hashtext() deterministically maps the string to a 32-bit integer.
				var lockAcquired bool
				err = tx.QueryRow(ftsCtx, "SELECT pg_try_advisory_xact_lock(hashtext($1), 0)", options.ContentHash).Scan(&lockAcquired)

				if err != nil {
					logger.Warn("Database: failed to attempt advisory lock for FTS (non-fatal)", "err", err)
					// Proceed without lock to degrade gracefully
					lockAcquired = true
				}

				ftsOK := true
				if !lockAcquired {
					// Another parallel transaction is currently inserting this exact content_hash.
					// We can assume they'll succeed and we bypass the slow row lock.
					logger.Info("Database: skipping FTS insert due to concurrent indexing (advisory lock held)", "content_hash", truncateHash(options.ContentHash))
				} else {
					// Fast-path: Check if the message_contents row already exists.
					var exists bool
					err = tx.QueryRow(ftsCtx, "SELECT EXISTS(SELECT 1 FROM message_contents WHERE content_hash = $1)", options.ContentHash).Scan(&exists)
					if err != nil {
						ftsOK = false
						logger.Warn("Database: failed to check message_contents existence (non-fatal, message will be unsearchable)",
							"content_hash", truncateHash(options.ContentHash), "err", err)
					} else if !exists {
						_, err = tx.Exec(ftsCtx, `
							INSERT INTO message_contents (content_hash, text_body, headers, sent_date)
							VALUES ($1, $2, $3, $4)
							ON CONFLICT (content_hash) DO NOTHING
						`, options.ContentHash, textBodyArg, headersArg, options.SentDate)
						if err != nil {
							ftsOK = false
							logger.Warn("Database: failed to insert message content (non-fatal, message will be unsearchable)",
								"content_hash", truncateHash(options.ContentHash), "err", err)
						}
					}
				}

				// Clean up the savepoint: RELEASE on success, ROLLBACK on failure.
				// ftsCtx is context.Background() so it is safe to reuse here —
				// these are fast control-flow commands that must always succeed.
				if ftsOK {
					_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 0")
					_, _ = tx.Exec(ftsCtx, "RELEASE SAVEPOINT fts_insert")
				} else {
					_, _ = tx.Exec(ftsCtx, "ROLLBACK TO SAVEPOINT fts_insert")
					_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 0")
				}
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
	saneRawHeaders := helpers.SanitizeUTF8(options.RawHeaders)

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
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
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

	// Skip message_contents entirely when the message is already past the FTS retention
	// window. Creating the row would only add immediate work for the cleanup worker.
	if options.FTSRetention == 0 || options.SentDate.IsZero() || !options.SentDate.Before(time.Now().Add(-options.FTSRetention)) {
		// Decide what to store in message_contents.
		// Skip very large bodies/headers (>64KB) — the full content is always available in S3.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		var textBodyArg any = sanePlaintextBody
		var headersArg any = saneRawHeaders

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
		if len(saneRawHeaders) > maxStoredBodySize {
			logger.Info("Database: skipping headers storage for very large headers",
				"content_hash", truncateHash(options.ContentHash), "size_bytes", len(saneRawHeaders))
			headersArg = ""
			metrics.LargeBodyStorageSkipped.Inc()
		}

		// Only insert when there is actual content. A missing message_contents row is
		// expected for old/large messages and is handled gracefully downstream (unsearchable).
		headersStr, _ := headersArg.(string)
		if textBodyArg != nil || headersStr != "" {
			// Use a SAVEPOINT to isolate the FTS INSERT (same pattern as InsertMessage).
			_, spErr := tx.Exec(ctx, "SAVEPOINT fts_insert")
			if spErr != nil {
				logger.Warn("Database: failed to create savepoint for FTS insert (non-fatal)",
					"content_hash", truncateHash(options.ContentHash), "err", spErr)
			} else {
				// Give FTS its own independent 10s budget without Go-level cancellation.
				ftsCtx := context.Background()

				_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 10000") // 10 seconds

				var lockAcquired bool
				err = tx.QueryRow(ftsCtx, "SELECT pg_try_advisory_xact_lock(hashtext($1), 0)", options.ContentHash).Scan(&lockAcquired)
				if err != nil {
					logger.Warn("Database: failed to attempt advisory lock for FTS (non-fatal)", "err", err)
					lockAcquired = true // Proceed without lock to degrade gracefully
				}

				ftsOK := true
				if !lockAcquired {
					logger.Info("Database: skipping FTS insert due to concurrent indexing (advisory lock held)", "content_hash", truncateHash(options.ContentHash))
				} else {
					var exists bool
					err = tx.QueryRow(ftsCtx, "SELECT EXISTS(SELECT 1 FROM message_contents WHERE content_hash = $1)", options.ContentHash).Scan(&exists)
					if err != nil {
						ftsOK = false
						logger.Warn("Database: failed to check message_contents existence (non-fatal, message will be unsearchable)",
							"content_hash", truncateHash(options.ContentHash), "err", err)
					} else if !exists {
						_, err = tx.Exec(ftsCtx, `
							INSERT INTO message_contents (content_hash, text_body, headers, sent_date)
							VALUES ($1, $2, $3, $4)
							ON CONFLICT (content_hash) DO NOTHING
						`, options.ContentHash, textBodyArg, headersArg, options.SentDate)
						if err != nil {
							ftsOK = false
							logger.Warn("Database: failed to insert message content (non-fatal, message will be unsearchable)",
								"content_hash", truncateHash(options.ContentHash), "err", err)
						}
					}
				}

				// Clean up savepoint (see InsertMessage for rationale).
				if ftsOK {
					_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 0")
					_, _ = tx.Exec(ftsCtx, "RELEASE SAVEPOINT fts_insert")
				} else {
					_, _ = tx.Exec(ftsCtx, "ROLLBACK TO SAVEPOINT fts_insert")
					_, _ = tx.Exec(ftsCtx, "SET LOCAL statement_timeout = 0")
				}
			}
		}
	}

	return messageRowId, uidToUse, nil
}
