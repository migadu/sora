package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
)

// Message struct to represent an email message
type Message struct {
	ID             int64      // ID of the message
	AccountID      int64      // ID of the user who owns the message
	UID            imap.UID   // Unique identifier for the message
	ContentHash    string     // Hash of the message content
	S3Domain       string     // S3 domain for the message
	S3Localpart    string     // S3 localpart for the message
	MailboxID      int64      // ID of the mailbox the message belongs to
	IsUploaded     bool       // Indicates if the message is uploaded to S3
	Seq            uint32     // Sequence number of the message in the mailbox
	BitwiseFlags   int        // Bitwise flags for the message (e.g., \Seen, \Flagged)
	CustomFlags    []string   // Custom flags for the message
	FlagsChangedAt *time.Time // Time when the flags were last changed
	Subject        string     // Subject of the message
	InternalDate   time.Time  // The internal date the message was received
	SentDate       time.Time  // The date the message was sent
	Size           int        // Size of the message in bytes
	MessageID      string     // Unique Message-ID from the message headers
	BodyStructure  *imap.BodyStructure
	CreatedModSeq  int64
	UpdatedModSeq  *int64
	InReplyTo      string
	RecipientsJSON []byte
	ExpungedModSeq *int64
}

// SearchMessageResult represents a lightweight slice of message metadata
// used exclusively for IMAP SEARCH/SORT operations to prevent massive
// data serialization over the database wire.
type SearchMessageResult struct {
	ID             int64
	UID            imap.UID
	MailboxID      int64
	ContentHash    string
	CreatedModSeq  int64
	UpdatedModSeq  *int64
	ExpungedModSeq *int64
	Seq            uint32
}

// MessagePart represents a part of an email message (e.g., body, attachments)
type MessagePart struct {
	MessageID  int64  // Reference to the message ID
	PartNumber int    // Part number (e.g., 1 for body, 2 for attachments)
	Size       int    // Size of the part in bytes
	S3Key      string // S3 key to reference the part's storage location
	Type       string // MIME type of the part (e.g., "text/plain", "text/html", "application/pdf")
}

// IMAP message flags as bitwise constants
const (
	FlagSeen     = 1 << iota // 1: 000001
	FlagAnswered             // 2: 000010
	FlagFlagged              // 4: 000100
	FlagDeleted              // 8: 001000
	FlagDraft                // 16: 010000
	FlagRecent               // 32: 100000
)

func ContainsFlag(flags int, flag int) bool {
	return flags&flag != 0
}

func FlagToBitwise(flag imap.Flag) int {
	switch strings.ToLower(string(flag)) {
	case "\\seen":
		return FlagSeen
	case "\\answered":
		return FlagAnswered
	case "\\flagged":
		return FlagFlagged
	case "\\deleted":
		return FlagDeleted
	case "\\draft":
		return FlagDraft
	case "\\recent":
		return FlagRecent
	}

	return 0
}

// Convert IMAP flags (e.g., "\Seen", "\Answered") to bitwise flags
func FlagsToBitwise(flags []imap.Flag) int {
	var bitwiseFlags int

	for _, flag := range flags {
		bitwiseFlags |= FlagToBitwise(flag)
	}
	return bitwiseFlags
}

// Convert bitwise flags to IMAP flag strings
func BitwiseToFlags(bitwiseFlags int) []imap.Flag {
	var flags []imap.Flag

	if bitwiseFlags&FlagSeen != 0 {
		flags = append(flags, imap.FlagSeen)
	}
	if bitwiseFlags&FlagAnswered != 0 {
		flags = append(flags, imap.FlagAnswered)
	}
	if bitwiseFlags&FlagFlagged != 0 {
		flags = append(flags, imap.FlagFlagged)
	}
	if bitwiseFlags&FlagDeleted != 0 {
		flags = append(flags, imap.FlagDeleted)
	}
	if bitwiseFlags&FlagDraft != 0 {
		flags = append(flags, imap.FlagDraft)
	}
	// \Recent is a session flag (RFC 3501 §2.3.2) and must NOT be served from
	// stored data.  Existing messages may still have the FlagRecent bit (32) set
	// from before the fix that stopped writing it.  We intentionally skip it
	// here so FETCH FLAGS never returns a stale \Recent from the database.

	return flags
}

func (db *Database) GetMessagesByNumSet(ctx context.Context, mailboxID int64, numSet imap.NumSet, includeBodyStructure ...bool) ([]Message, error) {
	includeBS := len(includeBodyStructure) > 0 && includeBodyStructure[0]
	if uidSet, ok := numSet.(imap.UIDSet); ok {
		messages, err := db.getMessagesByUIDSet(ctx, mailboxID, uidSet, includeBS)
		if err != nil {
			return nil, err
		}
		return messages, nil
	}

	if seqSet, ok := numSet.(imap.SeqSet); ok {
		messages, err := db.getMessagesBySeqSet(ctx, mailboxID, seqSet, includeBS)
		if err != nil {
			return nil, err
		}
		return messages, nil
	}

	return nil, fmt.Errorf("unsupported NumSet type: %T", numSet)
}

func (db *Database) getMessagesByUIDSet(ctx context.Context, mailboxID int64, uidSet imap.UIDSet, includeBodyStructure bool) ([]Message, error) {
	if len(uidSet) == 0 {
		return nil, nil
	}

	bsColInner := ""
	if includeBodyStructure {
		bsColInner = "m.body_structure, "
	}

	// Consolidate all UID ranges into a single WHERE clause to avoid executing hundreds
	// of individual database queries for fragmented fetches (e.g. Apple Mail).
	var conditions []string
	var args []any
	args = append(args, mailboxID)

	for _, uidRange := range uidSet {
		if uidRange.Stop == imap.UID(0) {
			args = append(args, int64(uidRange.Start))
			conditions = append(conditions, fmt.Sprintf("m.uid >= $%d", len(args)))
		} else {
			args = append(args, int64(uidRange.Start), int64(uidRange.Stop))
			conditions = append(conditions, fmt.Sprintf("(m.uid >= $%d AND m.uid <= $%d)", len(args)-1, len(args)))
		}
	}

	whereClause := strings.Join(conditions, " OR ")

	// Check if result set would be too large
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM messages m
		WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
		  AND (%s)
	`, whereClause)

	var estimatedCount int64
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, countQuery, args...).Scan(&estimatedCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count messages in UID set: %w", err)
	}

	if estimatedCount > int64(db.fetchMaxResults) {
		return nil, fmt.Errorf("result set too large (%d messages), maximum allowed is %d", estimatedCount, db.fetchMaxResults)
	}

	if estimatedCount <= int64(db.fetchChunkSize) {
		// Small result set: fetch in single query
		return db.fetchMessagesByUIDSetDirect(ctx, mailboxID, whereClause, args, includeBodyStructure, bsColInner)
	}

	// Large result set: fetch in chunks
	log.Printf("Database: Chunking UID fetch for mailbox %d (%d messages, %d per chunk)", mailboxID, estimatedCount, db.fetchChunkSize)
	return db.fetchMessagesByUIDSetChunked(ctx, mailboxID, whereClause, args, includeBodyStructure, bsColInner, db.fetchChunkSize)
}

func (db *Database) fetchMessagesByUIDSetDirect(ctx context.Context, mailboxID int64, whereClause string, args []any, includeBodyStructure bool, bsColInner string) ([]Message, error) {
	query := fmt.Sprintf(`
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, %[1]sm.created_modseq, ms.updated_modseq, m.expunged_modseq,
			0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
		  AND (%[2]s)
		ORDER BY m.uid`, bsColInner, whereClause)

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages with UID set: %w", err)
	}

	messages, err := scanMessages(rows, includeBodyStructure)
	if err != nil {
		return nil, err
	}
	if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func (db *Database) fetchMessagesByUIDSetChunked(ctx context.Context, mailboxID int64, whereClause string, args []any, includeBodyStructure bool, bsColInner string, chunkSize int) ([]Message, error) {
	metrics.MessageFetchChunked.WithLabelValues("uid_set").Inc()

	var allMessages []Message
	var lastUID int64
	chunkCount := 0

	for {
		query := fmt.Sprintf(`
			SELECT
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
				m.internal_date, m.size, %[1]sm.created_modseq, ms.updated_modseq, m.expunged_modseq,
				0 as seqnum,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
			  AND (%[2]s)
			  AND m.uid > $%d
			ORDER BY m.uid ASC
			LIMIT $%d`, bsColInner, whereClause, len(args)+1, len(args)+2)

		argsWithLimit := append(append([]any{}, args...), lastUID, chunkSize)
		rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, argsWithLimit...)
		if err != nil {
			return nil, fmt.Errorf("failed to query messages chunk after uid %d: %w", lastUID, err)
		}

		messages, err := scanMessages(rows, includeBodyStructure)
		if err != nil {
			return nil, err
		}

		if len(messages) == 0 {
			break
		}

		lastUID = int64(messages[len(messages)-1].UID)
		allMessages = append(allMessages, messages...)
		chunkCount++

		// Check context cancellation between chunks
		if ctx.Err() != nil {
			return nil, fmt.Errorf("chunked fetch cancelled: %w", ctx.Err())
		}

		if len(messages) < chunkSize {
			break
		}
	}

	metrics.MessageFetchChunks.WithLabelValues("uid_set").Observe(float64(chunkCount))

	if err := db.HydrateMessageSequences(ctx, mailboxID, allMessages); err != nil {
		return nil, err
	}
	return allMessages, nil
}

func (db *Database) getUIDBySeqNum(ctx context.Context, mailboxID int64, seqNum uint32) (imap.UID, error) {
	if seqNum == 0 {
		return 0, fmt.Errorf("invalid sequence number 0")
	}
	var uid uint32
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT uid FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL 
		ORDER BY uid ASC 
		OFFSET $2 LIMIT 1
	`, mailboxID, seqNum-1).Scan(&uid)
	return imap.UID(uid), err
}

func (db *Database) getMessagesBySeqSet(ctx context.Context, mailboxID int64, seqSet imap.SeqSet, includeBodyStructure bool) ([]Message, error) {
	if len(seqSet) == 0 {
		return nil, nil
	}
	if len(seqSet) == 1 && seqSet[0].Start == 1 && (seqSet[0].Stop == 0) {
		log.Printf("Database: SeqSet includes all messages (1:*) for mailbox %d", mailboxID)
		return db.fetchAllActiveMessagesRaw(ctx, mailboxID, includeBodyStructure)
	}

	bsColInner := ""
	if includeBodyStructure {
		bsColInner = "m.body_structure, "
	}

	// Map sequence ranges to UID ranges to prevent O(N) ROW_NUMBER() CTE scans
	var conditions []string
	var args []any
	args = append(args, mailboxID)

	for _, seqRange := range seqSet {
		startUID, err := db.getUIDBySeqNum(ctx, mailboxID, seqRange.Start)
		if err != nil {
			// If we fail to resolve Start (e.g. out of bounds), skip this range
			continue
		}

		if seqRange.Stop == 0 {
			args = append(args, int64(startUID))
			conditions = append(conditions, fmt.Sprintf("m.uid >= $%d", len(args)))
		} else {
			stopUID, err := db.getUIDBySeqNum(ctx, mailboxID, seqRange.Stop)
			if err != nil {
				// Stop is out of bounds, meaning we fetch up to the highest message we have
				args = append(args, int64(startUID))
				conditions = append(conditions, fmt.Sprintf("m.uid >= $%d", len(args)))
			} else {
				// Safely ensure min/max alignment in case of reverse sequence bounds requested by client
				minUid := min(startUID, stopUID)
				maxUid := max(startUID, stopUID)
				args = append(args, int64(minUid), int64(maxUid))
				conditions = append(conditions, fmt.Sprintf("(m.uid >= $%d AND m.uid <= $%d)", len(args)-1, len(args)))
			}
		}
	}

	if len(conditions) == 0 {
		// No valid sequences requested
		return nil, nil
	}

	whereClause := strings.Join(conditions, " OR ")

	// Check if result set would be too large
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM messages m
		WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
		  AND (%s)
	`, whereClause)

	var estimatedCount int64
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, countQuery, args...).Scan(&estimatedCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count messages in Seq set: %w", err)
	}

	if estimatedCount > int64(db.fetchMaxResults) {
		return nil, fmt.Errorf("result set too large (%d messages), maximum allowed is %d", estimatedCount, db.fetchMaxResults)
	}

	if estimatedCount <= int64(db.fetchChunkSize) {
		// Small result set: fetch in single query
		return db.fetchMessagesBySeqSetDirect(ctx, mailboxID, whereClause, args, includeBodyStructure, bsColInner)
	}

	// Large result set: fetch in chunks
	log.Printf("Database: Chunking Seq fetch for mailbox %d (%d messages, %d per chunk)", mailboxID, estimatedCount, db.fetchChunkSize)
	return db.fetchMessagesBySeqSetChunked(ctx, mailboxID, whereClause, args, includeBodyStructure, bsColInner, db.fetchChunkSize)
}

func (db *Database) fetchMessagesBySeqSetDirect(ctx context.Context, mailboxID int64, whereClause string, args []any, includeBodyStructure bool, bsColInner string) ([]Message, error) {
	query := fmt.Sprintf(`
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, %sm.created_modseq, ms.updated_modseq, m.expunged_modseq,
			0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
		  AND (%s)
		ORDER BY m.uid
	`, bsColInner, whereClause)

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages with mapped Seq set: %w", err)
	}

	messages, err := scanMessages(rows, includeBodyStructure)
	if err != nil {
		return nil, err
	}
	if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func (db *Database) fetchMessagesBySeqSetChunked(ctx context.Context, mailboxID int64, whereClause string, args []any, includeBodyStructure bool, bsColInner string, chunkSize int) ([]Message, error) {
	metrics.MessageFetchChunked.WithLabelValues("seq_set").Inc()

	var allMessages []Message
	var lastUID int64
	chunkCount := 0

	for {
		query := fmt.Sprintf(`
			SELECT
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
				m.internal_date, m.size, %sm.created_modseq, ms.updated_modseq, m.expunged_modseq,
				0 as seqnum,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.mailbox_id = $1 AND m.uploaded = true AND m.expunged_at IS NULL
			  AND (%s)
			  AND m.uid > $%d
			ORDER BY m.uid ASC
			LIMIT $%d
		`, bsColInner, whereClause, len(args)+1, len(args)+2)

		argsWithLimit := append(append([]any{}, args...), lastUID, chunkSize)
		rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, argsWithLimit...)
		if err != nil {
			return nil, fmt.Errorf("failed to query messages chunk after uid %d: %w", lastUID, err)
		}

		messages, err := scanMessages(rows, includeBodyStructure)
		if err != nil {
			return nil, err
		}

		if len(messages) == 0 {
			break
		}

		lastUID = int64(messages[len(messages)-1].UID)
		allMessages = append(allMessages, messages...)
		chunkCount++

		// Check context cancellation between chunks
		if ctx.Err() != nil {
			return nil, fmt.Errorf("chunked fetch cancelled: %w", ctx.Err())
		}

		if len(messages) < chunkSize {
			break
		}
	}

	metrics.MessageFetchChunks.WithLabelValues("seq_set").Observe(float64(chunkCount))

	if err := db.HydrateMessageSequences(ctx, mailboxID, allMessages); err != nil {
		return nil, err
	}
	return allMessages, nil
}

func (db *Database) fetchAllActiveMessagesRaw(ctx context.Context, mailboxID int64, includeBodyStructure bool) ([]Message, error) {
	// Filter to uploaded messages only (same as getMessagesBySeqSet / getMessagesByUIDSet).
	// This path handles the rare edge-case SeqSet "1:*" where the wildcard was not
	// resolved (session count == 0).  See getMessagesByUIDSet for the full rationale.

	// Check message count first
	var messageCount int64
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*) FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL AND uploaded = true
	`, mailboxID).Scan(&messageCount)
	if err != nil {
		return nil, fmt.Errorf("fetchAllActiveMessagesRaw: failed to count messages: %w", err)
	}

	if messageCount > int64(db.fetchMaxResults) {
		return nil, fmt.Errorf("result set too large (%d messages), maximum allowed is %d", messageCount, db.fetchMaxResults)
	}

	if messageCount <= int64(db.fetchChunkSize) {
		// Small mailbox: fetch in single query
		return db.fetchAllActiveMessagesRawDirect(ctx, mailboxID, includeBodyStructure)
	}

	// Large mailbox: fetch in chunks
	log.Printf("Database: Chunking SeqSet 1:* fetch for mailbox %d (%d messages, %d per chunk)", mailboxID, messageCount, db.fetchChunkSize)
	return db.fetchAllActiveMessagesRawChunked(ctx, mailboxID, includeBodyStructure, db.fetchChunkSize)
}

func (db *Database) fetchAllActiveMessagesRawDirect(ctx context.Context, mailboxID int64, includeBodyStructure bool) ([]Message, error) {
	bsCol := ""
	if includeBodyStructure {
		bsCol = "m.body_structure, "
	}

	query := fmt.Sprintf(`
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, %sm.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL AND m.uploaded = true
		ORDER BY m.uid ASC
	`, bsCol)
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("fetchAllActiveMessagesRaw: failed to query: %w", err)
	}
	messages, err := scanMessages(rows, includeBodyStructure)
	if err != nil {
		return nil, err
	}
	if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func (db *Database) fetchAllActiveMessagesRawChunked(ctx context.Context, mailboxID int64, includeBodyStructure bool, chunkSize int) ([]Message, error) {
	metrics.MessageFetchChunked.WithLabelValues("all_messages").Inc()

	bsCol := ""
	if includeBodyStructure {
		bsCol = "m.body_structure, "
	}

	var allMessages []Message
	var lastUID int64
	chunkCount := 0

	for {
		query := fmt.Sprintf(`
			SELECT
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
				m.internal_date, m.size, %sm.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL AND m.uploaded = true
			  AND m.uid > $2
			ORDER BY m.uid ASC
			LIMIT $3
		`, bsCol)

		rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, lastUID, chunkSize)
		if err != nil {
			return nil, fmt.Errorf("fetchAllActiveMessagesRaw: failed to query chunk after uid %d: %w", lastUID, err)
		}

		messages, err := scanMessages(rows, includeBodyStructure)
		if err != nil {
			return nil, err
		}

		if len(messages) == 0 {
			break
		}

		lastUID = int64(messages[len(messages)-1].UID)
		allMessages = append(allMessages, messages...)
		chunkCount++

		// Check context cancellation between chunks
		if ctx.Err() != nil {
			return nil, fmt.Errorf("chunked fetch cancelled: %w", ctx.Err())
		}

		if len(messages) < chunkSize {
			break
		}
	}

	metrics.MessageFetchChunks.WithLabelValues("all_messages").Observe(float64(chunkCount))

	if err := db.HydrateMessageSequences(ctx, mailboxID, allMessages); err != nil {
		return nil, err
	}
	return allMessages, nil
}

func scanMessages(rows pgx.Rows, includeBodyStructure bool) ([]Message, error) {
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var customFlagsJSON []byte
		var recipientsJSON []byte
		var bodyStructureBytes []byte

		// Build scan args dynamically — body_structure is only present when includeBodyStructure is true.
		scanArgs := []any{
			&msg.ID, &msg.AccountID, &msg.UID, &msg.MailboxID, &msg.ContentHash,
			&msg.S3Domain, &msg.S3Localpart, &msg.IsUploaded, &msg.BitwiseFlags, &customFlagsJSON,
			&msg.InternalDate, &msg.Size,
		}
		if includeBodyStructure {
			scanArgs = append(scanArgs, &bodyStructureBytes)
		}
		scanArgs = append(scanArgs,
			&msg.CreatedModSeq, &msg.UpdatedModSeq,
			&msg.ExpungedModSeq, &msg.Seq, &msg.FlagsChangedAt, &msg.Subject, &msg.SentDate, &msg.MessageID,
			&msg.InReplyTo, &recipientsJSON,
		)

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("failed to scan message: %v", err)
		}

		if includeBodyStructure {
			msg.BodyStructure = deserializeBodyStructure(bodyStructureBytes, msg.Size, msg.AccountID, msg.MailboxID, msg.UID, msg.ContentHash)
		}
		// When !includeBodyStructure, msg.BodyStructure remains nil.
		// Callers that need it (e.g. FETCH BODYSTRUCTURE) will lazy-fetch via GetMessageBodyStructure.

		if err := json.Unmarshal(customFlagsJSON, &msg.CustomFlags); err != nil {
			log.Printf("Database: ERROR - failed unmarshalling custom_flags for UID %d: %v. JSON: %s", msg.UID, err, string(customFlagsJSON))
		}
		msg.RecipientsJSON = recipientsJSON
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning rows: %v", err)
	}

	return messages, nil
}

func scanSearchMessages(rows pgx.Rows) ([]SearchMessageResult, error) {
	defer rows.Close()

	var messages []SearchMessageResult
	for rows.Next() {
		var msg SearchMessageResult

		// Scan ONLY the subset of columns required for SEARCH / SORT / CONDSTORE
		if err := rows.Scan(
			&msg.ID, &msg.UID, &msg.MailboxID, &msg.ContentHash,
			&msg.CreatedModSeq, &msg.UpdatedModSeq, &msg.ExpungedModSeq, &msg.Seq,
		); err != nil {
			return nil, fmt.Errorf("failed to scan search message: %v", err)
		}

		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning search rows: %v", err)
	}

	return messages, nil
}

// deserializeBodyStructure deserializes and validates a body_structure blob, returning a fallback on any error.
func deserializeBodyStructure(data []byte, msgSize int, accountID, mailboxID int64, uid imap.UID, contentHash string) *imap.BodyStructure {
	if len(data) > 0 {
		bs, err := helpers.DeserializeBodyStructureGob(data)
		if err != nil {
			log.Printf("Database: WARNING - account_id=%d mailbox_id=%d UID=%d content_hash=%s: failed to deserialize body_structure: %v",
				accountID, mailboxID, uid, contentHash, err)
		} else if validateErr := helpers.ValidateBodyStructure(bs); validateErr != nil {
			log.Printf("Database: WARNING - account_id=%d mailbox_id=%d UID=%d content_hash=%s: invalid body_structure: %v",
				accountID, mailboxID, uid, contentHash, validateErr)
		} else {
			return bs
		}
	}

	// Fallback: safe default with Extended populated for BODYSTRUCTURE compatibility.
	defaultBS := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Size:     uint32(msgSize),
		Extended: &imap.BodyStructureSinglePartExt{},
	}
	var bs imap.BodyStructure = defaultBS
	return &bs
}

// GetMessageBodyStructure fetches the body structure of a single message individually.
func (db *Database) GetMessageBodyStructure(ctx context.Context, uid imap.UID, mailboxID int64) (*imap.BodyStructure, error) {
	var bodyStructureBytes []byte
	var size int
	var accountID int64
	var contentHash string

	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT body_structure, size, account_id, content_hash
		FROM messages
		WHERE mailbox_id = $1 AND uid = $2
	`, mailboxID, int64(uid)).Scan(&bodyStructureBytes, &size, &accountID, &contentHash)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve body_structure: %w", err)
	}

	return deserializeBodyStructure(bodyStructureBytes, size, accountID, mailboxID, uid, contentHash), nil
}

func (db *Database) GetMessagesByFlag(ctx context.Context, mailboxID int64, flag imap.Flag) ([]Message, error) {
	// Convert the IMAP flag to its corresponding bitwise value
	bitwiseFlag := FlagToBitwise(flag)

	// Use a unified ROW_NUMBER() CTE instead of a correlated COUNT(*) subquery.
	// While a correlated count is fast for 1-2 rows, fetching 50,000 flagged messages
	// forces Postgres to execute COUNT(*) 50,000 times, causing massive O(N^2) timeouts.
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
			0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND (ms.flags & $2) != 0 AND m.expunged_at IS NULL
		ORDER BY m.uid
	`, mailboxID, bitwiseFlag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Use scanMessages helper which correctly handles all fields including custom_flags
	messages, err := scanMessages(rows, false)
	if err != nil {
		return nil, fmt.Errorf("GetMessagesByFlag: failed to scan messages: %w", err)
	}

	if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
		return nil, err
	}
	return messages, nil
}

// MessageUIDSeq holds the UID and sequence number of a message, used for
// lightweight operations like EXPUNGE that do not need full message data.
type MessageUIDSeq struct {
	UID imap.UID
	Seq uint32
}

// GetDeletedMessageUIDsAndSeqs efficiently retrieves only UIDs and sequence numbers
// for messages with the \Deleted flag, optimized for EXPUNGE operations.
// This avoids fetching unnecessary columns like body_structure and recipients_json.
func (db *Database) GetDeletedMessageUIDsAndSeqs(ctx context.Context, mailboxID int64) ([]MessageUIDSeq, error) {
	// Use unified ROW_NUMBER() CTE instead of a correlated subquery for sequence mapping
	// to prevent massive O(N^2) timeouts if a user attempts to bulk-delete thousands of messages.
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		WITH numbered AS (
			SELECT uid, ROW_NUMBER() OVER(ORDER BY uid) as seqnum
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		)
		SELECT m.uid, n.seqnum
		FROM messages m
		JOIN numbered n ON m.uid = n.uid
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND (ms.flags & $2) != 0 AND m.expunged_at IS NULL
		ORDER BY m.uid
	`, mailboxID, FlagToBitwise(imap.FlagDeleted))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []MessageUIDSeq
	for rows.Next() {
		var entry MessageUIDSeq
		if err := rows.Scan(&entry.UID, &entry.Seq); err != nil {
			return nil, err
		}
		results = append(results, entry)
	}

	return results, rows.Err()
}

// GetRecentMessagesForWarmup fetches the most recent messages from specified mailboxes for cache warming
// Returns a map of mailboxName -> []contentHash for the most recent messages
func (db *Database) GetRecentMessagesForWarmup(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	if messageCount <= 0 {
		return make(map[string][]string), nil
	}

	// Check if account has any mailboxes - skip warmup for new accounts to avoid noise
	mailboxCount, err := db.GetMailboxesCount(ctx, AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to count mailboxes: %w", err)
	}
	if mailboxCount == 0 {
		// New account with no mailboxes yet - skip warmup silently
		return make(map[string][]string), nil
	}

	result := make(map[string][]string)

	for _, mailboxName := range mailboxNames {
		mailbox, err := db.GetMailboxByName(ctx, AccountID, mailboxName)
		if err != nil {
			log.Printf("WarmUp: failed to get mailbox '%s' for user %d: %v", mailboxName, AccountID, err)
			continue // Skip this mailbox if not found
		}

		// Create search criteria to get all messages (no filters)
		criteria := &imap.SearchCriteria{}

		// Get the most recent messages. Use SearchMessagesWithCriteria to trigger the
		// fast-path ORDER BY uid DESC which operates in O(1) via indices, instead of
		// forcing a massive in-memory ordering on internal_date.
		messages, err := db.SearchMessagesWithCriteria(ctx, mailbox.ID, criteria, messageCount)
		if err != nil {

			log.Printf("WarmUp: failed to get recent messages for mailbox '%s': %v", mailboxName, err)
			continue
		}

		// Extract content hashes for the most recent messages (up to messageCount)
		var contentHashes []string
		for i, message := range messages {
			if i >= messageCount {
				break
			}
			if message.ContentHash != "" {
				contentHashes = append(contentHashes, message.ContentHash)
			}
		}

		if len(contentHashes) > 0 {
			result[mailboxName] = contentHashes
			log.Printf("WarmUp: prepared %d content hashes for mailbox '%s'", len(contentHashes), mailboxName)
		}
	}

	return result, nil
}

// HydrateMessageSequences takes a slice of messages and dynamically maps their IMAP sequence numbers (Seq)
// using a highly optimized O(1) Index-Only streaming pass through the database, rather than O(K*N) subqueries.
func (db *Database) HydrateMessageSequences(ctx context.Context, mailboxID int64, messages []Message) error {
	return hydrateSequencesCore(ctx, db, mailboxID, messages,
		func(m *Message) uint32 { return uint32(m.UID) },
		func(m *Message, seq uint32) { m.Seq = seq },
	)
}

// HydrateSearchMessageSequences works the same as HydrateMessageSequences but operates
// on the lightweight SearchMessageResult struct.
func (db *Database) HydrateSearchMessageSequences(ctx context.Context, mailboxID int64, messages []SearchMessageResult) error {
	return hydrateSequencesCore(ctx, db, mailboxID, messages,
		func(m *SearchMessageResult) uint32 { return uint32(m.UID) },
		func(m *SearchMessageResult, seq uint32) { m.Seq = seq },
	)
}

func hydrateSequencesCore[T any](
	ctx context.Context,
	db *Database,
	mailboxID int64,
	messages []T,
	getUID func(*T) uint32,
	setSeq func(*T, uint32),
) error {
	if len(messages) == 0 {
		return nil
	}

	interestedUIDs := make(map[uint32]*T, len(messages))
	var uids []int64
	var minUID, maxUID uint32 = 0xFFFFFFFF, 0

	for i := range messages {
		uid := getUID(&messages[i])
		if uid < minUID {
			minUID = uid
		}
		if uid > maxUID {
			maxUID = uid
		}
		interestedUIDs[uid] = &messages[i]
		uids = append(uids, int64(uid))
	}

	distance := maxUID - minUID
	var rows pgx.Rows
	var err error

	// If we are modifying a very sparse list of sequences relative to the size of the array,
	// use the targeted correlation query. Otherwise, fall back to the optimized bounded window function.
	if len(messages) >= 100 && uint64(distance) < uint64(len(messages))*100 {
		// Optimized sequence hydration using batch approach:
		// 1. Find min/max UID in our target set
		// 2. Count how many messages exist below min UID (base offset)
		// 3. Use ROW_NUMBER only on the UID range containing our targets
		// This is much faster than full-mailbox ROW_NUMBER for dense sequence fetches.
		rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, `
			WITH target_uids AS (
				SELECT unnest($2::bigint[]) AS uid
			),
			uid_range AS (
				SELECT MIN(uid) as min_uid, MAX(uid) as max_uid FROM target_uids
			),
			base_offset AS (
				SELECT COUNT(*)::bigint as offset
				FROM messages
				WHERE mailbox_id = $1
				  AND expunged_at IS NULL
				  AND uid < (SELECT min_uid FROM uid_range)
			),
			windowed AS (
				SELECT
					uid,
					ROW_NUMBER() OVER(ORDER BY uid) as relative_seq
				FROM messages
				WHERE mailbox_id = $1
				  AND expunged_at IS NULL
				  AND uid >= (SELECT min_uid FROM uid_range)
				  AND uid <= (SELECT max_uid FROM uid_range)
			)
			SELECT w.uid, (w.relative_seq + b.offset)::bigint as seqnum
			FROM windowed w, base_offset b
			WHERE w.uid = ANY($2::bigint[])
		`, mailboxID, uids)
	} else {
		// Sparse sequence hydration using indexed lateral approach.
		rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, `
			SELECT t.uid,
				   (SELECT COUNT(*) + 1 
					FROM messages m 
					WHERE m.mailbox_id = $1 AND expunged_at IS NULL AND m.uid < t.uid
				   ) as seqnum
			FROM unnest($2::bigint[]) as t(uid)
		`, mailboxID, uids)
	}

	if err != nil {
		return fmt.Errorf("failed to query sequence streams: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var uid int64
		var seq int64
		if err := rows.Scan(&uid, &seq); err != nil {
			return fmt.Errorf("failed to scan sequence stream: %w", err)
		}
		if msgPtr, ok := interestedUIDs[uint32(uid)]; ok {
			setSeq(msgPtr, uint32(seq))
		}
	}

	return rows.Err()
}
