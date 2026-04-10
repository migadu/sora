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
	var messages []Message

	bsCol := ""
	if includeBodyStructure {
		bsCol = "m.body_structure, "
	}

	for _, uidRange := range uidSet {
		// OPTIMIZATION: Use offset+range pattern instead of full-mailbox CTE.
		// Instead of computing ROW_NUMBER() over ALL non-expunged messages (O(N)),
		// we COUNT messages before the range start (index-only scan) and only
		// number messages within the requested UID range.
		// This reduces cost from O(N) to O(range_size + index_scan_to_start).
		//
		// Filter to uploaded messages only.  A message that is not yet uploaded to S3
		// has its body on local disk only — on any other node its body is inaccessible
		// and FETCH would return a misleading empty literal.  Only serving uploaded
		// messages ensures consistent, correct behaviour across all nodes.

		var rows pgx.Rows
		var err error
		var rangeDesc string

		if uidRange.Stop == imap.UID(0) {
			// Wildcard range (e.g., 1:*)
			rangeDesc = fmt.Sprintf("%d:*", uidRange.Start)
			query := fmt.Sprintf(`
				WITH
				  range_messages AS (
				    SELECT *, ROW_NUMBER() OVER(ORDER BY uid) as range_pos
				    FROM messages
				    WHERE mailbox_id = $1 AND uid >= $2 AND expunged_at IS NULL
				  ),
				  preceding AS (
				    SELECT COUNT(*) as cnt FROM messages
				    WHERE mailbox_id = $1 AND uid < $2 AND expunged_at IS NULL
				  )
				SELECT
				    m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
				    m.internal_date, m.size, %sm.created_modseq, m.updated_modseq, m.expunged_modseq,
				    (SELECT cnt FROM preceding) + m.range_pos as seqnum,
				    m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
				FROM range_messages m
				WHERE m.uploaded = true
				ORDER BY m.uid`, bsCol)
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, uint32(uidRange.Start))
		} else {
			// Regular range (e.g., 1:5)
			rangeDesc = fmt.Sprintf("%d:%d", uidRange.Start, uidRange.Stop)
			query := fmt.Sprintf(`
				WITH
				  range_messages AS (
				    SELECT *, ROW_NUMBER() OVER(ORDER BY uid) as range_pos
				    FROM messages
				    WHERE mailbox_id = $1 AND uid >= $2 AND uid <= $3 AND expunged_at IS NULL
				  ),
				  preceding AS (
				    SELECT COUNT(*) as cnt FROM messages
				    WHERE mailbox_id = $1 AND uid < $2 AND expunged_at IS NULL
				  )
				SELECT
				    m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
				    m.internal_date, m.size, %sm.created_modseq, m.updated_modseq, m.expunged_modseq,
				    (SELECT cnt FROM preceding) + m.range_pos as seqnum,
				    m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
				FROM range_messages m
				WHERE m.uploaded = true
				ORDER BY m.uid`, bsCol)
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, uint32(uidRange.Start), uint32(uidRange.Stop))
		}

		if err != nil {
			return nil, fmt.Errorf("failed to query messages with UID range %s: %v", rangeDesc, err)
		}

		rangeMessages, err := scanMessages(rows, includeBodyStructure)
		if err != nil {
			return nil, err
		}

		messages = append(messages, rangeMessages...)
	}
	return messages, nil
}

func (db *Database) getMessagesBySeqSet(ctx context.Context, mailboxID int64, seqSet imap.SeqSet, includeBodyStructure bool) ([]Message, error) {
	if len(seqSet) == 1 && seqSet[0].Start == 1 && (seqSet[0].Stop == 0) {
		log.Printf("Database: SeqSet includes all messages (1:*) for mailbox %d", mailboxID)
		return db.fetchAllActiveMessagesRaw(ctx, mailboxID, includeBodyStructure)
	}

	bsCol := ""
	if includeBodyStructure {
		bsCol = "m.body_structure, "
	}

	var allMessages []Message

	for _, seqRange := range seqSet {
		// Filter to uploaded messages only (see getMessagesByUIDSet for the rationale).
		baseQuery := fmt.Sprintf(`
			WITH numbered_messages AS (
				SELECT *, ROW_NUMBER() OVER(ORDER BY uid) as seqnum
				FROM messages
				WHERE mailbox_id = $1 AND expunged_at IS NULL
			)
			SELECT 
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
				m.internal_date, m.size, %sm.created_modseq, m.updated_modseq, m.expunged_modseq, m.seqnum,
				m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
			FROM numbered_messages m
		`, bsCol)

		var rows pgx.Rows
		var err error

		if seqRange.Stop == 0 {
			// Wildcard range (e.g., 5:*) — no upper bound
			query := baseQuery + " WHERE m.seqnum >= $2 AND m.uploaded = true ORDER BY m.uid"
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, seqRange.Start)
		} else {
			// Bounded range (e.g., 1:5)
			query := baseQuery + " WHERE m.seqnum >= $2 AND m.seqnum <= $3 AND m.uploaded = true ORDER BY m.uid"
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, seqRange.Start, seqRange.Stop)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to query messages for sequence range %d:%d: %v",
				seqRange.Start, seqRange.Stop, err)
		}

		rangeMessages, err := scanMessages(rows, includeBodyStructure)
		if err != nil {
			return nil, err
		}

		allMessages = append(allMessages, rangeMessages...)
	}
	return allMessages, nil
}

func (db *Database) fetchAllActiveMessagesRaw(ctx context.Context, mailboxID int64, includeBodyStructure bool) ([]Message, error) {
	// Filter to uploaded messages only (same as getMessagesBySeqSet / getMessagesByUIDSet).
	// This path handles the rare edge-case SeqSet "1:*" where the wildcard was not
	// resolved (session count == 0).  See getMessagesByUIDSet for the full rationale.
	bsCol := ""
	if includeBodyStructure {
		bsCol = "m.body_structure, "
	}

	query := fmt.Sprintf(`
		WITH numbered_messages AS (
			SELECT *, ROW_NUMBER() OVER(ORDER BY uid) as seqnum
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		)
		SELECT 
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
			m.internal_date, m.size, %sm.created_modseq, m.updated_modseq, m.expunged_modseq, m.seqnum,
			m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM numbered_messages m
		WHERE m.uploaded = true
		ORDER BY m.uid
	`, bsCol)
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("fetchAllActiveMessagesRaw: failed to query: %w", err)
	}
	return scanMessages(rows, includeBodyStructure)
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
	`, mailboxID, uid).Scan(&bodyStructureBytes, &size, &accountID, &contentHash)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve body_structure: %w", err)
	}

	return deserializeBodyStructure(bodyStructureBytes, size, accountID, mailboxID, uid, contentHash), nil
}

func (db *Database) GetMessagesByFlag(ctx context.Context, mailboxID int64, flag imap.Flag) ([]Message, error) {
	// Convert the IMAP flag to its corresponding bitwise value
	bitwiseFlag := FlagToBitwise(flag)
	// OPTIMIZATION: Use correlated COUNT subquery instead of full-mailbox CTE.
	// Flag-based queries typically return small result sets (e.g., \Deleted for EXPUNGE),
	// so per-row COUNT is more efficient than materializing the entire mailbox.
	// Each COUNT uses an index-only scan on idx_messages_mailbox_uid_active.
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
			m.internal_date, m.size, m.created_modseq, m.updated_modseq, m.expunged_modseq,
			(SELECT COUNT(*) FROM messages m2
			 WHERE m2.mailbox_id = $1 AND m2.uid <= m.uid AND m2.expunged_at IS NULL) as seqnum,
			m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		WHERE m.mailbox_id = $1 AND (m.flags & $2) != 0 AND m.expunged_at IS NULL
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
	// OPTIMIZATION: Use correlated COUNT subquery instead of full-mailbox CTE.
	// EXPUNGE typically affects a small number of messages, so per-row COUNT
	// is more efficient than materializing the entire mailbox for ROW_NUMBER().
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT m.uid,
			(SELECT COUNT(*) FROM messages m2
			 WHERE m2.mailbox_id = $1 AND m2.uid <= m.uid AND m2.expunged_at IS NULL) as seqnum
		FROM messages m
		WHERE m.mailbox_id = $1 AND (m.flags & $2) != 0 AND m.expunged_at IS NULL
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

// GetMessageHeaders retrieves the raw headers for a specific message.
func (db *Database) GetMessageHeaders(ctx context.Context, messageUID imap.UID, mailboxID int64) (string, error) {
	var headers string
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT mc.headers
		FROM message_contents mc
		JOIN messages m ON m.content_hash = mc.content_hash
		WHERE m.uid = $1 AND m.mailbox_id = $2 AND m.expunged_at IS NULL
	`, messageUID, mailboxID).Scan(&headers)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("no message found with UID %d in mailbox %d or no content associated", messageUID, mailboxID)
		}
		return "", fmt.Errorf("failed to query message headers for UID %d: %w", messageUID, err)
	}

	return headers, nil
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

		// Create sort criteria to order by internal date descending (most recent first)
		sortCriteria := []imap.SortCriterion{{
			Key:     imap.SortKeyArrival,
			Reverse: true, // Most recent first
		}}

		// Get the sorted messages (most recent first)
		// Limit to messageCount to avoid fetching too many messages
		messages, err := db.GetMessagesSorted(ctx, mailbox.ID, criteria, sortCriteria, messageCount)
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
