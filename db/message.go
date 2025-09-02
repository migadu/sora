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
	UserID         int64     // ID of the user who owns the message
	UID            imap.UID  // Unique identifier for the message
	ContentHash    string    // Hash of the message content
	MailboxID      int64     // ID of the mailbox the message belongs to
	IsUploaded     bool      // Indicates if the message is uploaded to S3
	Seq            uint32    // Sequence number of the message in the mailbox
	BitwiseFlags   int       // Bitwise flags for the message (e.g., \Seen, \Flagged)
	CustomFlags    []string  // Custom flags for the message
	FlagsChangedAt time.Time // Time when the flags were last changed
	Subject        string    // Subject of the message
	InternalDate   time.Time // The internal date the message was received
	SentDate       time.Time // The date the message was sent
	Size           int       // Size of the message in bytes
	MessageID      string    // Unique Message-ID from the message headers
	BodyStructure  imap.BodyStructure
	CreatedModSeq  int64
	UpdatedModSeq  *int64
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
	if bitwiseFlags&FlagRecent != 0 {
		flags = append(flags, imap.Flag("\\Recent"))
	}

	return flags
}

func (db *Database) GetMessagesByNumSet(ctx context.Context, mailboxID int64, numSet imap.NumSet) ([]Message, error) {
	if uidSet, ok := numSet.(imap.UIDSet); ok {
		messages, err := db.getMessagesByUIDSet(ctx, mailboxID, uidSet)
		if err != nil {
			return nil, err
		}
		return messages, nil
	}

	if seqSet, ok := numSet.(imap.SeqSet); ok {
		messages, err := db.getMessagesBySeqSet(ctx, mailboxID, seqSet)
		if err != nil {
			return nil, err
		}
		return messages, nil
	}

	return nil, fmt.Errorf("unsupported NumSet type: %T", numSet)
}

func (db *Database) getMessagesByUIDSet(ctx context.Context, mailboxID int64, uidSet imap.UIDSet) ([]Message, error) {
	var messages []Message

	for _, uidRange := range uidSet {
		// Base query is the same for all cases
		baseQuery := `
			WITH numbered_messages AS (
				SELECT 
					account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
					internal_date, size, body_structure,
					created_modseq, updated_modseq, expunged_modseq,
					row_number() OVER (ORDER BY uid) AS seqnum
				FROM messages
				WHERE mailbox_id = $1 AND expunged_at IS NULL
			)
			SELECT 
				account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
				internal_date, size, body_structure,
				created_modseq, updated_modseq, expunged_modseq, seqnum
			FROM numbered_messages
			WHERE uid >= $2
		`

		var rows pgx.Rows
		var err error
		var rangeDesc string

		// Add upper bound condition for non-wildcard queries
		if uidRange.Stop == imap.UID(0) {
			// Wildcard range (e.g., 1:*)
			rangeDesc = fmt.Sprintf("%d:*", uidRange.Start)
			query := baseQuery + " ORDER BY seqnum"
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, uint32(uidRange.Start))
		} else {
			// Regular range (e.g., 1:5)
			rangeDesc = fmt.Sprintf("%d:%d", uidRange.Start, uidRange.Stop)
			query := baseQuery + " AND uid <= $3 ORDER BY seqnum"
			rows, err = db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, uint32(uidRange.Start), uint32(uidRange.Stop))
		}

		if err != nil {
			return nil, fmt.Errorf("failed to query messages with UID range %s: %v", rangeDesc, err)
		}

		rangeMessages, err := scanMessages(rows)
		if err != nil {
			return nil, err
		}

		messages = append(messages, rangeMessages...)
	}
	return messages, nil
}

func (db *Database) getMessagesBySeqSet(ctx context.Context, mailboxID int64, seqSet imap.SeqSet) ([]Message, error) {
	if len(seqSet) == 1 && seqSet[0].Start == 1 && (seqSet[0].Stop == 0) {
		log.Printf("[DB] SeqSet includes all messages (1:*) for mailbox %d", mailboxID)
		return db.fetchAllActiveMessagesRaw(ctx, mailboxID)
	}

	var allMessages []Message

	for _, seqRange := range seqSet {
		stopSeq := seqRange.Stop

		query := `
			WITH numbered_messages AS (
				SELECT 
					account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
					internal_date, size, body_structure,
					created_modseq, updated_modseq, expunged_modseq,
					row_number() OVER (ORDER BY uid) AS seqnum
				FROM messages
				WHERE mailbox_id = $1 AND expunged_at IS NULL
			)
			SELECT 
				account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
				internal_date, size, body_structure,
				created_modseq, updated_modseq, expunged_modseq, seqnum
			FROM numbered_messages
			WHERE seqnum >= $2 AND seqnum <= $3
			ORDER BY seqnum
		`

		rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID, seqRange.Start, stopSeq)
		if err != nil {
			return nil, fmt.Errorf("failed to query messages for sequence range %d:%d: %v",
				seqRange.Start, stopSeq, err)
		}

		rangeMessages, err := scanMessages(rows)
		if err != nil {
			return nil, err
		}

		allMessages = append(allMessages, rangeMessages...)
	}
	return allMessages, nil
}

func (db *Database) fetchAllActiveMessagesRaw(ctx context.Context, mailboxID int64) ([]Message, error) {
	query := `
		WITH numbered_messages AS (
			SELECT 
				account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
				internal_date, size, body_structure,
				created_modseq, updated_modseq, expunged_modseq,
				row_number() OVER (ORDER BY uid) AS seqnum
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		)
		SELECT 
			account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
			internal_date, size, body_structure,
			created_modseq, updated_modseq, expunged_modseq, seqnum
		FROM numbered_messages
		ORDER BY seqnum
	`
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("fetchAllActiveMessagesRaw: failed to query: %w", err)
	}
	return scanMessages(rows)
}

func scanMessages(rows pgx.Rows) ([]Message, error) {
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var bodyStructureBytes []byte
		var customFlagsJSON []byte

		if err := rows.Scan(&msg.UserID, &msg.UID, &msg.MailboxID, &msg.ContentHash, &msg.IsUploaded,
			&msg.BitwiseFlags, &customFlagsJSON, &msg.InternalDate, &msg.Size, &bodyStructureBytes, &msg.CreatedModSeq,
			&msg.UpdatedModSeq, &msg.ExpungedModSeq, &msg.Seq); err != nil {
			return nil, fmt.Errorf("failed to scan message: %v", err)
		}
		bodyStructure, err := helpers.DeserializeBodyStructureGob(bodyStructureBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize BodyStructure: %v", err)
		}
		if err := json.Unmarshal(customFlagsJSON, &msg.CustomFlags); err != nil {
			log.Printf("[DB] ERROR: failed unmarshalling custom_flags for UID %d: %v. JSON: %s", msg.UID, err, string(customFlagsJSON))
		}
		msg.BodyStructure = *bodyStructure
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning rows: %v", err)
	}

	return messages, nil
}

func (db *Database) GetMessagesByFlag(ctx context.Context, mailboxID int64, flag imap.Flag) ([]Message, error) {
	// Convert the IMAP flag to its corresponding bitwise value
	bitwiseFlag := FlagToBitwise(flag)
	// Query to select messages with the specified flag, including custom_flags
	// and other necessary fields to populate the Message struct.
	// It also calculates seqnum.
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		WITH numbered_messages AS (
			SELECT 
				account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
				internal_date, size, body_structure,
				created_modseq, updated_modseq, expunged_modseq,
				ROW_NUMBER() OVER (ORDER BY uid) AS seqnum
			FROM messages
			WHERE mailbox_id = $1 AND (flags & $2) != 0 AND expunged_at IS NULL
		)
		SELECT 
			account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
			internal_date, size, body_structure,
			created_modseq, updated_modseq, expunged_modseq, seqnum
		FROM numbered_messages
	`, mailboxID, bitwiseFlag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Use scanMessages helper which correctly handles all fields including custom_flags
	messages, err := scanMessages(rows)
	if err != nil {
		return nil, fmt.Errorf("GetMessagesByFlag: failed to scan messages: %w", err)
	}

	return messages, nil
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
