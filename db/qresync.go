package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

// GetVanishedUIDs returns UIDs that were expunged between sinceModSeq and untilModSeq.
// This is used for QRESYNC SELECT to report expunged messages to the client.
// RFC 7162 §3.2.5: VANISHED response contains UIDs expunged since client's last sync.
//
// The query uses the idx_messages_expunged_modseq index for efficient lookups.
func (d *Database) GetVanishedUIDs(ctx context.Context, mailboxID int64, sinceModSeq, untilModSeq uint64) ([]imap.UID, error) {
	query := `
		SELECT uid
		FROM messages
		WHERE mailbox_id = $1
		  AND expunged_modseq > $2
		  AND expunged_modseq <= $3
		  AND expunged_at IS NOT NULL
		ORDER BY uid
	`

	rows, err := d.GetReadPool().Query(ctx, query, mailboxID, sinceModSeq, untilModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query vanished UIDs: %w", err)
	}
	defer rows.Close()

	var uids []imap.UID
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan vanished UID: %w", err)
		}
		uids = append(uids, imap.UID(uid))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vanished UIDs: %w", err)
	}

	return uids, nil
}

// QResyncModifiedMessage represents a message that has been modified since a given modseq.
// Used for QRESYNC SELECT to send unsolicited FETCH responses for changed messages.
type QResyncModifiedMessage struct {
	ID     int64
	UID    imap.UID
	Flags  []imap.Flag
	ModSeq uint64
	SeqNum uint32 // Will be populated by caller based on current mailbox state
}

// GetMessagesChangedSince returns messages that were created or modified after sinceModSeq.
// This is used for QRESYNC SELECT to report changed messages to the client.
// RFC 7162 §3.2.5: Server sends unsolicited FETCH responses for modified messages.
//
// Returns messages that:
// - Were created after sinceModSeq (created_modseq > sinceModSeq), OR
// - Had flags changed after sinceModSeq (updated_modseq > sinceModSeq)
// - Are NOT expunged (expunged_at IS NULL)
//
// The query uses idx_messages_created_modseq and idx_messages_updated_modseq indexes.
func (d *Database) GetMessagesChangedSince(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]QResyncModifiedMessage, error) {
	query := `
		SELECT
			m.id,
			m.uid,
			COALESCE(ms.flags, 0),
			COALESCE(ms.custom_flags, '[]'::jsonb),
			GREATEST(m.created_modseq, COALESCE(ms.updated_modseq, 0)),
			0::integer AS seqnum
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1
		  AND m.expunged_at IS NULL
		  AND (m.created_modseq > $2 OR COALESCE(ms.updated_modseq, 0) > $2)
		ORDER BY m.uid
	`

	rows, err := d.GetReadPool().Query(ctx, query, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query changed messages: %w", err)
	}
	defer rows.Close()

	var messages []QResyncModifiedMessage
	for rows.Next() {
		var msg QResyncModifiedMessage
		var bitwiseFlags int
		var customFlagsJSON []byte

		if err := rows.Scan(&msg.ID, &msg.UID, &bitwiseFlags, &customFlagsJSON, &msg.ModSeq, &msg.SeqNum); err != nil {
			return nil, fmt.Errorf("failed to scan changed message: %w", err)
		}

		// Convert bitwise flags to imap.Flag
		msg.Flags = BitwiseToFlags(bitwiseFlags)

		// Parse and append custom flags
		var customFlags []string
		if len(customFlagsJSON) > 0 && string(customFlagsJSON) != "[]" {
			if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom flags: %w", err)
			}
			for _, customFlag := range customFlags {
				msg.Flags = append(msg.Flags, imap.Flag(customFlag))
			}
		}

		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating changed messages: %w", err)
	}

	// Hydrate dynamic sequence numbers in-memory using optimized gap cumulative SUM trick
	if err := hydrateSequencesCore(ctx, d, mailboxID, messages,
		func(m *QResyncModifiedMessage) uint32 { return uint32(m.UID) },
		func(m *QResyncModifiedMessage, seq uint32) { m.SeqNum = seq },
	); err != nil {
		return nil, fmt.Errorf("failed to hydrate modified message sequences: %w", err)
	}

	return messages, nil
}

// Convenience aliases for consistency with existing codebase patterns
func (d *Database) GetVanishedUIDsWithRetry(ctx context.Context, mailboxID int64, sinceModSeq, untilModSeq uint64) ([]imap.UID, error) {
	return d.GetVanishedUIDs(ctx, mailboxID, sinceModSeq, untilModSeq)
}

func (d *Database) GetMessagesChangedSinceWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]QResyncModifiedMessage, error) {
	return d.GetMessagesChangedSince(ctx, mailboxID, sinceModSeq)
}

// GetVanishedUIDsForFetch returns vanished UIDs for FETCH VANISHED modifier.
// Similar to GetVanishedUIDs but for use with UID FETCH command.
// RFC 7162 §3.2.6: UID FETCH with VANISHED modifier.
//
// This is a convenience wrapper around GetVanishedUIDs for FETCH operations.
func (d *Database) GetVanishedUIDsForFetch(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]imap.UID, error) {
	// For FETCH, we want all UIDs vanished since sinceModSeq up to current time
	// We use a very large untilModSeq value (current highest modseq will be determined by caller)
	query := `
		SELECT uid
		FROM messages
		WHERE mailbox_id = $1
		  AND expunged_modseq > $2
		  AND expunged_at IS NOT NULL
		ORDER BY uid
	`

	rows, err := d.GetReadPool().Query(ctx, query, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query vanished UIDs for fetch: %w", err)
	}
	defer rows.Close()

	var uids []imap.UID
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan vanished UID: %w", err)
		}
		uids = append(uids, imap.UID(uid))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vanished UIDs: %w", err)
	}

	return uids, nil
}

func (d *Database) GetVanishedUIDsForFetchWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]imap.UID, error) {
	return d.GetVanishedUIDsForFetch(ctx, mailboxID, sinceModSeq)
}

// ValidateQResyncUIDValidity checks if the client's UIDValidity matches the current mailbox UIDValidity.
// Returns true if they match, false if client needs to perform full resync.
// RFC 7162 §3.2.5: If UIDVALIDITY changes, client must discard cached state.
func (d *Database) ValidateQResyncUIDValidity(ctx context.Context, mailboxID int64, clientUIDValidity uint32) (bool, error) {
	var currentUIDValidity uint32
	err := d.GetReadPool().QueryRow(ctx, `
		SELECT uid_validity
		FROM mailboxes
		WHERE id = $1
	`, mailboxID).Scan(&currentUIDValidity)

	if err == pgx.ErrNoRows {
		return false, fmt.Errorf("mailbox not found")
	}
	if err != nil {
		return false, fmt.Errorf("failed to query UIDVALIDITY: %w", err)
	}

	return currentUIDValidity == clientUIDValidity, nil
}

func (d *Database) ValidateQResyncUIDValidityWithRetry(ctx context.Context, mailboxID int64, clientUIDValidity uint32) (bool, error) {
	return d.ValidateQResyncUIDValidity(ctx, mailboxID, clientUIDValidity)
}

// GetActiveUIDsInSet returns the active (non-expunged) UIDs in the mailbox that fall within the given UIDSet.
// This is used for QRESYNC SELECT to efficiently check which of the client's known UIDs are still active.
func (d *Database) GetActiveUIDsInSet(ctx context.Context, mailboxID int64, uidSet imap.UIDSet) ([]imap.UID, error) {
	if len(uidSet) == 0 {
		return nil, nil
	}

	var conditions []string
	var args []any
	args = append(args, mailboxID)

	for _, uidRange := range uidSet {
		if uidRange.Stop == imap.UID(0) || uidRange.Start == uidRange.Stop {
			args = append(args, int64(uidRange.Start))
			conditions = append(conditions, fmt.Sprintf("uid = $%d", len(args)))
		} else {
			args = append(args, int64(uidRange.Start), int64(uidRange.Stop))
			conditions = append(conditions, fmt.Sprintf("(uid >= $%d AND uid <= $%d)", len(args)-1, len(args)))
		}
	}

	whereClause := strings.Join(conditions, " OR ")

	query := fmt.Sprintf(`
		SELECT uid
		FROM messages
		WHERE mailbox_id = $1
		  AND expunged_at IS NULL
		  AND (%s)
		ORDER BY uid
	`, whereClause)

	rows, err := d.GetReadPool().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query active UIDs in set: %w", err)
	}
	defer rows.Close()

	var uids []imap.UID
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan active UID: %w", err)
		}
		uids = append(uids, imap.UID(uid))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating active UIDs in set: %w", err)
	}

	return uids, nil
}

func (d *Database) GetActiveUIDsInSetWithRetry(ctx context.Context, mailboxID int64, uidSet imap.UIDSet) ([]imap.UID, error) {
	return d.GetActiveUIDsInSet(ctx, mailboxID, uidSet)
}
