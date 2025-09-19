package db

import (
	"context"
	"fmt"
	"log"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

func (db *Database) MoveMessages(ctx context.Context, tx pgx.Tx, ids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	// Map to store the original UID to new UID mapping
	messageUIDMap := make(map[imap.UID]imap.UID)

	// Check if source and destination mailboxes are the same
	if srcMailboxID == destMailboxID {
		log.Printf("[DB] WARNING: source and destination mailboxes are the same (ID=%d). Aborting move operation.", srcMailboxID)
		return nil, fmt.Errorf("cannot move messages within the same mailbox")
	}

	// Acquire locks on both mailboxes in a consistent order to prevent deadlocks.
	// The triggers for message_sequences and mailbox_stats will attempt to acquire
	// locks, and a concurrent MOVE operation between the same two mailboxes could
	// otherwise lead to a deadlock (A->B locks B then A; B->A locks A then B).
	var lock1, lock2 int64
	if srcMailboxID < destMailboxID {
		lock1 = srcMailboxID
		lock2 = destMailboxID
	} else {
		lock1 = destMailboxID
		lock2 = srcMailboxID
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1), pg_advisory_xact_lock($2)", lock1, lock2); err != nil {
		return nil, fmt.Errorf("failed to acquire locks for move on mailboxes %d and %d: %w", srcMailboxID, destMailboxID, err)
	}

	// Get the source message IDs and UIDs
	rows, err := tx.Query(ctx, `
		SELECT id, uid FROM messages 
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
		ORDER BY uid
	`, srcMailboxID, ids)
	if err != nil {
		log.Printf("[DB] ERROR: failed to query source messages: %v", err)
		return nil, consts.ErrInternalError
	}
	defer rows.Close()

	// Collect message IDs and source UIDs
	var messageIDs []int64
	var sourceUIDsForMap []imap.UID
	for rows.Next() {
		var messageID int64
		var sourceUID imap.UID
		if err := rows.Scan(&messageID, &sourceUID); err != nil {
			return nil, fmt.Errorf("failed to scan message ID and UID: %v", err)
		}
		messageIDs = append(messageIDs, messageID)
		sourceUIDsForMap = append(sourceUIDsForMap, sourceUID)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through source messages: %v", err)
	}

	if len(messageIDs) == 0 {
		log.Printf("[DB] WARNING: no messages found to move from mailbox %d", srcMailboxID)
		return messageUIDMap, nil
	}

	// Atomically increment highest_uid for the number of messages being moved.
	var newHighestUID int64
	numToMove := int64(len(messageIDs))
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $1 WHERE id = $2 RETURNING highest_uid`, numToMove, destMailboxID).Scan(&newHighestUID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to update highest UID: %v", err)
		return nil, consts.ErrDBUpdateFailed
	}

	// Calculate the new UIDs for the moved messages.
	var newUIDs []int64
	startUID := newHighestUID - numToMove + 1
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

	// Batch insert the moved messages into the destination mailbox.
	// This single query is much more efficient than inserting in a loop.
	// It also fixes a bug where s3_domain, s3_localpart, and the correct
	// mailbox_path were not being copied to the new message rows.
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (
			account_id, content_hash, uploaded, message_id, in_reply_to, 
			subject, sent_date, internal_date, flags, custom_flags, size, 
			body_structure, recipients_json, s3_domain, s3_localpart,
			subject_sort, from_name_sort, from_email_sort, to_email_sort, cc_email_sort,
			mailbox_id, mailbox_path, flags_changed_at, created_modseq, uid
		)
		SELECT 
			m.account_id, m.content_hash, m.uploaded, m.message_id, m.in_reply_to,
			m.subject, m.sent_date, m.internal_date, m.flags, m.custom_flags, m.size,
			m.body_structure, m.recipients_json, m.s3_domain, m.s3_localpart,
			m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_email_sort, m.cc_email_sort,
			$1 AS mailbox_id,
			$2 AS mailbox_path,
			NOW() AS flags_changed_at,
			nextval('messages_modseq'),
			d.new_uid
		FROM messages m
		JOIN unnest($3::bigint[], $4::bigint[]) AS d(message_id, new_uid) ON m.id = d.message_id
	`, destMailboxID, destMailboxName, messageIDs, newUIDs)
	if err != nil {
		log.Printf("[DB] ERROR: failed to batch insert messages into destination mailbox: %v", err)
		return nil, fmt.Errorf("failed to move messages: %w", err)
	}

	// Mark the original messages as expunged in the source mailbox
	_, err = tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE mailbox_id = $1 AND id = ANY($2)
	`, srcMailboxID, messageIDs)

	if err != nil {
		log.Printf("[DB] ERROR: failed to mark original messages as expunged: %v", err)
		return nil, fmt.Errorf("failed to mark original messages as expunged: %v", err)
	}

	return messageUIDMap, nil
}
