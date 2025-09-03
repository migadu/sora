package db

import (
	"context"
	"fmt"
	"log"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (db *Database) MoveMessages(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	// Map to store the original UID to new UID mapping
	messageUIDMap := make(map[imap.UID]imap.UID)

	// Check if source and destination mailboxes are the same
	if srcMailboxID == destMailboxID {
		log.Printf("[DB] WARNING: source and destination mailboxes are the same (ID=%d). Aborting move operation.", srcMailboxID)
		return nil, fmt.Errorf("cannot move messages within the same mailbox")
	}

	// Ensure the destination mailbox exists
	_, err := db.GetMailbox(ctx, destMailboxID, userID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to fetch mailbox %d: %v", destMailboxID, err)
		return nil, consts.ErrMailboxNotFound
	}

	// Begin a transaction
	tx, err := db.BeginTx(ctx)
	if err != nil {
		log.Printf("[DB] ERROR: failed to begin transaction: %v", err)
		return nil, consts.ErrInternalError
	}
	defer tx.Rollback(ctx) // Rollback if any error occurs

	// Get the count of messages to move
	var messageCount int
	err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND uid = ANY($2)", srcMailboxID, ids).Scan(&messageCount)
	if err != nil {
		log.Printf("[DB] ERROR: failed to count messages to move: %v", err)
		return nil, consts.ErrInternalError
	}

	if messageCount == 0 {
		log.Printf("[DB] WARNING: no messages found to move from mailbox %d", srcMailboxID)
		return messageUIDMap, nil
	}

	// Lock the destination mailbox and get the current highest UID
	var highestUID int64
	err = tx.QueryRow(ctx, `
		SELECT highest_uid 
		FROM mailboxes 
		WHERE id = $1 
		FOR UPDATE;`, destMailboxID).Scan(&highestUID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to fetch highest UID: %v", err)
		return nil, consts.ErrDBQueryFailed
	}

	// Get the source message IDs and UIDs
	rows, err := tx.Query(ctx, `
		SELECT id, uid FROM messages 
		WHERE mailbox_id = $1 AND uid = ANY($2)
		ORDER BY uid
	`, srcMailboxID, ids)
	if err != nil {
		log.Printf("[DB] ERROR: failed to query source messages: %v", err)
		return nil, consts.ErrInternalError
	}
	defer rows.Close()

	// Collect message IDs and assign new UIDs
	var messageIDs []int64
	var newUIDs []int64
	for rows.Next() {
		var messageID int64
		var sourceUID imap.UID
		if err := rows.Scan(&messageID, &sourceUID); err != nil {
			return nil, fmt.Errorf("failed to scan message ID and UID: %v", err)
		}
		messageIDs = append(messageIDs, messageID)

		highestUID++
		newUIDs = append(newUIDs, highestUID)
		messageUIDMap[sourceUID] = imap.UID(highestUID)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through source messages: %v", err)
	}

	// Update the highest UID in the destination mailbox
	_, err = tx.Exec(ctx, `
		UPDATE mailboxes 
		SET highest_uid = $1 
		WHERE id = $2
	`, highestUID, destMailboxID)
	if err != nil {
		log.Printf("[DB] ERROR: failed to update highest UID: %v", err)
		return nil, consts.ErrDBUpdateFailed
	}

	// Move each message individually with its assigned UID
	for i, messageID := range messageIDs {
		newUID := newUIDs[i]

		_, err = tx.Exec(ctx, `
			INSERT INTO messages (
				account_id,
				content_hash, 
				uploaded,
				message_id, 
				in_reply_to, 
				subject, 
				sent_date, 
				internal_date, 
				flags, 
				custom_flags,
				size, 
				body_structure, 
				recipients_json,
				mailbox_id, 
				mailbox_path, 
				flags_changed_at,
				created_modseq,
				uid
			)
			SELECT 
				account_id,
				content_hash, 
				uploaded,
				message_id, 
				in_reply_to, 
				subject, 
				sent_date, 
				internal_date, 
				flags, 
				custom_flags,
				size, 
				body_structure, 
				recipients_json,
				$1 AS mailbox_id,  -- Assign to the new mailbox
				mailbox_path, 
				NOW() AS flags_changed_at,
				nextval('messages_modseq'),
				$2 -- Assign the new UID
			FROM messages
			WHERE id = $3 AND mailbox_id = $4
		`, destMailboxID, newUID, messageID, srcMailboxID)

		if err != nil {
			log.Printf("[DB] ERROR: failed to insert message %d into destination mailbox: %v", messageID, err)
			return nil, fmt.Errorf("failed to move message %d: %v", messageID, err)
		}
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

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		log.Printf("[DB] ERROR: failed to commit transaction: %v", err)
		return nil, consts.ErrInternalError
	}

	return messageUIDMap, nil
}
