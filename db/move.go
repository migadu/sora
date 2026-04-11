package db

import (
	"context"
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
)

func (db *Database) MoveMessages(ctx context.Context, tx pgx.Tx, ids *[]imap.UID, srcMailboxID, destMailboxID int64, AccountID int64) (map[imap.UID]imap.UID, error) {
	// Map to store the original UID to new UID mapping
	messageUIDMap := make(map[imap.UID]imap.UID)

	// Per RFC 6851, moving to the same mailbox is allowed and assigns new UIDs.
	// This is useful for "refreshing" messages with new UIDs.
	if srcMailboxID == destMailboxID {
		logger.Info("Database: moving messages within the same mailbox, will assign new UIDs", "mailbox_id", srcMailboxID)
	}

	// Acquire locks on both mailboxes in a consistent order to prevent deadlocks.
	// The triggers for mailbox_stats will attempt to acquire
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

	// Lock source message rows early (before INSERT triggers) to establish a
	// consistent lock ordering: advisory mailbox lock → row locks on source rows.
	// Without FOR UPDATE here, concurrent EXPUNGE could hold row locks and then
	// wait for the advisory lock while MOVE holds the advisory lock and waits
	// for those same row locks → deadlock.
	rows, err := tx.Query(ctx, `
		SELECT id, uid FROM messages
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
		ORDER BY uid
		FOR UPDATE
	`, srcMailboxID, ids)
	if err != nil {
		logger.Error("Database: failed to query source messages", "err", err)
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
		logger.Warn("Database: no messages found to move", "mailbox_id", srcMailboxID)
		return messageUIDMap, nil
	}

	// Atomically increment highest_uid for the number of messages being moved.
	var newHighestUID int64
	numToMove := int64(len(messageIDs))
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $1 WHERE id = $2 RETURNING highest_uid`, numToMove, destMailboxID).Scan(&newHighestUID)
	if err != nil {
		logger.Error("Database: failed to update highest UID", "err", err)
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

	// Batch insert the moved messages.
	//
	// For same-mailbox moves, we must mark old messages as expunged BEFORE inserting
	// new ones to avoid having two active copies of the same message.
	if srcMailboxID == destMailboxID {
		// Step 1: Mark old messages as expunged to remove them from the unique index
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND id = ANY($2) AND expunged_at IS NULL
		`, srcMailboxID, messageIDs)
		if err != nil {
			logger.Error("Database: failed to mark messages as expunged for same-mailbox move", "err", err)
			return nil, fmt.Errorf("failed to mark messages as expunged: %w", err)
		}

		// Step 2: Insert new copies with new UIDs
		// The expunged messages are now excluded from the unique index, so this succeeds
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
					nextval('messages_modseq') AS created_modseq,
					new_uid
				FROM src_data
				RETURNING id, uid
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT i.id, $1, ms.flags, ms.custom_flags, NOW(), nextval('messages_modseq')
			FROM inserted i
			JOIN src_data s ON s.new_uid = i.uid
			JOIN message_state ms ON ms.message_id = s.original_id
		`, srcMailboxID, destMailboxName, messageIDs, newUIDs)
		if err != nil {
			logger.Error("Database: failed to insert new messages for same-mailbox move", "err", err)
			return nil, fmt.Errorf("failed to move messages: %w", err)
		}
		logger.Info("Database: moved message(s) with new UIDs in same-mailbox move (old messages marked as expunged)", "count", len(messageIDs))
	} else {
		// Different mailbox: normal insert from existing rows
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
					nextval('messages_modseq') AS created_modseq,
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
			logger.Error("Database: failed to batch insert messages into destination mailbox", "err", err)
			return nil, fmt.Errorf("failed to move messages: %w", err)
		}
	}

	// Mark the original messages as expunged in the source mailbox
	// (unless we already did this above for same-mailbox moves)
	// AND expunged_at IS NULL ensures we only touch rows we actually locked via
	// FOR UPDATE above, avoiding unnecessary lock contention on already-expunged rows.
	if srcMailboxID != destMailboxID {
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND id = ANY($2) AND expunged_at IS NULL
		`, srcMailboxID, messageIDs)

		if err != nil {
			logger.Error("Database: failed to mark original messages as expunged", "err", err)
			return nil, fmt.Errorf("failed to mark original messages as expunged: %v", err)
		}
	}

	return messageUIDMap, nil
}
