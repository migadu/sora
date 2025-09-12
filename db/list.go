package db

import (
	"context"
	"fmt"
)

func (db *Database) ListMessages(ctx context.Context, mailboxID int64) ([]Message, error) {
	var messages []Message

	// First, check if there are any messages in the mailbox at all (including expunged)
	var totalCount, expungedCount int
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT 
			COUNT(*) as total_count,
			COUNT(*) FILTER (WHERE expunged_at IS NOT NULL) as expunged_count
		FROM 
			messages
		WHERE 
			mailbox_id = $1
	`, mailboxID).Scan(&totalCount, &expungedCount)

	if err != nil {
		return nil, fmt.Errorf("failed to count messages: %v", err)
	}

	// Now query only the non-expunged messages
	query := `
		WITH numbered_messages AS (
			SELECT
				id, account_id, uid, mailbox_id, content_hash, s3_domain, s3_localpart, uploaded, flags, custom_flags,
				internal_date, size, body_structure, in_reply_to, recipients_json, created_modseq, updated_modseq, expunged_modseq,
				flags_changed_at, subject, sent_date, message_id,
				ROW_NUMBER() OVER (ORDER BY uid) AS seqnum
			FROM messages m
			WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		)
		SELECT 
			id, account_id, uid, mailbox_id, content_hash, s3_domain, s3_localpart, uploaded, flags, custom_flags,
			internal_date, size, body_structure, created_modseq, updated_modseq, expunged_modseq, seqnum,
			flags_changed_at, subject, sent_date, message_id, in_reply_to, recipients_json
		FROM numbered_messages
		ORDER BY uid` // Ordering by uid is fine, seqnum is derived based on id order

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	messages, err = scanMessages(rows) // scanMessages will close rows
	if err != nil {
		return nil, fmt.Errorf("ListMessages: failed to scan messages: %w", err)
	}

	return messages, nil
}
