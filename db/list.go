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
			SELECT m.*, ROW_NUMBER() OVER(ORDER BY m.uid) as seqnum
			FROM messages m
			WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		)
		SELECT 
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded,
			ms.flags, ms.custom_flags,
			m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq, m.seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM numbered_messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id
		ORDER BY m.uid`

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	messages, err = scanMessages(rows, false) // scanMessages will close rows
	if err != nil {
		return nil, fmt.Errorf("ListMessages: failed to scan messages: %w", err)
	}

	return messages, nil
}
