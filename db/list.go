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
		SELECT 
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
			m.internal_date, m.size, m.body_structure, m.created_modseq, m.updated_modseq, m.expunged_modseq, ms.seqnum,
			m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		JOIN message_sequences ms ON m.mailbox_id = ms.mailbox_id AND m.uid = ms.uid
		WHERE m.mailbox_id = $1 ORDER BY ms.seqnum`

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
