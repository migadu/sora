package db

import (
	"context"
	"fmt"
)

func (db *Database) ListMessages(ctx context.Context, mailboxID int64) ([]Message, error) {
	var messages []Message

	// Now query only the non-expunged messages
	query := `
		SELECT 
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded,
			ms.flags, ms.custom_flags,
			m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.uid`

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	messages, err = scanMessages(rows, false) // scanMessages will close rows
	if err != nil {
		return nil, fmt.Errorf("ListMessages: failed to scan messages: %w", err)
	}

	if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
		return nil, err
	}

	return messages, nil
}

// ListMessagesForPOP3 returns the lean POP3Message projection for every
// non-expunged message in the mailbox, ordered by UID. POP3 message numbers are
// positional, 1-based and stable for the session (RFC 1939 §5), so this skips the
// message_state JOIN, the heavy content columns, and the sequence-number
// hydration that ListMessages performs but POP3 never reads — holding far less
// memory and running one fewer query per session.
func (db *Database) ListMessagesForPOP3(ctx context.Context, mailboxID int64) ([]POP3Message, error) {
	query := `
		SELECT m.account_id, m.uid, m.content_hash, m.s3_domain, m.s3_localpart, m.size, m.uploaded
		FROM messages m
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.uid`

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("ListMessagesForPOP3: failed to query messages: %w", err)
	}
	defer rows.Close()

	var messages []POP3Message
	for rows.Next() {
		var m POP3Message
		if err := rows.Scan(&m.AccountID, &m.UID, &m.ContentHash, &m.S3Domain, &m.S3Localpart, &m.Size, &m.IsUploaded); err != nil {
			return nil, fmt.Errorf("ListMessagesForPOP3: failed to scan message: %w", err)
		}
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListMessagesForPOP3: row iteration failed: %w", err)
	}
	return messages, nil
}
