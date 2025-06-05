package db

import (
	"context"
	"fmt"
	"log"
)

func (db *Database) ListMessages(ctx context.Context, mailboxID int64) ([]Message, error) {
	var messages []Message

	// First, check if there are any messages in the mailbox at all (including expunged)
	var totalCount, expungedCount int
	err := db.Pool.QueryRow(ctx, `
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

	log.Printf("[LIST] Mailbox %d has %d total messages, %d expunged, %d active",
		mailboxID, totalCount, expungedCount, totalCount-expungedCount)

	// Now query only the non-expunged messages
	query := `
		WITH numbered_messages AS (
			SELECT 
				account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
				internal_date, size, body_structure,
				created_modseq, updated_modseq, expunged_modseq,
				ROW_NUMBER() OVER (ORDER BY uid) AS seqnum
			FROM messages
			WHERE mailbox_id = $1 AND expunged_at IS NULL
		)
		SELECT 
			account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
			internal_date, size, body_structure,
			created_modseq, updated_modseq, expunged_modseq, seqnum
		FROM numbered_messages
		ORDER BY uid` // Ordering by uid is fine, seqnum is derived based on id order

	rows, err := db.Pool.Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	messages, err = scanMessages(rows) // scanMessages will close rows
	if err != nil {
		return nil, fmt.Errorf("ListMessages: failed to scan messages: %w", err)
	}

	log.Printf("[LIST] Returning %d messages for mailbox %d", len(messages), mailboxID)
	return messages, nil
}
