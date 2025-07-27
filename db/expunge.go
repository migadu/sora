package db

import (
	"context"
	"fmt"
	"log"

	"github.com/emersion/go-imap/v2"
)

func (db *Database) ExpungeMessageUIDs(ctx context.Context, mailboxID int64, uids ...imap.UID) (int64, error) {
	if len(uids) == 0 {
		log.Printf("[DB] no UIDs to expunge for mailbox %d", mailboxID)
		return 0, nil
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction for ExpungeMessageUIDs: %w", err)
	}
	// Defer rollback in case of errors. Commit will be called explicitly on success.
	defer tx.Rollback(ctx)

	log.Printf("[DB] expunging %d messages from mailbox %d: %v", len(uids), mailboxID, uids)

	result, err := tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
	`, mailboxID, uids)

	if err != nil {
		log.Printf("[DB] error executing expunge update: %v", err)
		return 0, err
	}

	rowsAffected := result.RowsAffected()
	log.Printf("[DB] successfully expunged %d messages from mailbox %d", rowsAffected, mailboxID)

	// Get the current MODSEQ after expunge operation
	var currentModSeq int64
	err = tx.QueryRow(ctx, "SELECT currval('messages_modseq')").Scan(&currentModSeq)
	if err != nil {
		log.Printf("[DB] error getting current modseq after expunge: %v", err)
		return 0, err
	}

	// Double-check that the messages were actually expunged within the transaction
	var count int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM messages 
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
	`, mailboxID, uids).Scan(&count)

	if err != nil {
		// If the check itself fails, it's an issue, but the primary update might have succeeded.
		// Depending on policy, you might still want to commit or force a rollback.
		// For now, log it and proceed to commit if the UPDATE was successful.
		log.Printf("[DB] error checking if messages were expunged within transaction: %v", err)
	} else if count > 0 {
		log.Printf("[DB] WARNING: %d messages were not expunged", count)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit transaction for ExpungeMessageUIDs: %w", err)
	}

	return currentModSeq, nil
}
