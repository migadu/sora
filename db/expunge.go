package db

import (
	"context"
	"log"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

func (db *Database) ExpungeMessageUIDs(ctx context.Context, tx pgx.Tx, mailboxID int64, uids ...imap.UID) (int64, error) {
	if len(uids) == 0 {
		log.Printf("[DB] no UIDs to expunge for mailbox %d", mailboxID)
		return 0, nil
	}

	log.Printf("[DB] expunging %d messages from mailbox %d: %v", len(uids), mailboxID, uids)

	var currentModSeq int64
	var rowsAffected int64
	err := tx.QueryRow(ctx, `
		WITH updated AS (
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
			RETURNING expunged_modseq
		)
		SELECT COUNT(*), COALESCE(MAX(expunged_modseq), 0)
		FROM updated
	`, mailboxID, uids).Scan(&rowsAffected, &currentModSeq)

	if err != nil {
		log.Printf("[DB] error executing expunge update: %v", err)
		return 0, err
	}

	log.Printf("[DB] successfully expunged %d messages from mailbox %d, current modseq: %d", rowsAffected, mailboxID, currentModSeq)
	return currentModSeq, nil
}
