package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

func (db *Database) ExpungeMessageUIDs(ctx context.Context, tx pgx.Tx, mailboxID int64, uids ...imap.UID) (int64, error) {
	start := time.Now()
	var err error
	defer func() {
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.DBQueryDuration.WithLabelValues("message_expunge", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("message_expunge", status, "write").Inc()
	}()

	if len(uids) == 0 {
		logger.Info("Database: no UIDs to expunge", "mailbox_id", mailboxID)
		return 0, nil
	}

	logger.Info("Database: expunging messages", "count", len(uids), "mailbox_id", mailboxID, "uids", uids)

	// Serialize unseen_count maintenance per mailbox so the expunge trigger and a
	// concurrent flag-change trigger can't race their cross-table reads and drift
	// the cache negative. See lockMailboxStats for the full rationale.
	if err = lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return 0, err
	}

	var currentModSeq int64
	var rowsAffected int64
	err = tx.QueryRow(ctx, `
		WITH updated AS (
			UPDATE messages m
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE m.mailbox_id = $1 AND m.uid = ANY($2::bigint[]) AND m.expunged_at IS NULL
			RETURNING expunged_modseq
		)
		SELECT COUNT(*), COALESCE(MAX(expunged_modseq), 0)
		FROM updated
	`, mailboxID, uids).Scan(&rowsAffected, &currentModSeq)

	if err != nil {
		logger.Error("Database: error executing expunge update", "err", err)
		return 0, err
	}

	logger.Info("Database: successfully expunged messages", "count", rowsAffected, "mailbox_id", mailboxID, "modseq", currentModSeq)
	return currentModSeq, nil
}

// ExpungeMessagesByIDs marks the given message rows expunged (two-phase deletion): the
// rows stay until the cleaner, after the grace period and under its per-object lock,
// confirms that nothing else references each S3 object and deletes both. Admin tools
// that want a mailbox emptied use this rather than deleting objects themselves: a
// message COPY'd into another folder shares the object, and deleting it directly took
// the other folder's copy with it. Returns how many rows were newly expunged.
func (db *Database) ExpungeMessagesByIDs(ctx context.Context, tx pgx.Tx, messageIDs []int64) (int64, error) {
	if len(messageIDs) == 0 {
		return 0, nil
	}

	// Lock the mailboxes rows of the live messages before expunging them, as every
	// other unseen-mutating path does (see lockMailboxStats): without it the expunge
	// trigger and a concurrent flag change's trigger can both charge the same unseen
	// message to unseen_count. The messages may span several mailboxes (a purge passes
	// a mailbox and its children), so the rows are locked in ascending id order, like
	// the age-based expunge and MOVE, which keeps this deadlock-free against them.
	rows, err := tx.Query(ctx, `
		SELECT id FROM mailboxes
		WHERE id IN (SELECT mailbox_id FROM messages WHERE id = ANY($1) AND expunged_at IS NULL)
		ORDER BY id
		FOR UPDATE
	`, messageIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to lock mailboxes for expunge by id: %w", err)
	}
	lockedMailboxIDs, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return 0, fmt.Errorf("failed to lock mailboxes for expunge by id: %w", err)
	}

	// Expunge only rows in a mailbox locked above. A message that was already expunged
	// when the mailboxes were picked and has been restored since may sit in a mailbox
	// this transaction does not hold, and locking that one now would break the ascending
	// order; it is left alone, as if this ran before the restore. A row without a
	// mailbox is expunged as before: the stats triggers skip it.
	tag, err := tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE id = ANY($1) AND expunged_at IS NULL
		  AND (mailbox_id = ANY($2) OR mailbox_id IS NULL)
	`, messageIDs, lockedMailboxIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to expunge messages by id: %w", err)
	}
	return tag.RowsAffected(), nil
}
