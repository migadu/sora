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

	// The messages may span several mailboxes (a purge passes a mailbox and its
	// children), so they are locked in ascending id order (see lockLiveMessageMailboxes).
	const byID = `m.id = ANY($1)`
	locked, err := lockLiveMessageMailboxes(ctx, tx, byID, messageIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to expunge messages by id: %w", err)
	}
	n, err := expungeLiveMessages(ctx, tx, locked, byID, messageIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to expunge messages by id: %w", err)
	}
	return n, nil
}

// lockLiveMessageMailboxes locks the mailboxes rows of the live messages that match cond,
// a condition on messages m over args, and returns their ids. Every other
// unseen-mutating path locks its mailbox first (see lockMailboxStats): without it the
// expunge trigger and a concurrent flag change's trigger can both charge the same unseen
// message to unseen_count. The rows are locked in ascending id order, like the age-based
// expunge and MOVE, which keeps this deadlock-free against them.
func lockLiveMessageMailboxes(ctx context.Context, tx pgx.Tx, cond string, args ...any) ([]int64, error) {
	return lockMailboxesOfLiveMessages(ctx, tx, "FOR UPDATE", cond, args...)
}

// lockIdleLiveMessageMailboxes is lockLiveMessageMailboxes for a caller that can leave
// some of the messages for a later run: it locks only the mailboxes no other transaction
// holds now (SKIP LOCKED), and never waits for one. The live messages of a mailbox it
// skips stay live, so a hard delete leaves them alone (see notLiveInMailbox).
func lockIdleLiveMessageMailboxes(ctx context.Context, tx pgx.Tx, cond string, args ...any) ([]int64, error) {
	return lockMailboxesOfLiveMessages(ctx, tx, "FOR UPDATE SKIP LOCKED", cond, args...)
}

func lockMailboxesOfLiveMessages(ctx context.Context, tx pgx.Tx, locking, cond string, args ...any) ([]int64, error) {
	rows, err := tx.Query(ctx, `
		SELECT id FROM mailboxes
		WHERE id IN (SELECT m.mailbox_id FROM messages m WHERE m.expunged_at IS NULL AND (`+cond+`))
		ORDER BY id
		`+locking, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to lock mailboxes: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, fmt.Errorf("failed to lock mailboxes: %w", err)
	}
	return ids, nil
}

// expungeLiveMessages expunges the live messages that match cond (as for
// lockLiveMessageMailboxes) and sit in one of mailboxIDs, the mailboxes the caller
// locked. A message that was already expunged when the mailboxes were picked and has
// been restored since may sit in a mailbox this transaction does not hold, and locking
// that one now would break the ascending order; it is left alone, as if this ran before
// the restore. A message without a mailbox is expunged as well: the stats triggers skip
// it. Returns how many rows were expunged.
func expungeLiveMessages(ctx context.Context, tx pgx.Tx, mailboxIDs []int64, cond string, args ...any) (int64, error) {
	tag, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE messages m
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE m.expunged_at IS NULL
		  AND (m.mailbox_id = ANY($%d) OR m.mailbox_id IS NULL)
		  AND (%s)
	`, len(args)+1, cond), append(args[:len(args):len(args)], mailboxIDs)...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// notLiveInMailbox holds for a message row that a hard delete may remove without
// leaving it counted: one that is expunged, or in no mailbox.
//
// A DELETE on messages removes the message's message_state row by cascade before
// either stats trigger runs, so the messages trigger can no longer read its flags and
// the message_state trigger can no longer see that it was live: a live message deleted
// directly stays in unseen_count. A hard delete therefore expunges the live rows it is
// about to delete first (lockLiveMessageMailboxes, then expungeLiveMessages), so that
// the expunge trigger takes them out of message_count, unseen_count and total_size
// under the mailbox lock, and deletes only rows that are then not live. One that still
// is came into a mailbox the delete did not lock, and is left for later.
// TestHardDeletesOfMessagesSkipLiveRows fails on a DELETE FROM messages that does not
// keep to such rows (#2023).
const notLiveInMailbox = `(m.expunged_at IS NOT NULL OR m.mailbox_id IS NULL)`

// hardDeleteMessages deletes the messages that match cond (as for
// lockLiveMessageMailboxes) for good, after expunging the live ones among them that sit
// in mailboxIDs, the mailboxes the caller locked with lockLiveMessageMailboxes (see
// notLiveInMailbox). Returns how many rows were deleted.
func hardDeleteMessages(ctx context.Context, tx pgx.Tx, mailboxIDs []int64, cond string, args ...any) (int64, error) {
	if _, err := expungeLiveMessages(ctx, tx, mailboxIDs, cond, args...); err != nil {
		return 0, fmt.Errorf("failed to expunge messages before deleting them: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM messages m WHERE `+notLiveInMailbox+` AND (`+cond+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to delete messages: %w", err)
	}
	return tag.RowsAffected(), nil
}
