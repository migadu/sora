package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Every insert path writes a message's message_state row in the statement that inserts
// the message, but older builds left live messages without one (#1151):
//
//   - a database that ran migration 000022 without its copy of the flags (#613) lost the
//     row of every message it held;
//   - a restore before 89a559d5 brought back a message whose mailbox an older build had
//     purged, which deleted its row, and wrote none;
//   - COPY and MOVE before #1213 built the new message's row with an inner join on the
//     source's, so a copy or move of such a message had none either.
//
// Readers show such a message with no flags (COALESCE(ms.flags, 0)), but SEARCH's flag
// tests are NULL for it, the unseen count and the first-unseen lookup count only rows,
// and the flag writers updated the row that was not there. Only the message's body in S3
// could tell its lost flags, and nothing kept them, so both online flag writers (on
// demand) and the offline repair give it the state it is already shown with: no flags
// and no keywords.

const missingMessageStateBatchSQL = `
	SELECT s.id, live.mailbox_id
	FROM (
		SELECT m.id, (ms.message_id IS NULL) AS stateless
		FROM (
			SELECT id FROM messages WHERE id > $1 ORDER BY id LIMIT $2
		) m
		LEFT JOIN message_state ms ON ms.message_id = m.id
	) s
	LEFT JOIN LATERAL (
		SELECT l.mailbox_id
		FROM messages l
		WHERE s.stateless AND l.id = s.id AND l.expunged_at IS NULL AND l.mailbox_id IS NOT NULL
	) live ON TRUE
	ORDER BY s.id`

const missingMessageStateMailboxesSQL = `
	SELECT DISTINCT m.mailbox_id
	FROM messages m
	WHERE m.id = ANY($1::bigint[]) AND m.expunged_at IS NULL AND m.mailbox_id IS NOT NULL
	  AND NOT EXISTS (SELECT 1 FROM message_state ms WHERE ms.message_id = m.id)
	ORDER BY 1`

const lockMailboxesSQL = `SELECT id FROM mailboxes WHERE id = ANY($1::bigint[]) ORDER BY id FOR UPDATE`

// seedMissingMailboxStatsSQL ensures each locked mailbox has a mailbox_stats row seeded
// from its live messages before maintain_mailbox_stats_state() fires on INSERT into
// message_state (otherwise a pre-000037 restored mailbox with no mailbox_stats row gets
// a row created with message_count = 0 and highest_modseq = 0).
const seedMissingMailboxStatsSQL = `
	INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
	SELECT mb_id,
	       COALESCE((SELECT COUNT(*) FROM messages m WHERE m.mailbox_id = mb_id AND m.expunged_at IS NULL), 0),
	       0,
	       COALESCE((SELECT SUM(m.size) FROM messages m WHERE m.mailbox_id = mb_id AND m.expunged_at IS NULL), 0),
	       COALESCE((SELECT MAX(GREATEST(m.created_modseq, COALESCE(m.expunged_modseq, 0))) FROM messages m WHERE m.mailbox_id = mb_id), 1),
	       now()
	FROM unnest($1::bigint[]) AS mb_id
	WHERE NOT EXISTS (SELECT 1 FROM mailbox_stats ms WHERE ms.mailbox_id = mb_id)
	ON CONFLICT (mailbox_id) DO NOTHING`

// addMissingMessageStateSQL writes a row with the column defaults (no flags, no keywords,
// no updated_modseq, initial_modseq = NULL) for each message of $1 that is still live in
// one of the mailboxes of $2 and has none, and returns the mailbox of each row it wrote.
const addMissingMessageStateSQL = `
	INSERT INTO message_state (message_id, mailbox_id)
	SELECT m.id, m.mailbox_id
	FROM messages m
	WHERE m.id = ANY($1::bigint[]) AND m.expunged_at IS NULL AND m.mailbox_id = ANY($2::bigint[])
	ORDER BY m.id
	ON CONFLICT (message_id) DO NOTHING
	RETURNING mailbox_id`

var recountMailboxUnseenSQL = `
	UPDATE mailbox_stats ms
	SET unseen_count = ` + liveUnseenCount("ms.mailbox_id") + `,
	    updated_at = now()
	WHERE ms.mailbox_id = ANY($1::bigint[])`

// MessageWithoutState is a live message without a message_state row.
type MessageWithoutState struct {
	ID        int64
	MailboxID int64
}

// MissingStateBatch is one batch of FindMissingMessageState.
type MissingStateBatch struct {
	Scanned int                   // message rows read, live or not; 0 at the end of the table
	LastID  int64                 // the last id read: where the next batch starts
	Missing []MessageWithoutState // the live messages among them without a row, in id order
}

// MessageStateRepair is what one AddMissingMessageState wrote.
type MessageStateRepair struct {
	Added     int64   // rows written
	Mailboxes []int64 // the mailboxes they were written in, whose unseen_count was counted again, in id order
}

// FindMissingMessageState reads up to limit message ids after afterID, in id order, and
// returns the live messages among them that have no message_state row.
func (d *Database) FindMissingMessageState(ctx context.Context, afterID int64, limit int) (MissingStateBatch, error) {
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, missingMessageStateBatchSQL, pgx.QueryExecModeExec, afterID, limit)
	if err != nil {
		return MissingStateBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	defer rows.Close()

	var batch MissingStateBatch
	for rows.Next() {
		var id int64
		var mailboxID *int64
		if err := rows.Scan(&id, &mailboxID); err != nil {
			return MissingStateBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
		}
		batch.Scanned++
		batch.LastID = id
		if mailboxID != nil {
			batch.Missing = append(batch.Missing, MessageWithoutState{ID: id, MailboxID: *mailboxID})
		}
	}
	if err := rows.Err(); err != nil {
		return MissingStateBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	return batch, nil
}

// AddMissingMessageState gives each message of ids that is still live and still has no
// message_state row one with no flags and no keywords, without bumping modseq, and
// recomputes unseen_count for the affected mailboxes.
func (d *Database) AddMissingMessageState(ctx context.Context, tx pgx.Tx, ids []int64) (MessageStateRepair, error) {
	if len(ids) == 0 {
		return MessageStateRepair{}, nil
	}
	candidates, err := collectInt64s(tx.Query(ctx, missingMessageStateMailboxesSQL, pgx.QueryExecModeExec, ids))
	if err != nil {
		return MessageStateRepair{}, fmt.Errorf("failed to read the mailboxes of %d message(s): %w", len(ids), err)
	}
	if len(candidates) == 0 {
		return MessageStateRepair{}, nil
	}
	mailboxes, err := collectInt64s(tx.Query(ctx, lockMailboxesSQL, pgx.QueryExecModeExec, candidates))
	if err != nil {
		return MessageStateRepair{}, fmt.Errorf("failed to lock %d mailbox(es): %w", len(candidates), err)
	}
	if len(mailboxes) == 0 {
		return MessageStateRepair{}, nil
	}
	if _, err := tx.Exec(ctx, seedMissingMailboxStatsSQL, pgx.QueryExecModeExec, mailboxes); err != nil {
		return MessageStateRepair{}, fmt.Errorf("failed to initialize stats of %d mailbox(es): %w", len(mailboxes), err)
	}
	added, err := collectInt64s(tx.Query(ctx, addMissingMessageStateSQL, pgx.QueryExecModeExec, ids, mailboxes))
	if err != nil {
		return MessageStateRepair{}, fmt.Errorf("failed to add the state of %d message(s): %w", len(ids), err)
	}
	if len(added) == 0 {
		return MessageStateRepair{}, nil
	}
	repair := MessageStateRepair{Added: int64(len(added))}
	wrote := make(map[int64]bool, len(mailboxes))
	for _, mailboxID := range added {
		wrote[mailboxID] = true
	}
	for _, mailboxID := range mailboxes {
		if wrote[mailboxID] {
			repair.Mailboxes = append(repair.Mailboxes, mailboxID)
		}
	}
	if _, err := tx.Exec(ctx, recountMailboxUnseenSQL, pgx.QueryExecModeExec, repair.Mailboxes); err != nil {
		return MessageStateRepair{}, fmt.Errorf("failed to count the unseen messages of %d mailbox(es) again: %w", len(repair.Mailboxes), err)
	}
	return repair, nil
}

// ensureMessageStateForLockedMailbox seeds missing message_state rows (flags = 0,
// custom_flags = '[]', updated_modseq = NULL, initial_modseq = NULL) and reconciles
// mailbox_stats.unseen_count before an online flag writer runs its UPDATE. The caller
// must already hold lockMailboxStats(ctx, tx, mailboxID).
func (d *Database) ensureMessageStateForLockedMailbox(ctx context.Context, tx pgx.Tx, mailboxID int64, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	mailboxes := []int64{mailboxID}
	if _, err := tx.Exec(ctx, seedMissingMailboxStatsSQL, mailboxes); err != nil {
		return fmt.Errorf("failed to initialize mailbox_stats for mailbox %d: %w", mailboxID, err)
	}
	added, err := collectInt64s(tx.Query(ctx, addMissingMessageStateSQL, ids, mailboxes))
	if err != nil {
		return fmt.Errorf("failed to seed missing message_state in mailbox %d: %w", mailboxID, err)
	}
	if len(added) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, recountMailboxUnseenSQL, mailboxes); err != nil {
		return fmt.Errorf("failed to recount unseen messages in mailbox %d: %w", mailboxID, err)
	}
	return nil
}

func collectInt64s(rows pgx.Rows, err error) ([]int64, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
