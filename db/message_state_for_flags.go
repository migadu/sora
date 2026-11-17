package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Missing state is initialized only while applying an explicit flag-write request.
// Reads, startup and background work never backfill historical rows. Existing
// unknown flags cannot be recovered; the requested write starts from the empty
// state already exposed by FETCH, with unknown immutable initial_modseq.

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
