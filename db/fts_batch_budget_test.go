package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A batch that cannot finish before its deadline must commit the hashes it did finish, not
// run into the deadline. Otherwise the transaction rolls back, and because the queue is
// FIFO the same rows are polled again next time: a backlog bigger than one deadline's worth
// of work would never drain.
func TestFTSBatchCommitsPartialProgressBeforeDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, _ := setupCleanerTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// An interrupted earlier run leaves its rows at the head of the queue, where this batch
	// would index them instead of its own.
	_, err := db.GetWritePool().Exec(ctx, `DELETE FROM messages_fts_v2 WHERE content_hash LIKE 'budget\_%'`)
	require.NoError(t, err)

	const rows = 3000
	prefix := fmt.Sprintf("budget_%d_", time.Now().UnixNano())
	// Dated far in the past so a FIFO poll takes these first.
	_, err = db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date, created_at)
		SELECT $1 || g, $2, 'quarterly report number ' || g || repeat(' filler words here', 50),
		       now(), '1900-02-01'::timestamptz + make_interval(secs => g)
		FROM generate_series(1, $3) g`, prefix, accountID, rows)
	require.NoError(t, err)
	t.Cleanup(func() {
		db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE content_hash LIKE $1`, prefix+"%")
	})

	batchCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	tx, err := db.GetWritePool().Begin(batchCtx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background()) // releases the polled rows if an assertion fails
	n, err := db.ProcessFTSBatch(batchCtx, tx, rows)
	require.NoError(t, err, "a batch that runs short of time must stop and report progress, not fail at the deadline")
	require.NoError(t, tx.Commit(batchCtx))
	require.Greater(t, n, 0)
	require.Less(t, n, rows, "the fixture must be too large for one deadline, or this test proves nothing")

	var indexed, queued, poisoned int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE length(text_body_tsv) > 0),
		       count(*) FILTER (WHERE text_body_tsv IS NULL),
		       count(*) FILTER (WHERE length(text_body_tsv) = 0)
		FROM messages_fts_v2 WHERE content_hash LIKE $1`, prefix+"%").Scan(&indexed, &queued, &poisoned))
	require.Equal(t, n, indexed, "the progress reported is the progress committed")
	require.Equal(t, rows-n, queued, "the rest stays queued for the next batch")
	require.Equal(t, 0, poisoned)
}
