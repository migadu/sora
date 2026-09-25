package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Queued rows that carry no text of their own must be resolved from whichever row of the
// same body still holds pending text, instead of being left queued for that row's turn.
func TestFTSTextlessRowsResolveFromPendingText(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, _ := setupCleanerTestDatabase(t)
	t.Cleanup(db.Close) // registered first, so it runs after every other cleanup
	ctx := context.Background()

	// Rows are dated far in the past so a FIFO poll of the queue takes them first.
	stageV2 := func(hash string, acct int64, text any, createdAt string) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date, created_at)
			VALUES ($1, $2, $3, now(), $4::timestamptz)`, hash, acct, text, createdAt)
		require.NoError(t, err)
	}
	cleanup := func(hash string) {
		t.Cleanup(func() {
			db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE content_hash = $1`, hash)
			db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts WHERE content_hash = $1`, hash)
		})
	}
	runBatch := func(limit int) int {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		n, err := db.ProcessFTSBatch(ctx, tx, limit)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return n
	}
	requireIndexed := func(hash string, want int) {
		t.Helper()
		var indexed, queued int
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE text_body_tsv @@ plainto_tsquery('simple', 'quarterly')),
			       count(*) FILTER (WHERE text_body_tsv IS NULL)
			FROM messages_fts_v2 WHERE content_hash = $1`, hash).Scan(&indexed, &queued))
		require.Equal(t, want, indexed, "every row of the body must carry its real vector")
		require.Equal(t, 0, queued)
	}

	t.Run("text only in messages_fts", func(t *testing.T) {
		// Delivered by an old-binary node (or its v2 stage failed): the only pending text is
		// in the shared table, which the worker no longer polls.
		hash := fmt.Sprintf("v1only_%d", time.Now().UnixNano())
		cleanup(hash)
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body, sent_date) VALUES ($1, 'quarterly report', now())`, hash)
		require.NoError(t, err)
		stageV2(hash, accountID, nil, "1900-01-01")

		n := runBatch(1)
		require.Equal(t, 1, n, "the textless row must be resolved, not left queued forever")
		requireIndexed(hash, 1)

		var v1Text *string
		var v1Lexemes int
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT text_body, length(text_body_tsv) FROM messages_fts WHERE content_hash = $1`, hash).Scan(&v1Text, &v1Lexemes))
		require.Nil(t, v1Text, "the shared row's text is consumed")
		require.Greater(t, v1Lexemes, 0, "the shared row gets the same vector (dual-write)")
	})

	t.Run("textless rows ahead of their text row fill the batch", func(t *testing.T) {
		// Two textless rows sort ahead of the one row carrying the text, and the batch holds
		// only two. Leaving them queued resolves nothing, the worker stops for the tick, and
		// the next tick polls the same two rows again.
		hash := fmt.Sprintf("fifo_%d", time.Now().UnixNano())
		cleanup(hash)
		stageV2(hash, accountID, nil, "1900-01-02")
		stageV2(hash, accountID+3_200_000, nil, "1900-01-03")
		stageV2(hash, accountID+3_200_001, "quarterly report", "1900-01-04")

		n := runBatch(2)
		require.Equal(t, 3, n, "the text row is tokenised and the vector fanned out to both polled rows")
		requireIndexed(hash, 3)
	})
}
