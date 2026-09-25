package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// messages_fts stays dual-written through the soak so the release can be rolled back
// without data work. It must still be cleaned like it always was -- by retention, and when
// no message references a hash -- or it only ever grows, and a COPY's fan-out (which falls
// back to it for a vector) can bring a retention-pruned body back.
func TestFTSSharedTableStillCleanedDuringSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	t.Cleanup(db.Close) // registered first, so it runs after every other cleanup
	ctx := context.Background()
	ts := time.Now().UnixNano()

	v1Exists := func(hash string) bool {
		t.Helper()
		var n int
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM messages_fts WHERE content_hash = $1`, hash).Scan(&n))
		return n > 0
	}
	addVector := func(hash string, acct int64, sentDate string) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
			VALUES ($1, to_tsvector('simple', 'report'), $2::timestamptz) ON CONFLICT DO NOTHING`, hash, sentDate)
		require.NoError(t, err)
		_, err = db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
			VALUES ($1, $2, to_tsvector('simple', 'report'), $3::timestamptz)`, hash, acct, sentDate)
		require.NoError(t, err)
		t.Cleanup(func() {
			db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE content_hash = $1`, hash)
			db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts WHERE content_hash = $1`, hash)
		})
	}

	t.Run("retention prunes the shared row", func(t *testing.T) {
		expired := fmt.Sprintf("soak_expired_%d", ts)
		recent := fmt.Sprintf("soak_recent_%d", ts)
		addVector(expired, accountID, "1901-01-01")
		addVector(recent, accountID, time.Now().Format(time.RFC3339))

		// Other tests may leave older rows behind, and each call is capped, so drain.
		for i := 0; i < 100; i++ {
			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			n, err := db.PruneOldMessageVectors(ctx, tx, 365*24*time.Hour)
			require.NoError(t, err)
			require.NoError(t, tx.Commit(ctx))
			if n == 0 && !v1Exists(expired) {
				break
			}
		}
		assert.False(t, v1Exists(expired), "a shared row past retention must be pruned with its per-account rows")
		assert.True(t, v1Exists(recent), "a shared row within retention must stay")
	})

	t.Run("orphan sweep removes the shared row only when no message references the hash", func(t *testing.T) {
		orphan := fmt.Sprintf("soak_orphan_%d", ts)
		shared := fmt.Sprintf("soak_shared_%d", ts)
		otherAccount := accountID + 3_300_000
		addVector(orphan, accountID, time.Now().Format(time.RFC3339))
		// The per-account row for otherAccount is an orphan, but the body is still held by
		// a live message in accountID, so the shared row must stay.
		addVector(shared, otherAccount, time.Now().Format(time.RFC3339))
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
				                      internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, 9401, $3, 'subject', now(), now(), 100, TRUE, 'domain', 'part',
				        $4, 'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted`, accountID, mailboxID, shared, "<"+shared+"@example.com>")
		require.NoError(t, err)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		n, err := db.DeleteMessagesFTSByKeyBatch(ctx, tx, []FTSKey{
			{ContentHash: orphan, AccountID: accountID},
			{ContentHash: shared, AccountID: otherAccount},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		assert.Equal(t, int64(2), n, "both per-account rows are orphans")

		assert.False(t, v1Exists(orphan), "no message references the hash, so its shared row goes too")
		assert.True(t, v1Exists(shared), "a live message in another account still holds the body")
	})
}
