package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The backfill batches must find a body's accounts with an index-only scan on
// (content_hash, account_id). Joining mailboxes to key on the owner turns that into a heap
// fetch plus a mailbox lookup for every message row in the table -- measured 1.5x slower on
// a warm 500k-message scratch database, worse cold -- while producing the same rows for all
// mail delivered since June 2026 (and on production, for all mail). The catch-up keys on the
// owner instead; it reads messages by id range anyway.
func TestFTSv2BackfillBatchesStayIndexOnly(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_v2_backfill.sql"))
	require.NoError(t, err)

	for _, fn := range []string{"fts_v2_backfill_batch", "fts_v2_backfill_batch_nulldate"} {
		body := regexp.MustCompile(`(?s)CREATE OR REPLACE FUNCTION ` + fn + `\(.*?END \$\$;`).Find(script)
		require.NotNil(t, body, "function %s not found in the backfill script", fn)
		assert.NotContains(t, string(body), "mailboxes",
			"%s must not join mailboxes: it would make every message row a heap fetch", fn)
	}
}

// fts_v2_backfill_rest starts below the bound fts_v2_backfill_recent recorded, instead of
// re-reading every vector recent already copied. The batch function's p_hi is that bound.
func TestFTSv2BackfillBatchHonorsUpperBound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	t.Cleanup(db.Close) // registered first, so it runs after every other cleanup
	ctx := context.Background()

	script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_v2_backfill.sql"))
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, string(script))
	require.NoError(t, err)

	ts := time.Now().UnixNano()
	// A date window no other test uses: one body below the bound, one above it.
	below, above := fmt.Sprintf("bound_below_%d", ts), fmt.Sprintf("bound_above_%d", ts)
	for i, row := range []struct{ hash, sent string }{{below, "1800-06-01"}, {above, "1860-06-01"}} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
			VALUES ($1, to_tsvector('simple', 'report'), $2::timestamptz)`, row.hash, row.sent)
		require.NoError(t, err)
		_, err = db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
				                      internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3, $4, 'subject', now(), now(), 100, TRUE, 'domain', 'part',
				        $5, 'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted`,
			accountID, mailboxID, 9501+i, row.hash, "<"+row.hash+"@example.com>")
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		db.GetWritePool().Exec(c, `DELETE FROM messages_fts_v2 WHERE content_hash = ANY($1)`, []string{below, above})
		db.GetWritePool().Exec(c, `DELETE FROM messages_fts WHERE content_hash = ANY($1)`, []string{below, above})
	})

	var inserted, hashes int64
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `
		SELECT inserted, hashes FROM fts_v2_backfill_batch('1799-01-01', NULL, NULL, 100, '1850-01-01')`).Scan(&inserted, &hashes))
	assert.Equal(t, int64(1), hashes, "only the body at or below the bound is read")
	assert.Equal(t, int64(1), inserted)

	var got []string
	rows, err := db.GetWritePool().Query(ctx, `SELECT content_hash FROM messages_fts_v2 WHERE content_hash = ANY($1)`, []string{below, above})
	require.NoError(t, err)
	for rows.Next() {
		var h string
		require.NoError(t, rows.Scan(&h))
		got = append(got, h)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{below}, got)
}
