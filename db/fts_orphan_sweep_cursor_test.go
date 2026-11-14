package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGetUnusedFTSKeysResumesFromCursor: each GetUnusedFTSKeys call is bounded (scan
// windows, a wall-clock cap, the orphan limit), so the cleaner hands every call the cursor
// the previous one returned. When every call started from the lowest content_hash, rows
// past what one call could scan were never examined and their orphans never removed (#284).
func TestGetUnusedFTSKeysResumesFromCursor(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	t.Cleanup(db.Close) // registered first, so it runs after every other cleanup
	ctx := context.Background()

	// Real content hashes are lower-case hex, so this prefix sorts after all of them and
	// the test's rows are the last ones in the table.
	prefix := fmt.Sprintf("zzzz284_%019d_", time.Now().UnixNano())
	first := FTSKey{ContentHash: prefix + "a", AccountID: accountID}
	live := FTSKey{ContentHash: prefix + "b", AccountID: accountID}
	second := FTSKey{ContentHash: prefix + "c", AccountID: accountID}

	for _, k := range []FTSKey{first, live, second} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
			VALUES ($1, $2, to_tsvector('simple', 'needle'), now())`, k.ContentHash, k.AccountID)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		db.GetWritePool().Exec(context.Background(),
			`DELETE FROM messages_fts_v2 WHERE content_hash LIKE $1`, prefix+"%")
	})
	_, err := db.GetWritePool().Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date,
			                      size, uploaded, s3_domain, s3_localpart, message_id, body_structure,
			                      recipients_json, created_modseq)
			VALUES ($1, $2, 2840, $3, now(), now(), 100, TRUE, 'domain', 'part', $4, 'body', '[]',
			        nextval('messages_modseq'))
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, live.ContentHash, fmt.Sprintf("<%s@example.com>", live.ContentHash))
	require.NoError(t, err)

	// The orphan limit ends the call before the first orphan it cannot return, not at the
	// end of the scan window it was reading, or the second orphan (same window) would be
	// stepped over.
	keys, next, err := db.GetUnusedFTSKeys(ctx, FTSKey{ContentHash: prefix}, 1)
	require.NoError(t, err)
	require.Equal(t, []FTSKey{first}, keys)
	require.Equal(t, live, next, "the cursor must stop before the orphan the call did not return")

	// The next call resumes after the cursor; the referenced row is never listed.
	keys, next, err = db.GetUnusedFTSKeys(ctx, next, 1)
	require.NoError(t, err)
	require.Equal(t, []FTSKey{second}, keys)

	// Past the last row the cursor wraps around, so the next call starts over.
	require.Equal(t, FTSKey{}, next, "at the end of the table the cursor must wrap to the start")
	keys, next, err = db.GetUnusedFTSKeys(ctx, second, 1)
	require.NoError(t, err)
	require.Empty(t, keys)
	require.Equal(t, FTSKey{}, next)

	// A canceled scan must not advance over candidates it could not return. Hold
	// the real table lock so cancellation happens in PostgreSQL's query wait.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(ctx, "LOCK TABLE messages_fts_v2 IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	canceled, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	keys, next, err = db.GetUnusedFTSKeys(canceled, first, 1)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, keys)
	require.Equal(t, first, next)
}
