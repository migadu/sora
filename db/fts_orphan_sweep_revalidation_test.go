package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteMessagesFTSByHashBatchRevalidatesReferences reproduces the interleaving
// the FTS orphan sweep is exposed to.
//
// Phase 2b of the cleanup worker builds its list with GetUnusedFTSKeys on the READ
// pool, a scan that is allowed to run for up to 30 seconds, and then deletes that list
// in a separate transaction. Delivery inserts into messages_fts with
// ON CONFLICT (content_hash) DO NOTHING (db/append.go), so a message delivered in that
// window whose hash matches a still-present row silently relies on that row.
//
//	scan says H is orphaned -> a message with hash H is delivered (FTS insert no-ops)
//	-> the sweep deletes H -> a live message is permanently unsearchable, no error anywhere
//
// The test drives exactly that order: both hashes are unreferenced when the list is
// built, one of them gains a message before the delete runs.
func TestDeleteMessagesFTSByHashBatchRevalidatesReferences(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	orphanHash := fmt.Sprintf("fts_orphan_%d", ts)
	revivedHash := fmt.Sprintf("fts_revived_%d", ts)

	for _, hash := range []string{orphanHash, revivedHash} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv)
			VALUES ($1, $2, 'needle', to_tsvector('simple', 'needle'))
		`, hash, accountID)
		require.NoError(t, err)
	}

	// The sweep's candidate list: at this instant neither pair is referenced by any
	// message row, which is precisely what GetUnusedFTSKeys reports.
	sweptKeys := []FTSKey{{ContentHash: orphanHash, AccountID: accountID}, {ContentHash: revivedHash, AccountID: accountID}}
	for _, hash := range []string{orphanHash, revivedHash} {
		var referenced int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE content_hash = $1`, hash).Scan(&referenced))
		require.Equal(t, 0, referenced, "precondition: %s must be unreferenced when the sweep lists it", hash)
	}

	// Between the scan and the delete, a message with revivedHash is delivered. Its
	// own FTS insert is a no-op against the surviving row (ON CONFLICT DO NOTHING),
	// exactly as db.InsertMessage does it.
	deliverTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = deliverTx.Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date,
			                      size, uploaded, s3_domain, s3_localpart, message_id, body_structure,
			                      recipients_json, created_modseq)
			VALUES ($1, $2, 4100, $3, now(), now(), 100, TRUE, 'domain', 'part', $4, 'body', '[]',
			        nextval('messages_modseq'))
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, revivedHash, fmt.Sprintf("<msgid_%s@example.com>", revivedHash))
	require.NoError(t, err)
	_, err = deliverTx.Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date)
		VALUES ($1, $2, 'needle', now())
		ON CONFLICT (content_hash, account_id) DO NOTHING
	`, revivedHash, accountID)
	require.NoError(t, err)
	require.NoError(t, deliverTx.Commit(ctx))

	// The sweep now deletes the list it built earlier.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	deleted, err := db.DeleteMessagesFTSByKeyBatch(ctx, tx, sweptKeys)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	t.Logf("DeleteMessagesFTSByKeyBatch reported %d row(s) deleted", deleted)

	exists := func(hash string) bool {
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
			hash, accountID).Scan(&n))
		return n == 1
	}

	// CONTRAST (expected to hold): a hash that is still unreferenced is swept.
	assert.False(t, exists(orphanHash),
		"a genuinely unreferenced messages_fts_v2 row must still be deleted — this is the sweep's purpose")

	// THE ASSERTION: the hash that gained a message between scan and delete must survive.
	assert.True(t, exists(revivedHash),
		"SILENT SEARCHABILITY LOSS: the messages_fts_v2 row for a hash that gained a live message "+
			"between the GetUnusedFTSKeys scan and the delete was removed. The DELETE is a bare "+
			"'WHERE content_hash = ANY($1)' with no re-check that each hash is still unreferenced, "+
			"so the delivered message keeps a messages_fts_v2-less content_hash forever and is never "+
			"searchable again — with no error on any path.")

	assert.EqualValues(t, 1, deleted,
		"only the still-unreferenced hash should have been deleted")

	t.Logf("test account: %s", testEmail)
}
