package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrphanSweepConcurrentDeliveryRace reproduces the race condition where a delivery
// transaction runs concurrently with DeleteMessagesFTSByKeyBatch.
//
// Sequence:
//  1. Hash H is an orphan in messages_fts_v2 (listed by GetUnusedFTSKeys).
//  2. Delivery transaction T1 inserts a new message row with hash H into messages.
//  3. T1 executes stageFTS: ON CONFLICT DO NOTHING no-ops because the orphan row still exists.
//  4. Before T1 commits, cleanup transaction T2 calls DeleteMessagesFTSByKeyBatch for H.
//  5. T2 checks NOT ftsKeyReferencedSQL: because T1 has not committed, T1's message is
//     invisible to T2 under READ COMMITTED.
//  6. T2 deletes H from messages_fts_v2 and commits.
//  7. T1 commits.
//
// Result on unpatched code: the live message committed by T1 has NO row in messages_fts_v2,
// making it permanently unsearchable by body.
func TestOrphanSweepConcurrentDeliveryRace(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()
	hash := fmt.Sprintf("race_%d", ts)

	// Pre-condition: orphaned row in messages_fts_v2
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date)
		VALUES ($1, $2, 'needle', to_tsvector('simple', 'needle'), now())
	`, hash, accountID)
	require.NoError(t, err)

	// Step 1: Delivery begins T1
	t1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer t1.Rollback(ctx)

	// Step 2: T1 inserts into messages
	_, err = t1.Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date,
			                      size, uploaded, s3_domain, s3_localpart, message_id, body_structure,
			                      recipients_json, created_modseq)
			VALUES ($1, $2, 4200, $3, now(), now(), 100, TRUE, 'domain', 'part', $4, 'body', '[]',
			        nextval('messages_modseq'))
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, hash, fmt.Sprintf("<msgid_%s@example.com>", hash))
	require.NoError(t, err)

	// Step 3: T1 stages FTS (as stageFTS does)
	stageFTS(ctx, t1, hash, accountID, "needle", time.Now())

	// Step 4: Before T1 commits, cleanup runs T2
	t2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer t2.Rollback(ctx)

	deleted, err := db.DeleteMessagesFTSByKeyBatch(ctx, t2, []FTSKey{{ContentHash: hash, AccountID: accountID}})
	require.NoError(t, err)
	require.NoError(t, t2.Commit(ctx))

	// Step 5: T1 commits
	require.NoError(t, t1.Commit(ctx))

	// Step 6: Verify messages_fts_v2 row still exists for the delivered message
	var count int
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2
	`, hash, accountID).Scan(&count)
	require.NoError(t, err)

	t.Logf("deleted by sweep: %d, rows in messages_fts_v2 after commit: %d", deleted, count)
	assert.Equal(t, 1, count, "messages_fts_v2 row MUST survive or be re-created for the delivered message")
}
