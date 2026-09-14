package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cross-account COPY or MOVE lands a message under an account that has no FTS row for
// that body, because messages_fts_v2 is keyed by (content_hash, account_id). Without a
// re-stage the message is silently unsearchable by body in its new home -- the same class
// of bug that restagePendingUploads exists to prevent on the S3 side, and just as invisible:
// nothing errors, the search simply returns fewer results.
func TestRestageFTSCreatesDestinationPair(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	indexedHash := fmt.Sprintf("restage_indexed_%d", ts)
	neverIndexedHash := fmt.Sprintf("restage_bare_%d", ts)
	sourceAccountID := accountID + 2_000_000 // stands in for the account the copy came from

	// The body is indexed, but only for the SOURCE account.
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'restageneedle'), now())
	`, indexedHash, sourceAccountID)
	require.NoError(t, err)

	insert := func(uid int, hash string) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
				                      internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3, $4, 'Copied', now(), now(), 100, TRUE, 'domain', 'part', $5,
				        'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, uid, hash, fmt.Sprintf("<%s-%d@example.com>", hash, uid))
		require.NoError(t, err)
	}
	insert(9301, indexedHash)
	insert(9302, neverIndexedHash)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.restageFTS(ctx, tx, mailboxID, []int64{9301, 9302}))
	require.NoError(t, tx.Commit(ctx))

	pairExists := func(hash string) bool {
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
			hash, accountID).Scan(&n))
		return n == 1
	}

	assert.True(t, pairExists(indexedHash),
		"a message copied into this account must get its own FTS row, or it is unsearchable by body here")

	// The staged row carries no text and no vector: the worker fills it by copying the
	// sibling's finished vector rather than tokenising the body a second time.
	var hasText, hasVector bool
	require.NoError(t, db.GetReadPool().QueryRow(ctx, `
		SELECT text_body IS NOT NULL, text_body_tsv IS NOT NULL
		FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2
	`, indexedHash, accountID).Scan(&hasText, &hasVector))
	assert.False(t, hasText, "re-staging must not duplicate the body text; the vector is copied from a sibling")
	assert.False(t, hasVector, "the worker, not the copy, assigns the vector")

	assert.False(t, pairExists(neverIndexedHash),
		"a body that was never indexed at all (over 64KB, empty, or pruned) must not get a row: "+
			"it would sit queued with nothing to copy and end up poisoned")

	// The worker resolves the staged row by copying, with no tokenisation.
	txW, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ProcessFTSBatch(ctx, txW, 500)
	require.NoError(t, err)
	require.NoError(t, txW.Commit(ctx))

	require.NoError(t, db.GetReadPool().QueryRow(ctx, `
		SELECT text_body_tsv IS NOT NULL FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2
	`, indexedHash, accountID).Scan(&hasVector))
	assert.True(t, hasVector, "the FTS worker must fan the existing vector out to the copied account's row")
}

// Delivery must write BOTH FTS tables. The v2 row is what search reads; the v1 row is the
// rollback fallback that makes this release reversible without touching data that cannot be
// regenerated.
//
// This is a guard against a whole class of silent breakage: stageFTS swallows its own
// errors by design (an unindexed message is still a delivered message), so a malformed
// statement costs searchability with nothing but a log line to show for it. That is exactly
// what happened once already -- "INSERT ... SELECT $1, $2" cannot infer parameter types from
// the target columns, so the v2 statement failed to prepare and every delivery quietly
// staged nothing.
func TestDeliveryStagesBothFTSTables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	contentHash := fmt.Sprintf("dualwrite_%d", time.Now().UnixNano())

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		ContentHash:   contentHash,
		MessageID:     fmt.Sprintf("<%s@example.com>", contentHash),
		S3Domain:      "domain",
		S3Localpart:   "part",
		Size:          100,
		Subject:       "Dual write",
		PlaintextBody: "dualwriteneedle in the body",
		InternalDate:  time.Now(),
		SentDate:      time.Now(),
	}, PendingUpload{
		InstanceID:  "test-instance",
		ContentHash: contentHash,
		Size:        100,
		AccountID:   accountID,
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	var v1, v2 int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM messages_fts WHERE content_hash = $1`, contentHash).Scan(&v1))
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&v2))

	assert.Equal(t, 1, v1, "the legacy hash-keyed row is the rollback fallback and must still be written")
	assert.Equal(t, 1, v2,
		"NO per-account FTS row was staged, so this message will never be searchable by body. "+
			"stageFTS logs and swallows this failure, so check the warning it emitted")
}
