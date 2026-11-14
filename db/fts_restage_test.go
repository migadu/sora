package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
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

// Delivery must write messages_fts_v2. The v2 row is what search reads.
//
// This is a guard against a whole class of silent breakage: stageFTS swallows its own
// errors by design (an unindexed message is still a delivered message), so a malformed
// statement costs searchability with nothing but a log line to show for it.
func TestDeliveryStagesFTSV2(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	contentHash := fmt.Sprintf("ftsv2_%d", time.Now().UnixNano())

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
		Subject:       "FTS v2 write",
		PlaintextBody: "ftsv2needle in the body",
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

	var v2 int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&v2))

	assert.Equal(t, 1, v2,
		"NO per-account FTS row was staged, so this message will never be searchable by body. "+
			"stageFTS logs and swallows this failure, so check the warning it emitted")
}

// insertRestageFixture inserts an uploaded message row directly, and when indexed is set, the
// owning account's FTS row for its body with a finished vector.
func insertRestageFixture(t *testing.T, ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, accountID, mailboxID, uid int64, hash string, indexed bool) {
	t.Helper()
	_, err := q.Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
			                      internal_date, size, uploaded, s3_domain, s3_localpart,
			                      message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, 'Restage', now(), now(), 100, TRUE, 'domain', 'part', $5,
			        'body', '[]', nextval('messages_modseq'))
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, uid, hash, fmt.Sprintf("<%s-%d@example.com>", hash, uid))
	require.NoError(t, err)
	if !indexed {
		return
	}
	_, err = q.Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'restageneedle'), now())
		ON CONFLICT DO NOTHING
	`, hash, accountID)
	require.NoError(t, err)
}

// createRestageMailbox creates a mailbox for the account and returns its id.
func createRestageMailbox(t *testing.T, ctx context.Context, db *Database, accountID int64, name string) int64 {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
	require.NoError(t, tx.Commit(ctx))
	mbox, err := db.GetMailboxByName(ctx, accountID, name)
	require.NoError(t, err)
	return mbox.ID
}

// ftsLocksHeld counts the FTS sweep-coordination advisory locks held by tx's backend.
func ftsLocksHeld(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var n int
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND classid::bigint = $1
	`, int64(uint32(consts.SoraFTSOrphanSweepLockClassID))).Scan(&n))
	return n
}

// A COPY or MOVE can land a message on an account whose FTS row for that body is an orphan:
// the account held the body before, that message has since been purged, and the sweep has
// not run yet. The row is present, so there is nothing to insert, yet the sweep is about to
// delete it and cannot see the uncommitted message that now needs it. restageFTS must hold
// the sweep off with its shared lock even though it inserts nothing; deciding "the row is
// already there" without the lock is the race 30ece60 closed for delivery.
func TestRestageFTSHoldsOffTheOrphanSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	hash := fmt.Sprintf("restage_orphan_%d", time.Now().UnixNano())

	// The orphan: an FTS row for this account that no message references.
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ($1, $2, to_tsvector('simple', 'needle'), now())
	`, hash, accountID)
	require.NoError(t, err)

	// T1 lands the copied message and re-stages, but has not committed.
	t1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer t1.Rollback(ctx)
	insertRestageFixture(t, ctx, t1, accountID, mailboxID, 9501, hash, false)
	require.NoError(t, db.restageFTS(ctx, t1, mailboxID, []int64{9501}))

	// T2, the orphan sweep, runs before T1 commits.
	t2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer t2.Rollback(ctx)
	deleted, err := db.DeleteMessagesFTSByKeyBatch(ctx, t2, []FTSKey{{ContentHash: hash, AccountID: accountID}})
	require.NoError(t, err)
	require.NoError(t, t2.Commit(ctx))
	require.NoError(t, t1.Commit(ctx))

	var count int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
		hash, accountID).Scan(&count))
	t.Logf("deleted by sweep: %d, rows left for the copied message: %d", deleted, count)
	assert.Equal(t, 1, count,
		"the sweep deleted the FTS row of a message that was being copied in: it is now unsearchable by body")
}

// A same-account MOVE or COPY must take no FTS advisory locks. The shared lock is one entry
// per distinct body in PostgreSQL's server-wide lock table (about 25,600 entries in
// production), held until commit, and MOVE is not batched: moving a large folder within one
// account would otherwise fill the table and fail unrelated transactions with
// "out of shared memory".
func TestSameAccountMoveCopyTakeNoFTSLocks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	base := time.Now().UnixNano()

	const n = 20
	uids := make([]imap.UID, 0, n)
	for i := 0; i < n; i++ {
		uid := int64(9601 + i)
		insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid,
			fmt.Sprintf("restage_locks_%d_%d", base, i), true)
		uids = append(uids, imap.UID(uid))
	}

	t.Run("MOVE", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		moveUIDs := append([]imap.UID(nil), uids...)
		moved, err := db.MoveMessages(ctx, tx, &moveUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance")
		require.NoError(t, err)
		require.Len(t, moved, n)
		assert.Equal(t, 0, ftsLocksHeld(t, ctx, tx), "a same-account MOVE took one FTS lock per body")
	})

	t.Run("COPY", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		copyUIDs := append([]imap.UID(nil), uids...)
		copied, _, err := db.CopyMessages(ctx, tx, &copyUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil)
		require.NoError(t, err)
		require.Len(t, copied, n)
		assert.Equal(t, 0, ftsLocksHeld(t, ctx, tx), "a same-account COPY took one FTS lock per body")
	})
}

// A cross-account COPY or MOVE, through the real entry points, must still give the
// destination account its own FTS row for the body. This guards the callers' decision to
// skip the re-stage: getting "same account" wrong would make every moved or copied message
// unsearchable by body for its new owner.
func TestCrossAccountMoveCopyStageDestinationFTSRow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, ownerA, inboxA := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	emailB := fmt.Sprintf("restage_b_%d@example.com", time.Now().UnixNano())
	txB, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CreateAccount(ctx, txB, CreateAccountRequest{Email: emailB, Password: "password123", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, txB.Commit(ctx))
	ownerB, err := db.GetAccountIDByAddress(ctx, emailB)
	require.NoError(t, err)
	sharedB := createRestageMailbox(t, ctx, db, ownerB, "Shared")

	base := time.Now().UnixNano()
	copyHash := fmt.Sprintf("restage_xcopy_%d", base)
	moveHash := fmt.Sprintf("restage_xmove_%d", base)
	insertRestageFixture(t, ctx, db.GetWritePool(), ownerA, inboxA, 9701, copyHash, true)
	insertRestageFixture(t, ctx, db.GetWritePool(), ownerA, inboxA, 9702, moveHash, true)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	copyUIDs := []imap.UID{9701}
	_, _, err = db.CopyMessages(ctx, tx, &copyUIDs, inboxA, sharedB, ownerB, "example.net", "b", "test-instance", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	moveUIDs := []imap.UID{9702}
	_, err = db.MoveMessages(ctx, tx, &moveUIDs, inboxA, sharedB, ownerB, "example.net", "b", "test-instance")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	for name, hash := range map[string]string{"COPY": copyHash, "MOVE": moveHash} {
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`,
			hash, ownerB).Scan(&n))
		assert.Equal(t, 1, n, "cross-account %s left the message unsearchable by body for its new owner", name)
	}
}
