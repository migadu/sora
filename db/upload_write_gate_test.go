package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The uploader writes a body without holding its S3 object lock across the transfer. It
// passes a gate first (PassS3WriteGate), and from then on relies on every deleter's orphan
// re-check refusing a body that still has a pending_uploads row; the finalize checks that
// row is still the one it leased (CompleteLeasedS3Upload). These tests pin each part
// against a live database.

// insertKeyedMessage inserts one INBOX message row stored under example.com/<localpart>.
// expungedAt of the zero time leaves the message live.
func insertKeyedMessage(t *testing.T, database *Database, accountID, mailboxID int64, uid int, hash, localpart string, uploaded bool, expungedAt time.Time) {
	t.Helper()
	_, err := database.GetWritePool().Exec(context.Background(), `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at, expunged_modseq)
			VALUES ($1, $2, $3, $4, now(), now(), 100, $5, 'example.com', $6, $7, 'body', '[]', $3, $8, CASE WHEN $8::timestamptz IS NULL THEN NULL ELSE nextval('messages_modseq') END)
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, uid, hash, uploaded, localpart, fmt.Sprintf("<%s-%d@example.com>", hash, uid), nullableTime(expungedAt))
	require.NoError(t, err)
}

func TestPassS3WriteGate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, _ := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	hash := fmt.Sprintf("gate_%d", time.Now().UnixNano())
	pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
	lockID := GetS3ObjectLockID(accountID, hash)

	gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash)
	require.NoError(t, err)
	assert.Equal(t, S3WriteOpen, gate, "nothing holds the body and its row stands")
	_, held := findLockHolder(t, database, lockID)
	assert.False(t, held, "the gate must not keep the lock: holding it across the transfer is what pinned a pooled connection per upload")

	// A deleter (or a restore, or a cross-account COPY) holds the object lock.
	holder, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = holder.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID)
	require.NoError(t, err)
	started := time.Now()
	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash)
	require.NoError(t, err)
	assert.Equal(t, S3WriteBusy, gate, "a write must not start while a delete of the same body may be under way")
	assert.Less(t, time.Since(started), 2*time.Second, "the gate never waits for a holder")
	require.NoError(t, holder.Rollback(ctx))

	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash)
	require.NoError(t, err)
	assert.Equal(t, S3WriteOpen, gate, "the gate opens once the holder is done")

	// The leased row goes (a purge), and a later delivery of the same body stages a new
	// one. The lease is still over: only the row it leased kept deleters away.
	_, err = database.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE id = $1`, pendingID)
	require.NoError(t, err)
	createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash)
	require.NoError(t, err)
	assert.Equal(t, S3WriteAbandoned, gate)
}

// The correctness argument for not holding the lock across the transfer, end to end on
// the cleaner's real deletion path. The body's only message was expunged long ago, so
// the cleaner lists it; its pending row is all that protects the body.
func TestS3WriteGateKeepsDeletersAwayFromAnUploadInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	const gracePeriod = time.Hour

	hash := fmt.Sprintf("gate_flight_%d", time.Now().UnixNano())
	insertKeyedMessage(t, database, accountID, mailboxID, 300, hash, "user", true, time.Now().Add(-24*time.Hour))
	candidates := []UserScopedObjectForCleanup{{AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: "user"}}

	// 1. A cleaner confirms the body an orphan, and a delivery of the same body stages an
	//    upload before the cleaner's delete has landed. The upload must not write now: its
	//    object would be deleted right after.
	var pendingID int64
	err := database.ExecuteWithLockedS3Orphans(ctx, candidates, gracePeriod, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		require.Len(t, orphans, 1, "with no pending row yet the body is an orphan")
		pendingID = createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
		gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash)
		require.NoError(t, err)
		assert.Equal(t, S3WriteBusy, gate, "an upload must not write while a delete confirmed before its row existed is under way")
		return nil
	})
	require.NoError(t, err)

	// 2. Once that delete is done the gate opens, and the upload writes holding nothing.
	gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)

	// 3. Every later deleter sees the pending row and leaves the body alone, although no
	//    lock protects the upload in flight.
	err = database.ExecuteWithLockedS3Orphans(ctx, candidates, gracePeriod, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		assert.Empty(t, orphans, "a body whose upload passed the gate must not be deleted while its pending row stands")
		return nil
	})
	require.NoError(t, err)

	// 4. The finalize takes the row with it.
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/user/" + hash}))
	require.NoError(t, tx.Commit(ctx))
	var left int
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE id = $1`, pendingID).Scan(&left))
	assert.Equal(t, 0, left)
}

func TestCompleteLeasedS3Upload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	uploaded := func(hash string) bool {
		t.Helper()
		var u bool
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT uploaded FROM messages WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&u))
		return u
	}
	pendingRows := func(hash string) int {
		t.Helper()
		var n int
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&n))
		return n
	}

	t.Run("finalizes while the leased row stands", func(t *testing.T) {
		hash := fmt.Sprintf("leased_ok_%d", suffix)
		insertKeyedMessage(t, database, accountID, mailboxID, 400, hash, "user", false, time.Time{})
		pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)

		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/user/" + hash}))
		require.NoError(t, tx.Commit(ctx))

		assert.True(t, uploaded(hash))
		assert.Equal(t, 0, pendingRows(hash))
	})

	t.Run("refuses once the leased row is gone, even when a new delivery re-created one", func(t *testing.T) {
		hash := fmt.Sprintf("leased_gone_%d", suffix)
		insertKeyedMessage(t, database, accountID, mailboxID, 401, hash, "user", false, time.Time{})
		leased := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
		_, err := database.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE id = $1`, leased)
		require.NoError(t, err)
		createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)

		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx) // a failed require must not leave the connection held, or Close waits forever
		err = database.CompleteLeasedS3Upload(ctx, tx, leased, hash, accountID, []string{"example.com/user/" + hash})
		require.ErrorIs(t, err, ErrPendingUploadGone)
		assert.True(t, errors.Is(err, consts.ErrDBNotFound), "an answer, not a database failure: it must not trip the write breaker")
		require.NoError(t, tx.Rollback(ctx))

		// Between the gate and now the body was unprotected for a while, and a deleter
		// may have removed what was written: the rows must not claim it, and the new
		// row must stay so the next lease writes the body again.
		assert.False(t, uploaded(hash), "rows must not be marked uploaded on the strength of a lease that lapsed")
		assert.Equal(t, 1, pendingRows(hash), "the re-created row belongs to a later upload")
	})
}

func TestUnreferencedS3Keys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	otherAccount := createTestAccount(t, database, fmt.Sprintf("unref_other_%d@example.com", time.Now().UnixNano()), "password")
	otherMailbox := createTestMailbox(t, database, otherAccount, "INBOX")

	hash := fmt.Sprintf("unref_%d", time.Now().UnixNano())
	insertKeyedMessage(t, database, accountID, mailboxID, 500, hash, "expunged", false, time.Now().Add(-48*time.Hour))
	insertKeyedMessage(t, database, otherAccount, otherMailbox, 1, hash, "other", true, time.Time{})

	keys := []string{
		"example.com/expunged/" + hash, // an expunged row still carries it: the cleaner will list it
		"example.com/other/" + hash,    // another account's row carries it
		"example.com/nobody/" + hash,   // nothing carries it
	}
	unreferenced, err := database.UnreferencedS3Keys(ctx, hash, keys)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/nobody/" + hash}, unreferenced)
}
