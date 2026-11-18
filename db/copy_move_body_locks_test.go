package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s3BodyLocksHeld counts the single-key (bigint) advisory locks this backend holds: the
// S3 body locks. The FTS and rekey locks are two-key locks (objsubid 2).
func s3BodyLocksHeld(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var n int
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND objsubid = 1
	`).Scan(&n))
	return n
}

// A same-account MOVE or COPY must not hold one advisory lock per distinct body. Such a
// command is neither limited nor batched, each advisory lock is an entry in PostgreSQL's
// server-wide lock table until commit, and a full table fails every session with "out of
// shared memory": moving one large folder would do it. Its bodies are protected by its
// source rows instead (lockS3SourceClaims); the tests below pin that.
func TestSameAccountMoveCopyTakeNoS3BodyLocks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	base := time.Now().UnixNano()

	const n = 50
	uids := make([]imap.UID, 0, n)
	for i := 0; i < n; i++ {
		uid := int64(9701 + i)
		insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid,
			fmt.Sprintf("body_locks_%d_%d", base, i), true)
		uids = append(uids, imap.UID(uid))
	}

	t.Run("MOVE", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		moveUIDs := append([]imap.UID(nil), uids...)
		moved, err := db.MoveMessages(ctx, tx, &moveUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		require.NoError(t, err)
		require.Len(t, moved, n)
		assert.Equal(t, 0, s3BodyLocksHeld(t, ctx, tx), "a same-account MOVE holds one S3 body lock per body")
	})

	t.Run("COPY", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		copyUIDs := append([]imap.UID(nil), uids...)
		copied, _, err := db.CopyMessages(ctx, tx, &copyUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		require.NoError(t, err)
		require.Len(t, copied, n)
		assert.Equal(t, 0, s3BodyLocksHeld(t, ctx, tx), "a same-account COPY holds one S3 body lock per body")
	})
}

// reapableBodies runs the cleaner's body step on (accountID, domain/part/hash) with no
// grace period and reports how many bodies it found retirable. It deletes nothing: the
// storage callback refuses every object.
func reapableBodies(t *testing.T, ctx context.Context, db *Database, accountID int64, hash string) int {
	t.Helper()
	objects := []UserScopedObjectForCleanup{{AccountID: accountID, ContentHash: hash, S3Domain: "domain", S3Localpart: "part"}}
	reapable := 0
	_, err := db.ExecuteWithS3BodyCleanup(ctx, objects, 0, func(_ context.Context, orphans []UserScopedObjectForCleanup) (S3BodyCleanupResult, error) {
		reapable = len(orphans)
		return S3BodyCleanupResult{Rejected: orphans}, nil
	})
	require.NoError(t, err)
	return reapable
}

// lockNotAvailable reports whether err is PostgreSQL's lock_timeout expiring on a lock wait.
func lockNotAvailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

// A same-account COPY takes no body lock, so the source row is all that keeps the cleaner
// off the body until the copy commits: with no grace period, a source expunged after the
// copy read it would leave the account without a live row of the body, the cleaner would
// delete the object, and the copy would then commit a row marked uploaded for it. The copy
// therefore holds its source rows FOR SHARE: no expunge or delete of one commits first.
func TestSameAccountCopyHoldsSourceRowsUntilCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("copy_holds_source_%d", time.Now().UnixNano())
	const uid = 9801
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, true)

	copyTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(ctx)
	uids := []imap.UID{uid}
	copied, _, err := db.CopyMessages(ctx, copyTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	require.NoError(t, err)
	require.Len(t, copied, 1)

	// While the copy is open, neither an expunge nor a delete of its source gets through.
	for name, stmt := range map[string]string{
		"an expunge": `UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE mailbox_id = $1 AND uid = $2`,
		"a delete":   `DELETE FROM messages WHERE mailbox_id = $1 AND uid = $2`,
	} {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, stmt, inboxID, uid)
		require.NoError(t, tx.Rollback(ctx))
		require.Truef(t, lockNotAvailable(err), "%s of a source row got through while its copy was open: %v", name, err)
	}
	assert.Zero(t, reapableBodies(t, ctx, db, accountID, hash), "the cleaner found the body retirable while a copy of it was open")

	require.NoError(t, copyTx.Commit(ctx))

	// Once the copy has committed, the source may go: the copy is the live row now.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET expunged_at = now() - interval '1 hour', expunged_modseq = nextval('messages_modseq') WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)
	assert.Zero(t, reapableBodies(t, ctx, db, accountID, hash), "the cleaner found the body retirable although its copy is live")
}

// A same-account MOVE takes no body lock either. Its source rows are locked FOR UPDATE,
// then expunged and replaced in one transaction, so the account has a live row of the body
// at every moment a deleter can look: the source until the commit, the moved row after it.
func TestSameAccountMoveKeepsBodyReferencedThroughout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("move_keeps_body_%d", time.Now().UnixNano())
	const uid = 9811
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, true)

	moveTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer moveTx.Rollback(ctx)
	uids := []imap.UID{uid}
	moved, err := db.MoveMessages(ctx, moveTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	require.NoError(t, err)
	require.Len(t, moved, 1)

	assert.Zero(t, reapableBodies(t, ctx, db, accountID, hash), "the cleaner found the body retirable while a move of it was open")
	require.NoError(t, moveTx.Commit(ctx))
	// The source is expunged now, and with no grace period it alone would be retirable.
	assert.Zero(t, reapableBodies(t, ctx, db, accountID, hash), "the cleaner found the body retirable although the moved row is live")

	var live int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL`, accountID, hash).Scan(&live))
	assert.Equal(t, 1, live)
}

// CopyMessages must lock the destination's mailbox row before its source rows, the order
// MoveMessages takes them in. The other way round, a COPY holding source rows and waiting
// for the destination's mailbox row would deadlock with a MOVE into that mailbox, which
// holds the mailbox row and waits for the same source rows.
func TestCopyLocksDestinationMailboxBeforeSourceRows(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("copy_lock_order_%d", time.Now().UnixNano())
	const uid = 9821
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, true)

	// Stand in for a MOVE into Archive that has locked the mailbox row.
	holder, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer holder.Rollback(ctx)
	_, err = holder.Exec(ctx, `SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE`, archiveID)
	require.NoError(t, err)

	copyTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(ctx)
	var copyPID int
	require.NoError(t, copyTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&copyPID))
	done := make(chan error, 1)
	go func() {
		uids := []imap.UID{uid}
		_, _, err := db.CopyMessages(ctx, copyTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		done <- err
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) FROM pg_stat_activity WHERE pid = $1`,
			copyPID).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("CopyMessages finished without waiting for the destination's mailbox row: %v", err)
		default:
		}
		require.False(t, time.Now().After(deadline), "CopyMessages never waited for the destination's mailbox row")
		time.Sleep(5 * time.Millisecond)
	}

	// The copy waits for the mailbox row. It must not hold its source row yet: the MOVE
	// it waits for can still lock it.
	probe, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = probe.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
	require.NoError(t, err)
	_, err = probe.Exec(ctx, `SELECT 1 FROM messages WHERE mailbox_id = $1 AND uid = $2 FOR UPDATE`, inboxID, uid)
	require.NoError(t, probe.Rollback(ctx))
	require.NoError(t, err, "CopyMessages locked a source row before the destination's mailbox row")

	require.NoError(t, holder.Rollback(ctx))
	require.NoError(t, <-done)
}

// A COPY and a MOVE of the same messages into the same mailbox, started together, must
// both finish: each takes the mailbox rows first and the source rows second, so neither
// waits for the other in a cycle. Whichever locks the source rows second finds them moved
// (the copy copies nothing) or copied (the move moves them).
func TestConcurrentSameAccountCopyAndMoveDoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	base := time.Now().UnixNano()

	const rounds, perRound = 15, 10
	for round := 0; round < rounds; round++ {
		uids := make([]imap.UID, 0, perRound)
		for i := 0; i < perRound; i++ {
			uid := int64(20000 + round*perRound + i)
			insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid,
				fmt.Sprintf("copy_move_race_%d_%d_%d", base, round, i), true)
			uids = append(uids, imap.UID(uid))
		}

		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			tx, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback(ctx)
			copyUIDs := append([]imap.UID(nil), uids...)
			if _, _, err := db.CopyMessages(ctx, tx, &copyUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil); err != nil {
				errs <- fmt.Errorf("copy: %w", err)
				return
			}
			errs <- tx.Commit(ctx)
		}()
		go func() {
			<-start
			tx, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback(ctx)
			moveUIDs := append([]imap.UID(nil), uids...)
			if _, err := db.MoveMessages(ctx, tx, &moveUIDs, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil); err != nil {
				errs <- fmt.Errorf("move: %w", err)
				return
			}
			errs <- tx.Commit(ctx)
		}()
		close(start)
		require.NoError(t, <-errs, "round %d", round)
		require.NoError(t, <-errs, "round %d", round)
	}

	// Every message was moved exactly once, whatever the copy caught.
	var inInbox int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL AND uid >= 20000`, inboxID).Scan(&inInbox))
	assert.Zero(t, inInbox)
}
