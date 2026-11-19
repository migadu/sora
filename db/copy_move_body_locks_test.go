package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// pauseTx is a transaction that stops before its first statement containing match until
// resume is closed, and closes reached when it gets there.
type pauseTx struct {
	pgx.Tx
	match   string
	reached chan struct{}
	resume  chan struct{}
}

func newPauseTx(tx pgx.Tx, match string) *pauseTx {
	return &pauseTx{Tx: tx, match: match, reached: make(chan struct{}), resume: make(chan struct{})}
}

func (p *pauseTx) pause(ctx context.Context, sql string) error {
	if !strings.Contains(sql, p.match) {
		return nil
	}
	select {
	case <-p.reached:
		return nil // only the first one
	default:
	}
	close(p.reached)
	select {
	case <-p.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pauseTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := p.pause(ctx, sql); err != nil {
		return pgconn.CommandTag{}, err
	}
	return p.Tx.Exec(ctx, sql, args...)
}

func (p *pauseTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := p.pause(ctx, sql); err != nil {
		return nil, err
	}
	return p.Tx.Query(ctx, sql, args...)
}

// waitUntilBlocked waits until the backend pid waits for a lock, or until done yields.
// It reports whether the backend was seen waiting.
func waitUntilBlocked(t *testing.T, ctx context.Context, db *Database, pid int, done <-chan error) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) FROM pg_stat_activity WHERE pid = $1`,
			pid).Scan(&waiting))
		if waiting {
			return true
		}
		if len(done) > 0 {
			return false
		}
		require.False(t, time.Now().After(deadline), "backend %d neither finished nor waited for a lock", pid)
		time.Sleep(5 * time.Millisecond)
	}
}

// liveRowsWithoutUpload counts the live rows of (accountID, hash) that are not uploaded and
// have no pending upload: rows nothing will ever upload.
func liveRowsWithoutUpload(t *testing.T, ctx context.Context, db *Database, accountID int64, hash string) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `
		SELECT count(*) FROM messages m
		WHERE m.account_id = $1 AND m.content_hash = $2 AND m.expunged_at IS NULL AND NOT m.uploaded
		  AND NOT EXISTS (SELECT 1 FROM pending_uploads pu WHERE pu.account_id = m.account_id AND pu.content_hash = m.content_hash)`,
		accountID, hash).Scan(&n))
	return n
}

// The failed-upload cleanup deletes the pending upload row and then expunges the
// unuploaded message rows; a COPY re-stages the pending upload row after it has read its
// sources. If the copy held an unuploaded source row, the two would wait for each other:
// the copy for the deleted pending row, the cleanup for the message row. The copy holds
// only uploaded source rows (CopyMessages), so the cleanup never waits for it.
func TestCopyOfUnuploadedSourceDoesNotDeadlockWithDeleteFailedUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("copy_failed_upload_%d", time.Now().UnixNano())
	const uid, maxAttempts = 9831, 5
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, false)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)
	// A parked upload: the one the admin tool deletes.
	_, err = db.GetWritePool().Exec(ctx, `INSERT INTO pending_uploads (account_id, instance_id, content_hash, size, attempts) VALUES ($1, 'dead-instance', $2, 100, $3)`, accountID, hash, maxAttempts)
	require.NoError(t, err)

	// The copy has inserted its row and is about to re-stage the pending upload.
	copyTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(context.Background())
	paused := newPauseTx(copyTx, "INSERT INTO pending_uploads")
	copyDone := make(chan error, 1)
	go func() {
		uids := []imap.UID{uid}
		_, _, err := db.CopyMessages(ctx, paused, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		copyDone <- err
	}()
	select {
	case <-paused.reached:
	case err := <-copyDone:
		t.Fatalf("CopyMessages finished without re-staging the pending upload: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// The cleanup runs to its end while the copy is open.
	deleteTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer deleteTx.Rollback(context.Background())
	_, err = deleteTx.Exec(ctx, `SET LOCAL lock_timeout = '2s'`)
	require.NoError(t, err)
	_, err = db.DeleteFailedUpload(ctx, deleteTx, hash, accountID, maxAttempts)
	require.NoError(t, err, "DeleteFailedUpload waited for an open copy of the message it deletes")
	require.NoError(t, deleteTx.Commit(ctx))

	close(paused.resume)
	require.NoError(t, <-copyDone)
	require.NoError(t, copyTx.Commit(ctx))

	var sources int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid).Scan(&sources))
	assert.Zero(t, sources, "DeleteFailedUpload left the source message")
	// The copy the cleanup could not see has a pending upload of its own.
	assert.Zero(t, liveRowsWithoutUpload(t, ctx, db, accountID, hash), "the copy is not uploaded and has no pending upload")
}

// A source that is not uploaded when the copy holds its rows is not held, so its upload
// can finish before the copy inserts. Its copy must then be marked uploaded under a lock
// on the source, not taken as uploaded from an unlocked read, and not left to a pending
// upload on the copying node, which has no file for it (markCopiesOfLateUploadedSources).
func TestCopyOfSourceUploadedAfterItWasReadIsMarkedUnderLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("copy_upload_finishes_%d", time.Now().UnixNano())
	const uid = 9861
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, false)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)

	copyTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(context.Background())
	paused := newPauseTx(copyTx, "WITH src_data")
	type copyResult struct {
		uids map[imap.UID]imap.UID
		err  error
	}
	copyDone := make(chan copyResult, 1)
	go func() {
		uids := []imap.UID{uid}
		copied, _, err := db.CopyMessages(ctx, paused, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		copyDone <- copyResult{copied, err}
	}()
	select {
	case <-paused.reached:
	case res := <-copyDone:
		t.Fatalf("CopyMessages finished without inserting: %v", res.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// The upload finishes: the source is not held yet, so this does not wait for the copy.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '2s'`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `UPDATE messages SET uploaded = TRUE WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err, "marking the source uploaded waited for the open copy")
	require.NoError(t, tx.Commit(ctx))

	close(paused.resume)
	res := <-copyDone
	require.NoError(t, res.err)

	// Before the commit: the copy claims the object, so its source is held live.
	probe, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = probe.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
	require.NoError(t, err)
	_, err = probe.Exec(ctx, `UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, probe.Rollback(ctx))
	require.True(t, lockNotAvailable(err), "the source of a copy marked uploaded could be expunged while the copy was open: %v", err)
	assert.Zero(t, reapableBodies(t, ctx, db, accountID, hash), "the cleaner found the body retirable while a copy of it was open")

	require.NoError(t, copyTx.Commit(ctx))

	var uploaded bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE mailbox_id = $1 AND uid = $2`, archiveID, res.uids[uid]).Scan(&uploaded))
	assert.True(t, uploaded, "the copy of a source uploaded before the insert was not marked uploaded")
	var pending int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&pending))
	assert.Zero(t, pending, "the copy queued an upload for a body that is in S3")
}

// A source being expunged while the copy marks late-uploaded sources is waited for and
// then left out: the copy of a source that is gone by its commit must not claim the
// object through it.
func TestCopyDoesNotMarkCopyOfSourceExpungedMeanwhile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	hash := fmt.Sprintf("copy_source_expunged_%d", time.Now().UnixNano())
	const uid = 9871
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, false)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)

	copyTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(context.Background())
	var copyPID int
	require.NoError(t, copyTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&copyPID))
	paused := newPauseTx(copyTx, "WITH late AS")
	type copyResult struct {
		uids map[imap.UID]imap.UID
		err  error
	}
	copyDone := make(chan copyResult, 1)
	go func() {
		uids := []imap.UID{uid}
		copied, _, err := db.CopyMessages(ctx, paused, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		copyDone <- copyResult{copied, err}
	}()
	select {
	case <-paused.reached:
	case res := <-copyDone:
		t.Fatalf("CopyMessages finished without marking late sources: %v", res.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// The upload finishes, and an expunge of the source is still open when the copy marks
	// its late sources.
	other, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer other.Rollback(context.Background())
	_, err = other.Exec(ctx, `UPDATE messages SET uploaded = TRUE WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)
	require.NoError(t, other.Commit(ctx))
	expunge, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer expunge.Rollback(context.Background())
	_, err = expunge.Exec(ctx, `UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE mailbox_id = $1 AND uid = $2`, inboxID, uid)
	require.NoError(t, err)

	close(paused.resume)
	require.True(t, waitUntilBlocked(t, ctx, db, copyPID, make(chan error)), "the copy did not wait for the expunge of its source")
	require.NoError(t, expunge.Commit(ctx))

	res := <-copyDone
	require.NoError(t, res.err)
	require.NoError(t, copyTx.Commit(ctx))

	var uploaded bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE mailbox_id = $1 AND uid = $2`, archiveID, res.uids[uid]).Scan(&uploaded))
	assert.False(t, uploaded, "the copy claims the object through a source expunged before the copy committed")
	assert.Zero(t, liveRowsWithoutUpload(t, ctx, db, accountID, hash), "the copy is not uploaded and has no pending upload")
}

// The missing-object repair marks the rows of a key not uploaded under the exclusive body
// lock. A COPY or MOVE within one account does not hold that lock, so one can be open
// while the repair runs: the repair's UPDATE waits for the source row but cannot see the
// row the command then commits, and a moved source no longer matches at all. The repair
// must not leave that row marked uploaded for an object that is not there.
func TestMissingObjectRepairCoversOpenSameAccountCopyAndMove(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			db, _, accountID, inboxID := setupCleanerTestDatabase(t)
			defer db.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
			hash := fmt.Sprintf("repair_open_%s_%d", strings.ToLower(command), time.Now().UnixNano())
			const uid = 9841
			insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, hash, true)

			commandTx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer commandTx.Rollback(context.Background())
			uids := []imap.UID{uid}
			wantChanged := int64(1) // MOVE: the moved row; its source is expunged by then
			if command == "COPY" {
				_, _, err = db.CopyMessages(ctx, commandTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
				wantChanged = 2 // the source and its copy
			} else {
				_, err = db.MoveMessages(ctx, commandTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
			}
			require.NoError(t, err)
			var commandPID int
			require.NoError(t, commandTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&commandPID))

			var changed int64
			repairDone := make(chan error, 1)
			go func() {
				var err error
				changed, err = db.MarkMessagesAsNotUploadedIfAbsent(ctx, ContentObject{S3Domain: "domain", S3Localpart: "part", ContentHash: hash},
					func(context.Context) (bool, error) { return false, nil })
				repairDone <- err
			}()

			// The repair must have reached the source row the open command holds.
			deadline := time.Now().Add(10 * time.Second)
			for {
				var blocking bool
				require.NoError(t, db.GetWritePool().QueryRow(ctx,
					`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`,
					commandPID).Scan(&blocking))
				if blocking {
					break
				}
				select {
				case err := <-repairDone:
					t.Fatalf("the repair finished without waiting for the open %s: %v", command, err)
				default:
				}
				require.False(t, time.Now().After(deadline), "the repair never waited for the open %s", command)
				time.Sleep(5 * time.Millisecond)
			}

			require.NoError(t, commandTx.Commit(ctx))
			require.NoError(t, <-repairDone)

			var stillUploaded int
			require.NoError(t, db.GetWritePool().QueryRow(ctx,
				`SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL AND uploaded`,
				accountID, hash).Scan(&stillUploaded))
			assert.Zero(t, stillUploaded, "a live row is still marked uploaded for the absent object")
			assert.Equal(t, wantChanged, changed)
		})
	}
}

// A COPY reads its source mailbox; it must not hold that mailbox up. Flag changes and
// expunges of other messages there go on while a copy out of it is open, and a copy does
// not wait for one of them: only the messages being copied are held (the uploaded ones,
// see CopyMessages).
func TestCopyDoesNotHoldUpItsSourceMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
	base := time.Now().UnixNano()
	const copied, other, later = 9851, 9852, 9853
	for _, uid := range []int64{copied, other, later} {
		insertRestageFixture(t, ctx, db.GetWritePool(), accountID, inboxID, uid, fmt.Sprintf("copy_source_mailbox_%d_%d", base, uid), true)
	}

	t.Run("STORE and EXPUNGE during an open copy", func(t *testing.T) {
		copyTx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer copyTx.Rollback(ctx)
		uids := []imap.UID{copied}
		_, _, err = db.CopyMessages(ctx, copyTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		require.NoError(t, err)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
		require.NoError(t, err)
		_, _, err = db.AddMessageFlags(ctx, tx, other, inboxID, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err, "a STORE in the source mailbox waited for an open copy out of it")
		_, err = db.ExpungeMessageUIDs(ctx, tx, inboxID, other)
		require.NoError(t, err, "an EXPUNGE in the source mailbox waited for an open copy out of it")
	})

	t.Run("copy during an open STORE", func(t *testing.T) {
		// What STORE and EXPUNGE hold for as long as they run.
		holder, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer holder.Rollback(ctx)
		require.NoError(t, lockMailboxStats(ctx, holder, inboxID))

		copyTx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer copyTx.Rollback(ctx)
		_, err = copyTx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
		require.NoError(t, err)
		uids := []imap.UID{later}
		_, _, err = db.CopyMessages(ctx, copyTx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
		require.NoError(t, err, "a copy waited for a STORE in its source mailbox")
	})
}
