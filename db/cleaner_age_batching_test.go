package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AGE-1: ExpungeOldMessages (db/cleaner.go:106-141) is an unbatched UPDATE.
//
// Both tests in this file seed messages whose created_at is ~10 years in the
// past and then run the cleaner with olderThan = 5 years, so they only ever
// touch rows this test created (every other row in the shared test database is
// at most a few days old).
// ---------------------------------------------------------------------------

const (
	ageTestMessageAge = 10 * 365 * 24 * time.Hour // created_at = now() - 10y
	ageTestOlderThan  = 5 * 365 * 24 * time.Hour  // cleaner threshold = 5y
)

// seedAgeTestAccount creates a dedicated account plus n mailboxes and returns
// the account id and the mailbox ids.
func seedAgeTestAccount(t *testing.T, database *Database, tag string, mailboxes int) (int64, []int64) {
	t.Helper()
	ctx := context.Background()

	email := fmt.Sprintf("age1_%s_%d@example.com", tag, time.Now().UnixNano())

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := database.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)

	var mailboxIDs []int64
	for i := 0; i < mailboxes; i++ {
		name := fmt.Sprintf("AGE1-%s-%d", tag, i)
		tx2, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, database.CreateMailbox(ctx, tx2, accountID, name, nil))
		require.NoError(t, tx2.Commit(ctx))

		mb, err := database.GetMailboxByName(ctx, accountID, name)
		require.NoError(t, err)
		mailboxIDs = append(mailboxIDs, mb.ID)
	}

	// Keep the shared test database clean: remove everything this test seeded.
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = database.GetWritePool().Exec(cctx, `DELETE FROM messages WHERE account_id = $1`, accountID)
		_, _ = database.GetWritePool().Exec(cctx,
			`DELETE FROM messages_fts WHERE content_hash LIKE 'age1_' || $1 || '_%'`, tag)
		_, _ = database.GetWritePool().Exec(cctx, `DELETE FROM mailboxes WHERE account_id = $1`, accountID)
		_, _ = database.GetWritePool().Exec(cctx, `DELETE FROM credentials WHERE account_id = $1`, accountID)
		_, _ = database.GetWritePool().Exec(cctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	})

	return accountID, mailboxIDs
}

// seedAgedMessages inserts perMailbox over-age messages into every mailbox.
func seedAgedMessages(t *testing.T, database *Database, tag string, accountID int64, mailboxIDs []int64, perMailbox int) {
	t.Helper()
	seedAgedMessagesOfAge(t, database, tag, accountID, mailboxIDs, perMailbox, ageTestMessageAge)
}

// seedAgedMessagesOfAge is seedAgedMessages with an explicit age. Tests that must know
// exactly which rows a candidate SELECT picks seed rows older than every other test's,
// so ORDER BY created_at puts them first in the shared test database.
func seedAgedMessagesOfAge(t *testing.T, database *Database, tag string, accountID int64, mailboxIDs []int64, perMailbox int, age time.Duration) {
	t.Helper()
	ctx := context.Background()

	for i, mbID := range mailboxIDs {
		_, err := database.GetWritePool().Exec(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, s3_domain, s3_localpart, content_hash,
			                      uploaded, recipients_json, message_id, sent_date, internal_date,
			                      size, body_structure, created_modseq, created_at)
			SELECT $1, $2, g, 'age1-domain', 'age1-part',
			       'age1_' || $3 || '_' || $4 || '_' || g,
			       TRUE, '[]'::jsonb, 'age1-' || $3 || '-' || $4 || '-' || g,
			       now(), now(), 100, 'b'::bytea, nextval('messages_modseq'),
			       now() - $5::interval
			FROM generate_series(1, $6) g
		`, accountID, mbID, tag, fmt.Sprintf("%d", i), age, perMailbox)
		require.NoError(t, err, "seeding aged messages")
	}

	var n int
	require.NoError(t, database.GetReadPool().QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL`, accountID).Scan(&n))
	require.Equal(t, perMailbox*len(mailboxIDs), n, "seed precondition")
}

func countExpunged(t *testing.T, database *Database, accountID int64) int {
	t.Helper()
	var n int
	require.NoError(t, database.GetReadPool().QueryRow(context.Background(),
		`SELECT count(*) FROM messages WHERE account_id = $1 AND expunged_at IS NOT NULL`, accountID).Scan(&n))
	return n
}

// countExpungedAll counts expunged rows across the whole table. The cleaner is
// global, so forward progress is measured as a delta on this number.
func countExpungedAll(t *testing.T, database *Database) int {
	t.Helper()
	var n int
	require.NoError(t, database.GetReadPool().QueryRow(context.Background(),
		`SELECT count(*) FROM messages WHERE expunged_at IS NOT NULL`).Scan(&n))
	return n
}

// TestAGE1_ExpungeOldMessages_IsUnbatched proves the structural half of the
// finding: PruneOldMessageVectors caps every invocation at 1000 rows, while
// ExpungeOldMessages has no LIMIT at all — it rewrites every over-age row and
// locks every affected mailbox in one statement, one transaction.
//
// Both paths are given the SAME workload (2500 eligible rows) so the asymmetry
// is the only variable.
func TestAGE1_ExpungeOldMessages_IsUnbatched(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	// Registered first so it runs LAST (t.Cleanup is LIFO): the seed cleanup
	// below still needs a live pool.
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	tag := fmt.Sprintf("cap%d", time.Now().UnixNano())

	const mailboxCount = 5
	const perMailbox = 500
	const total = mailboxCount * perMailbox // 2500 eligible rows

	accountID, mailboxIDs := seedAgeTestAccount(t, database, tag, mailboxCount)
	seedAgedMessages(t, database, tag, accountID, mailboxIDs, perMailbox)

	// --- Control: the sibling cleaner path, same workload, is capped ---------
	for i := 0; i < total; i++ {
		_, err := database.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
			VALUES ('age1_' || $1 || '_fts_' || $2, to_tsvector('english', 'x'), now() - $3::interval)
			ON CONFLICT (content_hash) DO NOTHING
		`, tag, fmt.Sprintf("%d", i), ageTestMessageAge)
		require.NoError(t, err)
	}

	txPrune, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	pruned, err := database.PruneOldMessageVectors(ctx, txPrune, ageTestOlderThan)
	require.NoError(t, err)
	require.NoError(t, txPrune.Commit(ctx))
	require.Equal(t, int64(1000), pruned,
		"control: PruneOldMessageVectors must cap each call at 1000 rows (db/cleaner.go:367)")
	t.Logf("PruneOldMessageVectors: %d eligible rows -> %d rows in one call (capped)", total, pruned)

	// --- Subject: ExpungeOldMessages on the same-sized workload -------------
	txExpunge, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txExpunge.Rollback(context.Background())

	expunged, err := database.ExpungeOldMessages(ctx, txExpunge, ageTestOlderThan)
	require.NoError(t, err)

	// While the expunge transaction is still open, probe every seeded mailbox
	// from a second connection: FOR UPDATE NOWAIT fails with 55P03 on any row
	// this transaction holds. This measures the lock breadth of a single call.
	locked := 0
	for _, mbID := range mailboxIDs {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, perr := database.GetWritePool().Exec(probeCtx,
			`SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE NOWAIT`, mbID)
		cancel()
		var pgErr *pgconn.PgError
		if errors.As(perr, &pgErr) && pgErr.Code == "55P03" {
			locked++
		}
	}

	require.NoError(t, txExpunge.Commit(ctx))

	t.Logf("ExpungeOldMessages: %d eligible rows -> %d rows in ONE statement (%d of them this account's); "+
		"%d/%d mailboxes locked simultaneously",
		total, expunged, countExpunged(t, database, accountID), locked, mailboxCount)

	// Evidence, not the verdict: a fix that narrows the lock scope should be free
	// to change this number, so only assert the probe itself worked.
	require.Positive(t, locked, "sanity: the NOWAIT probe must detect at least one held mailbox lock")
	require.Positive(t, expunged, "sanity: the call must have expunged something")

	// THE DEFECT: no per-call bound. The same file already defines
	// BATCH_PURGE_SIZE = 1000 and PruneOldMessageVectors honours a 1000-row cap;
	// ExpungeOldMessages honours none, so its transaction size (and lock breadth)
	// scales with the backlog instead of with a batch constant.
	require.LessOrEqualf(t, expunged, int64(BATCH_PURGE_SIZE),
		"ExpungeOldMessages is unbatched: it expunged %d rows in a single UPDATE with no LIMIT "+
			"(and locked %d mailboxes in the same transaction), while PruneOldMessageVectors capped "+
			"an identical %d-row workload at %d rows per call. A backlog of N over-age messages is "+
			"one transaction of size N.",
		expunged, locked, total, pruned)
}

// TestAGE1_ExpungeOldMessages_PoisonPillUnderWriteDeadline proves the operational
// half of the finding: because the whole backlog is one statement in one
// transaction, exceeding the write deadline rolls the entire thing back. The
// cleaner therefore makes ZERO forward progress and every subsequent tick
// repeats the identical doomed statement.
//
// The deadline is derived from a measured run on this very machine (25% of the
// time the cleaner needs to clear the whole backlog, however many calls that
// takes), so the test is neither tuned to particular hardware nor to a
// particular implementation: a batched cleaner commits each bounded batch well
// inside the same deadline and makes progress.
func TestAGE1_ExpungeOldMessages_PoisonPillUnderWriteDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	// Registered first so it runs LAST (t.Cleanup is LIFO): the seed cleanup
	// below still needs a live pool.
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	tag := fmt.Sprintf("pill%d", time.Now().UnixNano())

	const mailboxCount = 4
	const perMailbox = 10000
	const total = mailboxCount * perMailbox // 40k over-age messages

	accountID, mailboxIDs := seedAgeTestAccount(t, database, tag, mailboxCount)
	seedAgedMessages(t, database, tag, accountID, mailboxIDs, perMailbox)

	// --- Calibrate: how long does clearing the whole backlog take, with no
	// deadline in the way? Implementation-neutral: call the cleaner repeatedly
	// until it reports nothing left, then throw the work away. The unbatched
	// implementation needs one call; a batched one needs many small ones.
	txCal, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	start := time.Now()
	var swept int64
	var calls int
	for i := 0; i < 500; i++ {
		n, err := database.ExpungeOldMessages(ctx, txCal, ageTestOlderThan)
		require.NoError(t, err)
		calls++
		swept += n
		if n == 0 {
			break
		}
	}
	clearBacklog := time.Since(start)
	require.NoError(t, txCal.Rollback(ctx)) // discard: the run below must start clean
	require.GreaterOrEqual(t, swept, int64(total), "calibration must clear the whole backlog")
	require.Equal(t, 0, countExpunged(t, database, accountID), "calibration run must leave no trace")
	require.Greater(t, clearBacklog, 300*time.Millisecond,
		"workload too small to exercise a write deadline; increase perMailbox")

	// Give each cleaner tick a quarter of the time the whole backlog needs. That
	// is the production situation: config [database] write_timeout versus a
	// backlog too big to clear inside one of them. An implementation that
	// commits in bounded batches still makes progress under this deadline.
	writeTimeout := clearBacklog / 4
	t.Logf("clearing the %d-row backlog took %v over %d call(s); simulating write_timeout=%v",
		total, clearBacklog, calls, writeTimeout)

	// --- Run the cleaner tick three times, exactly as the resilient wrapper
	// does it: BeginTx on the caller ctx, run the op under a write-timeout ctx,
	// roll back on error (pkg/resilient/admin_operations.go:455-553). ---------
	const ticks = 3
	expungedBefore := countExpungedAll(t, database)
	for attempt := 1; attempt <= ticks; attempt++ {
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		opCtx, cancel := context.WithTimeout(ctx, writeTimeout)
		rows, opErr := database.ExpungeOldMessages(opCtx, tx, ageTestOlderThan)
		cancel()

		if opErr != nil {
			_ = tx.Rollback(context.Background())
			t.Logf("tick %d: ExpungeOldMessages failed after the write deadline: %v", attempt, opErr)
			require.True(t,
				errors.Is(opErr, context.DeadlineExceeded) || isQueryCanceled(opErr),
				"expected a deadline/cancellation failure, got: %v", opErr)
			continue
		}
		require.NoError(t, tx.Commit(ctx))
		t.Logf("tick %d: committed %d rows", attempt, rows)
	}

	// Progress is measured as a delta over the whole table, so it counts any row
	// the cleaner managed to expunge — not just this account's.
	progress := countExpungedAll(t, database) - expungedBefore
	remaining := total - countExpunged(t, database, accountID)

	// THE DEFECT: after three full cleaner ticks — each of which burned the
	// entire write deadline doing real work — not a single message is expunged.
	// The backlog is a poison pill: every tick repeats the same all-or-nothing
	// statement and rolls it back, forever.
	require.Greaterf(t, progress, 0,
		"ExpungeOldMessages made ZERO progress across %d ticks under a %v write deadline: "+
			"%d over-age messages remain unexpunged. The unbatched UPDATE (db/cleaner.go:130-134) "+
			"is all-or-nothing, so a backlog that cannot finish inside one write deadline can never "+
			"be worked down — each tick rolls back everything it did.",
		ticks, writeTimeout, remaining)
}

// ---------------------------------------------------------------------------
// Regressions introduced by the AGE-1 batching fix itself. The batched cleaner
// no longer selects its victims inside the statement that holds the mailbox
// locks, which opens a window between the candidate SELECT and the UPDATE. Both
// tests below force a client operation into exactly that window by parking the
// cleaner on a mailbox row lock the test holds.
// ---------------------------------------------------------------------------

// ageTestAncientAge is older than every other row this package seeds, so
// `ORDER BY created_at LIMIT BATCH_PURGE_SIZE` selects precisely these rows.
const ageTestAncientAge = 20 * 365 * 24 * time.Hour

// blockOnMailbox opens a transaction holding mailboxID's row lock and returns it
// together with its backend pid, so waitForBlockedOn can tell when another backend
// has parked behind it.
func blockOnMailbox(t *testing.T, database *Database, mailboxID int64) (pgx.Tx, int) {
	t.Helper()
	ctx := context.Background()

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	var pid int
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(ctx, `SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE`, mailboxID)
	require.NoError(t, err, "holding the mailbox row lock")

	return tx, pid
}

// waitForBlockedOn blocks until some backend is waiting on a lock held by pid, which
// is how the test observes that ExpungeOldMessages has taken its candidate snapshot
// and is parked on the mailbox lock.
func waitForBlockedOn(t *testing.T, database *Database, pid int) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		var blocked int
		require.NoError(t, database.GetReadPool().QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity a
			WHERE a.wait_event_type = 'Lock' AND $1 = ANY(pg_blocking_pids(a.pid))
		`, pid).Scan(&blocked))
		if blocked > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the expunge transaction to park on the mailbox lock")
}

// mailboxRowLocked reports whether some other transaction currently holds the
// mailboxes row for mailboxID (FOR UPDATE NOWAIT fails with 55P03 if it does).
func mailboxRowLocked(t *testing.T, database *Database, mailboxID int64) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := database.GetWritePool().Exec(ctx, `SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE NOWAIT`, mailboxID)
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr) && pgErr.Code == "55P03", "unexpected probe error: %v", err)
	return true
}

// runExpungeBatch starts ExpungeOldMessages on tx in the background and returns a
// channel carrying its result, so the test can mutate the batch's candidates while
// the call is parked on the mailbox lock.
func runExpungeBatch(database *Database, tx pgx.Tx) <-chan struct {
	claimed int64
	err     error
} {
	done := make(chan struct {
		claimed int64
		err     error
	}, 1)
	go func() {
		claimed, err := database.ExpungeOldMessages(context.Background(), tx, ageTestOlderThan)
		done <- struct {
			claimed int64
			err     error
		}{claimed, err}
	}()
	return done
}

// TestAGE1_ExpungeOldMessages_ShortBatchIsNotADrainedBacklog covers the drain signal.
// The cleaner drains the backlog by calling this function until a batch comes back
// short (server/cleaner/worker.go: `count < db.BATCH_PURGE_SIZE` ends the ~30s budget).
// If the returned number is the UPDATE's row count, a single client EXPUNGE landing in
// the window between the candidate SELECT and the UPDATE shrinks a full batch to 999 and
// the drain stops after one batch — a 15k backlog then clears at 1000 per wake interval
// instead of ~15000.
func TestAGE1_ExpungeOldMessages_ShortBatchIsNotADrainedBacklog(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	tag := fmt.Sprintf("drain%d", time.Now().UnixNano())

	accountID, mailboxIDs := seedAgeTestAccount(t, database, tag, 1)
	mailboxID := mailboxIDs[0]
	seedAgedMessagesOfAge(t, database, tag, accountID, mailboxIDs, BATCH_PURGE_SIZE, ageTestAncientAge)

	var victimID int64
	require.NoError(t, database.GetReadPool().QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id LIMIT 1`, mailboxID).Scan(&victimID))

	blocker, blockerPID := blockOnMailbox(t, database, mailboxID)

	expungeTx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer expungeTx.Rollback(context.Background())

	done := runExpungeBatch(database, expungeTx)
	waitForBlockedOn(t, database, blockerPID)

	// A client expunges one of the batch's candidates out from under it.
	_, err = blocker.Exec(ctx, `
		UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		WHERE id = $1
	`, victimID)
	require.NoError(t, err)
	require.NoError(t, blocker.Commit(ctx))

	res := <-done
	require.NoError(t, res.err)
	require.NoError(t, expungeTx.Commit(ctx))

	require.Equalf(t, int64(BATCH_PURGE_SIZE), res.claimed,
		"ExpungeOldMessages claimed a full batch of %d over-age candidates but reported %d, because one "+
			"client EXPUNGE landed between the candidate SELECT and the UPDATE. The cleaner's drain loop "+
			"breaks on count < BATCH_PURGE_SIZE, so that single racing client abandons the remaining drain "+
			"budget and the backlog clears at one batch per wake interval.",
		BATCH_PURGE_SIZE, res.claimed)

	require.Equal(t, BATCH_PURGE_SIZE, countExpunged(t, database, accountID),
		"every candidate must end up expunged, whoever expunged it")
}

// TestAGE1_ExpungeOldMessages_NeverExpungesOutsideItsLockedMailboxes covers the lock
// ordering. The batch locks the mailboxes it saw in the candidate SELECT; if a candidate
// is relocated into a different mailbox before the UPDATE, expunging it anyway runs the
// mailbox_stats trigger against a mailbox the transaction does not hold — unserialised
// against concurrent STORE/EXPUNGE/MOVE there, which is the unseen_count drift class the
// mailbox-row FOR UPDATE exists to close.
func TestAGE1_ExpungeOldMessages_NeverExpungesOutsideItsLockedMailboxes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	tag := fmt.Sprintf("reloc%d", time.Now().UnixNano())

	accountID, mailboxIDs := seedAgeTestAccount(t, database, tag, 2)
	sourceID, destID := mailboxIDs[0], mailboxIDs[1]
	seedAgedMessagesOfAge(t, database, tag, accountID, mailboxIDs[:1], 3, ageTestAncientAge)

	var victimID int64
	require.NoError(t, database.GetReadPool().QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id LIMIT 1`, sourceID).Scan(&victimID))

	blocker, blockerPID := blockOnMailbox(t, database, sourceID)

	expungeTx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer expungeTx.Rollback(context.Background())

	done := runExpungeBatch(database, expungeTx)
	waitForBlockedOn(t, database, blockerPID)

	// The victim moves into a mailbox the batch never saw, and therefore never locked.
	_, err = blocker.Exec(ctx,
		`UPDATE messages SET mailbox_id = $2, uid = 1 WHERE id = $1`, victimID, destID)
	require.NoError(t, err)
	require.NoError(t, blocker.Commit(ctx))

	res := <-done
	require.NoError(t, res.err)

	// Both observations are taken while the expunge transaction is still open, so its
	// locks are still held.
	destLocked := mailboxRowLocked(t, database, destID)
	var victimExpunged bool
	require.NoError(t, expungeTx.QueryRow(ctx,
		`SELECT expunged_at IS NOT NULL FROM messages WHERE id = $1`, victimID).Scan(&victimExpunged))
	require.NoError(t, expungeTx.Commit(ctx))

	if victimExpunged {
		require.Truef(t, destLocked,
			"ExpungeOldMessages expunged message %d after it was relocated into mailbox %d, but its "+
				"transaction holds no lock on that mailbox: the mailbox_stats trigger ran against %d "+
				"unserialised against concurrent STORE/EXPUNGE/MOVE on it. Candidates are selected with "+
				"no row locks, so the mailbox set locked before the UPDATE can be stale.",
			victimID, destID, destID)
	}

	// Deferring the relocated victim must not drop it: the next batch sees its new
	// mailbox and locks that one.
	tx2, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(context.Background())
	_, err = database.ExpungeOldMessages(ctx, tx2, ageTestOlderThan)
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))

	require.Equal(t, 3, countExpunged(t, database, accountID),
		"a candidate deferred by a concurrent relocation must be expunged by a later batch")
}

// isQueryCanceled reports whether err is PostgreSQL 57014 (query canceled),
// which is what the server returns when pgx cancels a statement whose context
// deadline expired.
func isQueryCanceled(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "57014"
	}
	return errors.Is(err, pgx.ErrTxClosed)
}
