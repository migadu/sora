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

// Two worker instances (two nodes) each poll a different per-account row of the SAME body,
// both still carrying text -- the state a newsletter delivered to many accounts is in until
// the first tokenisation lands. Each holds FOR UPDATE on its polled row. Each then tokenises
// its own row, updates the shared messages_fts row, and fans the vector out to every sibling
// with a NULL vector -- which includes the row the OTHER worker holds.
//
// Before the fan-out, the shared-row update and the poison took their targets FOR UPDATE
// SKIP LOCKED, A waited for the row B held and B for the row A held: PostgreSQL aborted one
// of them with 40P01, and ProcessFTSBatch then POISONED that body (see
// TestFTSLockConflictNeverPoisonsGoodBody). Neither worker may wait on the other now.
func TestFTSWorkerFanOutDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, _ := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	hash := fmt.Sprintf("deadlock_%d", time.Now().UnixNano())
	a1, a2, a3 := accountID, accountID+3_000_000, accountID+3_000_001

	// The shared row that dual-write always creates, still queued.
	_, err := db.GetWritePool().Exec(ctx,
		`INSERT INTO messages_fts (content_hash, text_body, sent_date) VALUES ($1, 'shared body', now())`, hash)
	require.NoError(t, err)
	// Three accounts received the body before any tokenisation happened, so all three rows
	// carry text (ftsStageV2SQL omits text only when a sibling already has a vector).
	for _, acct := range []int64{a1, a2, a3} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date)
			VALUES ($1, $2, 'shared body', now())`, hash, acct)
		require.NoError(t, err)
	}

	// Each worker "polls" one row exactly as ProcessFTSBatch does.
	poll := func(acct int64) (context.Context, context.CancelFunc, pgx.Tx) {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		tx, err := db.GetWritePool().Begin(c)
		require.NoError(t, err)
		_, err = tx.Exec(c, `
			SELECT content_hash FROM messages_fts_v2
			WHERE content_hash = $1 AND account_id = $2 AND text_body_tsv IS NULL
			FOR UPDATE SKIP LOCKED`, hash, acct)
		require.NoError(t, err)
		return c, cancel, tx
	}
	ctxA, cancelA, txA := poll(a1)
	defer cancelA()
	defer txA.Rollback(context.Background())
	ctxB, cancelB, txB := poll(a2)
	defer cancelB()
	defer txB.Rollback(context.Background())

	type outcome struct {
		who string
		err error
	}
	results := make(chan outcome, 2)
	go func() {
		_, err := db.tokenizeAndFanOut(ctxA, txA, ftsQueueItem{Hash: hash, AccountID: a1, TextBody: "shared body"})
		results <- outcome{"A", err}
	}()
	go func() {
		_, err := db.tokenizeAndFanOut(ctxB, txB, ftsQueueItem{Hash: hash, AccountID: a2, TextBody: "shared body"})
		results <- outcome{"B", err}
	}()

	var deadlocks, successes int
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			var pgErr *pgconn.PgError
			switch {
			case r.err == nil:
				successes++
				t.Logf("worker %s completed", r.who)
			case errors.As(r.err, &pgErr) && pgErr.Code == "40P01":
				deadlocks++
				t.Logf("worker %s: deadlock detected by PostgreSQL: %s", r.who, pgErr.Message)
			default:
				t.Fatalf("worker %s failed with an unexpected error: %v", r.who, r.err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("workers still blocked after 20s: PostgreSQL did not resolve the cycle (deadlock_timeout?) or both are wedged")
		}
	}

	// "One deadlocked, one won" was the hazard; with SKIP LOCKED both complete.
	require.Equal(t, 0, deadlocks, "two workers fanning out the same hash must not wait on each other's polled rows")
	require.Equal(t, 2, successes)
}

// A worker that hits a lock conflict must never poison the body it was indexing.
//
// Worker B has polled one row of a body and is mid-batch. Worker A runs a real batch on
// another row of the same body. Before the fix, A's fan-out waited for B's row, hit its lock
// timeout, and ProcessFTSBatch treated that like an untokenisable payload: it wrote an empty
// vector into every row of the hash, v1 included, and nulled the text. The body was then
// unsearchable in every account, permanently. A lock conflict now either never happens (the
// fan-out skips rows another worker holds) or fails the batch, which is retried.
func TestFTSLockConflictNeverPoisonsGoodBody(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, _ := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	hash := fmt.Sprintf("lockpoison_%d", time.Now().UnixNano())
	a1, a2 := accountID, accountID+3_100_000

	_, err := db.GetWritePool().Exec(ctx,
		`INSERT INTO messages_fts (content_hash, text_body, sent_date) VALUES ($1, 'quarterly report attached', now())`, hash)
	require.NoError(t, err)
	// a1 is older, so a FIFO poll of one row takes it.
	for i, acct := range []int64{a1, a2} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date, created_at)
			VALUES ($1, $2, 'quarterly report attached', now(), now() - make_interval(secs => $3))`,
			hash, acct, 10-i)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE content_hash = $1`, hash)
		db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts WHERE content_hash = $1`, hash)
	})

	// Worker B holds a2, and lets go shortly after A's lock timeout would fire.
	txB, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = txB.Exec(ctx, `SELECT 1 FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2 FOR UPDATE`, hash, a2)
	require.NoError(t, err)
	released := make(chan struct{})
	go func() {
		time.Sleep(450 * time.Millisecond)
		txB.Rollback(context.Background())
		close(released)
	}()

	// Worker A: a real batch of one row, with a short lock timeout so any wait surfaces fast.
	txA, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = txA.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
	require.NoError(t, err)
	if _, err := db.ProcessFTSBatch(ctx, txA, 1); err != nil {
		t.Logf("worker A's batch failed (acceptable, it is retried): %v", err)
		require.NoError(t, txA.Rollback(ctx))
	} else {
		require.NoError(t, txA.Commit(ctx))
	}
	<-released

	// Later batches resolve whatever is left.
	for i := 0; i < 5; i++ {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		n, err := db.ProcessFTSBatch(ctx, tx, 100)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		if n == 0 {
			break
		}
	}

	rows, err := db.GetWritePool().Query(ctx, `
		SELECT 'v2:' || account_id, COALESCE(length(text_body_tsv), -1) FROM messages_fts_v2 WHERE content_hash = $1
		UNION ALL
		SELECT 'v1', COALESCE(length(text_body_tsv), -1) FROM messages_fts WHERE content_hash = $1`, hash)
	require.NoError(t, err)
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var who string
		var lexemes int
		require.NoError(t, rows.Scan(&who, &lexemes))
		seen++
		require.Greater(t, lexemes, 0, "%s: a good body was poisoned (empty vector) or never indexed (%d)", who, lexemes)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, 3, seen)
}

// Only a payload PostgreSQL cannot tokenise may be poisoned.
func TestIsFTSDataError(t *testing.T) {
	for code, want := range map[string]bool{
		"22P05": true,  // invalid byte sequence
		"22021": true,  // character not in repertoire
		"54000": true,  // string is too long for tsvector
		"40P01": false, // deadlock
		"55P03": false, // lock not available (lock_timeout)
		"57014": false, // query canceled (statement_timeout)
		"08006": false, // connection failure
	} {
		require.Equal(t, want, isFTSDataError(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: code})), code)
	}
	require.False(t, isFTSDataError(context.DeadlineExceeded))
}
