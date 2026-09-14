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
// A waits for a row B holds; B waits for a row (or the shared messages_fts row) A holds.
// PostgreSQL detects the cycle after deadlock_timeout and aborts one transaction: that
// worker's whole batch (up to 5000 rows) rolls back and it backs off 5 s before retrying.
// For a mass mailing this repeats across nodes until one wins.
//
// This test documents the hazard by reproducing it: exactly one of the two must fail with
// SQLSTATE 40P01. The fix is FOR UPDATE SKIP LOCKED on the fan-out's target selection, so a
// worker never waits on a row another worker holds; once that lands, invert this test.
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

	// The only two possible outcomes are "one deadlocked, one won" (the hazard) or "both
	// completed" (the SKIP LOCKED fix in place). Assert the current, unfixed behaviour so
	// the fix is forced to flip this assertion deliberately.
	require.Equal(t, 1, deadlocks,
		"expected exactly one worker to be aborted with 40P01: two workers fanning out the same "+
			"hash block on each other's polled rows. If both completed, the fan-out no longer waits "+
			"on locked rows and this test should assert successes == 2 instead.")
	require.Equal(t, 1, successes)
}
