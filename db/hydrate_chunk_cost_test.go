package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// A chunked whole-mailbox fetch must cost one pass over the mailbox, not one pass per
// chunk. Sequence hydration is the part at risk: a sequence number is a rank, so a
// hydration that re-derives it from the start of the mailbox scans a window that grows
// with every chunk, turning a full fetch into O(N^2/chunk).
//
// The assertion is scale-based rather than a fixed row budget: the same fetch is measured
// against a mailbox of N and of 2N messages, and hydration must cost roughly twice as
// much. Quadratic work quadruples, which no amount of per-row constant overhead can
// disguise, and no tuning of the chunk size can hide.
const (
	hydrateCostMessages  = 3000
	hydrateCostChunkSize = 100
	// Linear growth doubles the work when the mailbox doubles; quadratic growth
	// quadruples it. Anything at or under this threshold cannot be quadratic.
	hydrateCostLinearGrowthLimit = 2.3
)

func TestChunkedFetchSequenceHydrationIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("hydratecost_%d@example.com", ts), "password")

	small := seedDenseMailbox(t, database, accountID, fmt.Sprintf("CostSmall_%d", ts), hydrateCostMessages)
	large := seedDenseMailbox(t, database, accountID, fmt.Sprintf("CostLarge_%d", ts), 2*hydrateCostMessages)

	// Bring the analyzer up to date so the plans below are the ones production would get.
	// Without stats on message_state the planner picks a nested loop for the flag join whose
	// cost swamps the signal this test is after.
	_, err := database.GetWritePool().Exec(ctx, "ANALYZE messages, message_state")
	require.NoError(t, err)

	smallCost := measureFetchCost(t, ctx, database, small, hydrateCostMessages)
	largeCost := measureFetchCost(t, ctx, database, large, 2*hydrateCostMessages)
	require.NotZero(t, smallCost.hydrationRows, "harness broken: no hydration statement was measured")

	growth := float64(largeCost.hydrationRows) / float64(smallCost.hydrationRows)
	t.Logf("hydration rows examined: N=%d -> %d over %d stmts, 2N=%d -> %d over %d stmts",
		hydrateCostMessages, smallCost.hydrationRows, smallCost.hydrationStmts,
		2*hydrateCostMessages, largeCost.hydrationRows, largeCost.hydrationStmts)
	t.Logf("whole-fetch rows examined: N=%d -> %d, 2N=%d -> %d",
		hydrateCostMessages, smallCost.totalRows, 2*hydrateCostMessages, largeCost.totalRows)
	t.Logf("hydration growth when the mailbox doubled: %.2fx (linear is ~2.0x, quadratic is ~4.0x)", growth)

	require.LessOrEqualf(t, growth, hydrateCostLinearGrowthLimit,
		"SEQUENCE HYDRATION SCALES QUADRATICALLY: hydrating a whole-mailbox fetch grew %.2fx when the "+
			"mailbox doubled, want at most %.2fx. Per-chunk hydration is scanning a window proportional "+
			"to total mailbox size, so a full fetch costs O(N^2/chunk) instead of O(N).",
		growth, hydrateCostLinearGrowthLimit)
}

// fetchCost is the row-count accounting for one whole-mailbox fetch.
type fetchCost struct {
	hydrationRows  int64
	hydrationStmts int
	totalRows      int64
}

// measureFetchCost runs a whole-mailbox UID FETCH and reports how many rows the statements
// it issued actually produced, summed over all plan nodes. Every statement is captured
// through a pgx tracer and replayed under EXPLAIN (ANALYZE), so the figure is PostgreSQL's
// own accounting rather than an estimate or a stopwatch.
//
// Statements are split into the ones that fetch message payload and the rest, which is the
// sequence hydration this test is about. The split is by what a statement selects, not by
// matching any particular hydration SQL, so rewriting hydration cannot hide it from the
// measurement.
func measureFetchCost(t *testing.T, ctx context.Context, database *Database, mailboxID int64, wantMessages int) fetchCost {
	t.Helper()

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{
		WritePool:      database.GetWritePool(),
		ReadPool:       tracedPool,
		fetchChunkSize: hydrateCostChunkSize,
	}

	var uidSet imap.UIDSet
	uidSet.AddRange(1, 0) // 1:*

	seen := 0
	err := traced.StreamMessagesByNumSet(ctx, mailboxID, uidSet, func(chunk []Message) error {
		for i := range chunk {
			// Guard the measurement: a fetch that quietly skipped hydration would look
			// cheap. Every message must carry its correct sequence number.
			seen++
			require.Equalf(t, uint32(seen), chunk[i].Seq,
				"message uid %d must be hydrated with sequence number %d", chunk[i].UID, seen)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, wantMessages, seen, "fetch must return the whole mailbox")

	captured := tracer.captured()
	require.NotEmpty(t, captured, "harness broken: no statement was captured for the fetch")

	// Replay on the untraced pool so the EXPLAIN runs are not themselves captured.
	var cost fetchCost
	for _, q := range captured {
		var stmtRows int64
		for _, rows := range explainRowsPerNode(t, ctx, database.GetReadPool(), q) {
			stmtRows += int64(rows)
		}
		cost.totalRows += stmtRows
		// The payload query is the one that reads the message rows themselves.
		if !strings.Contains(q.SQL, "m.content_hash") {
			cost.hydrationRows += stmtRows
			cost.hydrationStmts++
		}
	}
	return cost
}

// seedDenseMailbox creates a mailbox holding count active messages with dense UIDs
// 1..count and returns its ID. Messages are inserted in bulk: the sizes needed to tell
// linear from quadratic growth apart are too large for row-at-a-time inserts.
func seedDenseMailbox(t *testing.T, database *Database, accountID int64, name string, count int) int64 {
	t.Helper()
	ctx := context.Background()

	mailboxID := createTestMailbox(t, database, accountID, name)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO messages (
			account_id, mailbox_id, mailbox_path, uid, content_hash, s3_domain, s3_localpart,
			size, internal_date, uploaded, created_modseq, subject_sort,
			from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort,
			recipients_json, message_id, sent_date, subject, body_structure, in_reply_to
		)
		SELECT
			$1::bigint, $2::bigint, $4, seq,
			'hash' || $2::bigint || '_' || seq, 'test.com', 'cost' || $2::bigint || '_' || seq,
			1024, now(), true, seq, '', '', '', '', '', '', '[]'::jsonb,
			'<msg' || $2::bigint || '_' || seq || '@cost>', now(), 'Subject ' || seq, '', ''
		FROM generate_series(1, $3::int) AS seq
	`, accountID, mailboxID, count, name)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, updated_modseq, flags_changed_at)
		SELECT id, $1::bigint, 0, '[]'::jsonb, 1, now()
		FROM messages WHERE mailbox_id = $1::bigint
	`, mailboxID)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `UPDATE mailboxes SET highest_uid = $2 WHERE id = $1`, mailboxID, count)
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))
	return mailboxID
}
