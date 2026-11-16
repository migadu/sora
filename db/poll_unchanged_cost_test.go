package db

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedQuery is one statement PollMailbox issued, with the arguments it bound.
type capturedQuery struct {
	SQL  string
	Args []any
}

// queryCapturingTracer records every statement executed on the pool it is attached to.
type queryCapturingTracer struct {
	mu      sync.Mutex
	queries []capturedQuery
}

func (t *queryCapturingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.queries = append(t.queries, capturedQuery{SQL: data.SQL, Args: data.Args})
	return ctx
}

func (t *queryCapturingTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (t *queryCapturingTracer) captured() []capturedQuery {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]capturedQuery(nil), t.queries...)
}

// newCapturingPool clones the pool configuration of an existing database and attaches a
// tracer, so the statements a db method issues can be inspected verbatim.
func newCapturingPool(t *testing.T, ctx context.Context, src *pgxpool.Pool, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()

	cfg := src.Config().Copy()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	return pool
}

// planNode is the subset of an EXPLAIN (ANALYZE, FORMAT JSON) node these tests read.
type planNode struct {
	NodeType    string     `json:"Node Type"`
	IndexName   string     `json:"Index Name"`
	IndexCond   string     `json:"Index Cond"`
	ActualRows  float64    `json:"Actual Rows"`
	ActualLoops float64    `json:"Actual Loops"`
	Plans       []planNode `json:"Plans"`
}

// walk visits n and every node below it, each with the node it is a child of (nil for n).
func (n planNode) walk(parent *planNode, visit func(n planNode, parent *planNode)) {
	visit(n, parent)
	for _, child := range n.Plans {
		child.walk(&n, visit)
	}
}

// andedWholeIndexScan reports whether n is a Bitmap Index Scan that its parent, a
// BitmapAnd, ANDs in without an index condition. Such a scan reads every entry of its
// partial index (idx_messages_account_hash_expunged: every expunged message in the
// table) only to apply the index's predicate to a bitmap its siblings already confine to
// the statement's own rows, so what it reads is the rest of the table. PostgreSQL costs
// it as the whole index and adds it only while that is cheaper than the heap pages it
// saves, which is while the index is small, as in a test database.
func (n planNode) andedWholeIndexScan(parent *planNode) bool {
	return parent != nil && parent.NodeType == "BitmapAnd" &&
		n.NodeType == "Bitmap Index Scan" && n.IndexCond == ""
}

// explainRowsPerNode runs the statement under EXPLAIN (ANALYZE, FORMAT JSON) and returns
// the number of rows each plan node actually produced (see planRowsPerNode).
func explainRowsPerNode(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q capturedQuery) map[string]float64 {
	t.Helper()

	var raw []byte
	err := pool.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+q.SQL, q.Args...).Scan(&raw)
	require.NoError(t, err, "failed to EXPLAIN the captured statement:\n%s", q.SQL)
	return planRowsPerNode(t, raw)
}

// planRowsPerNode returns the number of rows each node of an EXPLAIN (ANALYZE, FORMAT
// JSON) plan actually produced (rows x loops) for the statement's own rows. A whole-index
// scan ANDed into a bitmap (andedWholeIndexScan) counts nothing: its rows are those of
// every other mailbox, as many as the shared test database happens to hold.
func planRowsPerNode(t *testing.T, raw []byte) map[string]float64 {
	t.Helper()

	var explained []struct {
		Plan planNode `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &explained))
	require.Len(t, explained, 1)

	rows := make(map[string]float64)
	i := 0
	explained[0].Plan.walk(nil, func(n planNode, parent *planNode) {
		key := fmt.Sprintf("%d:%s", i, n.NodeType)
		i++
		switch {
		case n.ActualLoops == 0:
			// Never executed: a node the query did not reach costs nothing.
			rows[key] = 0
		case n.andedWholeIndexScan(parent):
			t.Logf("not counted: %.0f rows of %s, a whole-index scan ANDed into a bitmap",
				n.ActualRows*n.ActualLoops, n.IndexName)
			rows[key] = 0
		default:
			rows[key] = n.ActualRows * n.ActualLoops
		}
	})
	return rows
}

// The rows a statement reads for its mailbox must not include the rows of every other
// mailbox in the table. A BitmapAnd that ANDs in a partial index without an index
// condition reads that whole index (here every expunged message of the test database)
// to narrow a bitmap its sibling already confines to the mailbox; the cost tests that
// sum these rows then fail once the shared database holds enough expunged messages
// (#1748). A scan that a heap scan reads from on its own is still the statement's cost.
func TestPlanRowsLeaveOutWholeIndexScansANDedIntoABitmap(t *testing.T) {
	sum := func(raw string) float64 {
		t.Helper()
		var total float64
		for _, r := range planRowsPerNode(t, []byte(raw)) {
			total += r
		}
		return total
	}

	// The held branch of a numbering in a view, as PostgreSQL planned it on a test
	// database holding 1018 expunged messages.
	anded := `[{"Plan": {"Node Type": "Limit", "Actual Rows": 1, "Actual Loops": 1, "Plans": [
		{"Node Type": "Sort", "Actual Rows": 1, "Actual Loops": 1, "Plans": [
		{"Node Type": "Bitmap Heap Scan", "Actual Rows": 1, "Actual Loops": 1, "Plans": [
		{"Node Type": "BitmapAnd", "Actual Rows": 0, "Actual Loops": 1, "Plans": [
			{"Node Type": "Bitmap Index Scan", "Index Name": "idx_messages_mailbox_id_expunged_modseq",
			 "Index Cond": "((mailbox_id = '7'::bigint) AND (expunged_modseq > '2000'::bigint))",
			 "Actual Rows": 1, "Actual Loops": 1},
			{"Node Type": "Bitmap Index Scan", "Index Name": "idx_messages_account_hash_expunged",
			 "Actual Rows": 1018, "Actual Loops": 1}
		]}]}]}]}}]`
	require.Equal(t, float64(4), sum(anded),
		"the whole-index scan ANDed into the bitmap read other mailboxes' rows, not the statement's")

	alone := `[{"Plan": {"Node Type": "Bitmap Heap Scan", "Actual Rows": 5, "Actual Loops": 1, "Plans": [
		{"Node Type": "Bitmap Index Scan", "Index Name": "idx_messages_account_hash_expunged",
		 "Actual Rows": 1018, "Actual Loops": 1}
	]}}]`
	require.Equal(t, float64(1023), sum(alone),
		"a whole-index scan the heap scan reads from on its own is the statement's cost")
}

// TestPollMailboxUnchangedDoesNotScaleWithMailbox asserts the property that makes idle
// polling affordable: when the modseq has not advanced, nothing the poll executes may
// touch a number of rows that grows with the mailbox.
//
// Poll runs after every IMAP command and every 15 seconds per IDLE session, so a plan
// node that scans the whole active-message set turns "nothing happened" into
// O(sessions x mailbox_size) continuous load across the fleet.
//
// This checks the plan, not the clock: the statements the poll issues are captured
// through a pgx tracer and each is re-run under EXPLAIN (ANALYZE), so the assertion is
// about which rows PostgreSQL had to visit, never about elapsed time.
func TestPollMailboxUnchangedDoesNotScaleWithMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	// Large enough that a full scan of the mailbox is unmistakable in the plan.
	const numMessages = 300
	// A no-change poll may read the mailbox row and its stats row, nothing more.
	const maxRowsPerNode = 10

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	email := fmt.Sprintf("pollcost_%d@example.com", ts)
	accountID := createTestAccount(t, database, email, "password")
	mailboxName := fmt.Sprintf("PollCostBox_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for uid := uint32(1); uid <= numMessages; uid++ {
		insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	// Bring the analyzer up to date so the plans below are the ones production would get.
	_, err = database.GetWritePool().Exec(ctx, "ANALYZE messages")
	require.NoError(t, err)

	currentModSeq := getHighestModSeq(t, database, ctx, mailboxID)
	require.NotZero(t, currentModSeq, "precondition: the appends must have advanced the mailbox modseq")

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{WritePool: database.GetWritePool(), ReadPool: tracedPool}

	// The poll a client that is already up to date performs: nothing has changed.
	poll, err := traced.PollMailbox(ctx, mailboxID, currentModSeq)
	require.NoError(t, err)
	require.Empty(t, poll.Updates, "precondition: an up-to-date poll must report no updates")
	require.Equal(t, uint32(numMessages), poll.NumMessages,
		"an unchanged poll must still report the mailbox's message count to the session")
	require.Equal(t, currentModSeq, poll.ModSeq)

	captured := tracer.captured()
	require.NotEmpty(t, captured, "harness broken: no statement was captured for the poll")
	t.Logf("no-change poll issued %d statement(s)", len(captured))

	for _, q := range captured {
		rowsPerNode := explainRowsPerNode(t, ctx, database.GetReadPool(), q)
		for node, rows := range rowsPerNode {
			assert.LessOrEqualf(t, rows, float64(maxRowsPerNode),
				"IDLE POLL SCALES WITH THE MAILBOX: plan node %q visited %.0f rows for a mailbox of %d "+
					"messages while the poll concluded nothing had changed. Every IMAP command and every "+
					"15s IDLE tick pays this, so the cost is O(sessions x mailbox_size) while the mailbox "+
					"is idle.\nStatement:%s", node, rows, numMessages, q.SQL)
		}
	}
}

// TestPollMailboxReportsMessageCountOnBothPaths guards the counts the fast path must keep
// reporting: the session's EXISTS bookkeeping (server/imap/poll.go) treats a count below
// its own as a desync and disconnects the client, so a cheap no-change poll is only
// admissible while it still reports the true number of messages.
func TestPollMailboxReportsMessageCountOnBothPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	email := fmt.Sprintf("pollcount_%d@example.com", ts)
	accountID := createTestAccount(t, database, email, "password")
	mailboxName := fmt.Sprintf("PollCountBox_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	// Empty mailbox, nothing ever delivered: there is no mailbox_stats row yet.
	poll, err := database.PollMailbox(ctx, mailboxID, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), poll.NumMessages)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for uid := uint32(1); uid <= 5; uid++ {
		insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	// Changed path: the appends are new to this caller.
	poll, err = database.PollMailbox(ctx, mailboxID, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), poll.NumMessages, "changed poll must report the live message count")
	assert.Len(t, poll.Updates, 5)

	// Unchanged path: same count, no updates.
	upToDate := poll.ModSeq
	poll, err = database.PollMailbox(ctx, mailboxID, upToDate)
	require.NoError(t, err)
	assert.Empty(t, poll.Updates)
	assert.Equal(t, uint32(5), poll.NumMessages, "unchanged poll must report the same count as the changed poll")

	// Expunge two, then poll again: the count follows on the changed path...
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		WHERE mailbox_id = $1 AND uid <= 2
	`, mailboxID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	poll, err = database.PollMailbox(ctx, mailboxID, upToDate)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), poll.NumMessages, "changed poll must report the count after the expunges")

	// ...and stays put on the unchanged path that follows it.
	poll, err = database.PollMailbox(ctx, mailboxID, poll.ModSeq)
	require.NoError(t, err)
	assert.Empty(t, poll.Updates)
	assert.Equal(t, uint32(3), poll.NumMessages, "unchanged poll must agree with the preceding changed poll")
}
