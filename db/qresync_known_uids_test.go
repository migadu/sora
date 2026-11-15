package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetActiveUIDsInSetManyRanges: a fragmented known-uids ("1,3,5,...") is one range
// per UID, and the query must not grow with it (#1354). It had an OR term and one or
// two bind parameters per range, so a set of 70,000 ranges could not even be sent
// (the extended protocol allows 65,535 parameters).
func TestGetActiveUIDsInSetManyRanges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("knownuids_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("KnownUIDs_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	for _, uid := range []uint32{1, 2, 3, 139_999, 200_000, 200_002} {
		insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	// Every odd UID below 140,000, then 200,001:200,005.
	var known imap.UIDSet
	for uid := imap.UID(1); uid < 140_000; uid += 2 {
		known = append(known, imap.UIDRange{Start: uid, Stop: uid})
	}
	known = append(known, imap.UIDRange{Start: 200_001, Stop: 200_005})
	want := []imap.UID{1, 3, 139_999, 200_002}

	active, err := database.GetActiveUIDsInSet(ctx, mailboxID, known)
	require.NoError(t, err)
	assert.Equal(t, want, active)

	view := WithSeqView(ctx, getHighestModSeq(t, database, ctx, mailboxID))
	active, err = database.GetActiveUIDsInSet(view, mailboxID, known)
	require.NoError(t, err)
	assert.Equal(t, want, active, "in a view at the current modseq")
}

// knownUIDsPlanNode is the part of an EXPLAIN (ANALYZE, FORMAT JSON) node that says how
// many rows the node read: the ones it returned and the ones it dropped. PostgreSQL
// reports both per loop.
type knownUIDsPlanNode struct {
	NodeType         string              `json:"Node Type"`
	IndexName        string              `json:"Index Name"`
	ActualRows       float64             `json:"Actual Rows"`
	ActualLoops      float64             `json:"Actual Loops"`
	RemovedByFilter  float64             `json:"Rows Removed by Filter"`
	RemovedByJoin    float64             `json:"Rows Removed by Join Filter"`
	RemovedByRecheck float64             `json:"Rows Removed by Index Recheck"`
	Plans            []knownUIDsPlanNode `json:"Plans"`
}

func (n knownUIDsPlanNode) walk(visit func(knownUIDsPlanNode)) {
	visit(n)
	for _, child := range n.Plans {
		child.walk(visit)
	}
}

// TestGetActiveUIDsInSetReadsOnlyItsRanges: GetActiveUIDsInSet must read one index range
// per known-uids range and the UIDs inside it, and nothing more (#1354), however stale
// the statistics of the mailbox are.
//
// Two shapes: the one range "<oldest>:<newest>" a client such as Evolution sends, whose
// UIDs must come off the index in order instead of being sorted by the database on
// every SELECT, and a fragmented set of one range per UID on a mailbox that has grown
// since the last ANALYZE, which must not read the whole mailbox once per range.
func TestGetActiveUIDsInSetReadsOnlyItsRanges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const numMessages = 2000

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("knownuidsplan_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("KnownUIDsPlan_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	insert := func(from, to uint32) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		for uid := from; uid <= to; uid++ {
			insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
		}
		require.NoError(t, tx.Commit(ctx))
	}
	// The statistics see a mailbox of a few messages; it then grows, as a mailbox does
	// between two ANALYZEs of a large messages table.
	insert(1, 4)
	_, err := database.GetWritePool().Exec(ctx, "ANALYZE messages")
	require.NoError(t, err)
	insert(5, numMessages)

	var oneRange imap.UIDSet
	oneRange.AddRange(1, 5_000_000)
	var allUIDs []imap.UID
	for uid := imap.UID(1); uid <= numMessages; uid++ {
		allUIDs = append(allUIDs, uid)
	}
	var everyOther imap.UIDSet
	var oddUIDs []imap.UID
	for uid := imap.UID(1); uid < 2*numMessages; uid += 2 {
		everyOther = append(everyOther, imap.UIDRange{Start: uid, Stop: uid})
		if uid <= numMessages {
			oddUIDs = append(oddUIDs, uid)
		}
	}

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{WritePool: database.GetWritePool(), ReadPool: tracedPool}
	view := getHighestModSeq(t, database, ctx, mailboxID)

	for _, tc := range []struct {
		name  string
		known imap.UIDSet
		want  []imap.UID
	}{
		{"one range over the mailbox", oneRange, allUIDs},
		{"one range per odd UID", everyOther, oddUIDs},
	} {
		for _, mode := range []struct {
			name string
			ctx  context.Context
		}{
			{"plain", ctx},
			{"in a view", WithSeqView(ctx, view)},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				before := len(tracer.captured())
				active, err := traced.GetActiveUIDsInSet(mode.ctx, mailboxID, tc.known)
				require.NoError(t, err)
				require.Equal(t, tc.want, active)

				captured := tracer.captured()[before:]
				require.Len(t, captured, 1, "harness broken: want the one statement GetActiveUIDsInSet issues")
				q := captured[0]

				var raw []byte
				require.NoError(t, database.GetReadPool().QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+q.SQL, q.Args...).Scan(&raw))
				var explained []struct {
					Plan knownUIDsPlanNode `json:"Plan"`
				}
				require.NoError(t, json.Unmarshal(raw, &explained))
				require.Len(t, explained, 1)

				// Every range is one index lookup, and every UID found is read once.
				budget := float64(len(tc.known) + len(tc.want))
				explained[0].Plan.walk(func(n knownUIDsPlanNode) {
					read := (n.ActualRows + n.RemovedByFilter + n.RemovedByJoin + n.RemovedByRecheck) * n.ActualLoops
					assert.LessOrEqualf(t, read, budget,
						"plan node %s %s read %.0f rows for %d known-uids ranges holding %d active UIDs: "+
							"the cost must follow the ranges and the UIDs in them\n%s",
						n.NodeType, n.IndexName, read, len(tc.known), len(tc.want), raw)
					if n.NodeType == "Sort" || n.NodeType == "Incremental Sort" {
						assert.Zerof(t, n.ActualRows*n.ActualLoops,
							"the database sorted %.0f UIDs: each range comes off the index in UID order\n%s",
							n.ActualRows*n.ActualLoops, raw)
					}
				})
			})
		}
	}
}
