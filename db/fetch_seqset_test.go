package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// FETCH by sequence set returns the messages the set names now, each with its
// sequence number: a range starting past the last message is dropped, one ending
// past it runs to the last message, and the ends of a range may come in either order.
func TestStreamMessagesBySeqSet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchseq_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("FetchSeq_%d", ts), 10)
	// Expunging UIDs 2 and 5 leaves sequence numbers 1..8 on UIDs 1,3,4,6,7,8,9,10.
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now() WHERE mailbox_id = $1 AND uid IN (2, 5)`, mailboxID)
	require.NoError(t, err)
	seqOf := map[imap.UID]uint32{1: 1, 3: 2, 4: 3, 6: 4, 7: 5, 8: 6, 9: 7, 10: 8}

	cases := []struct {
		name string
		set  imap.SeqSet
		want []imap.UID
	}{
		{"range", imap.SeqSet{{Start: 2, Stop: 4}}, []imap.UID{3, 4, 6}},
		{"single numbers and a star", imap.SeqSet{{Start: 8, Stop: 8}, {Start: 1, Stop: 1}, {Start: 6, Stop: 0}}, []imap.UID{1, 8, 9, 10}},
		{"a range ending past the last message runs to it", imap.SeqSet{{Start: 7, Stop: 50}}, []imap.UID{9, 10}},
		{"a range starting past the last message is dropped", imap.SeqSet{{Start: 3, Stop: 3}, {Start: 20, Stop: 30}}, []imap.UID{4}},
		{"a set naming no message fetches nothing", imap.SeqSet{{Start: 20, Stop: 30}}, nil},
		{"reversed range", imap.SeqSet{{Start: 4, Stop: 2}}, []imap.UID{3, 4, 6}},
		{"whole mailbox", imap.SeqSet{{Start: 1, Stop: 8}}, []imap.UID{1, 3, 4, 6, 7, 8, 9, 10}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []imap.UID
			err := database.StreamMessagesByNumSet(ctx, mailboxID, tc.set, func(chunk []Message) error {
				for _, msg := range chunk {
					got = append(got, msg.UID)
					require.Equalf(t, seqOf[msg.UID], msg.Seq, "UID %d has the wrong sequence number", msg.UID)
				}
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// Naming more sequence numbers in a FETCH must not cost a pass over the mailbox each:
// the set is mapped to UIDs in one statement however many ranges it has (#111).
// Measured like TestSeqSetSearchCostDoesNotGrowWithRanges.
func TestSeqSetFetchCostDoesNotGrowWithRanges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const (
		messages = 2000
		ranges   = 100
		// Each further range may add the rows for the message it names, across the
		// fetch and its sequence hydration, but nothing like a pass over the mailbox,
		// which resolving ranges one at a time cost (about 2 x messages).
		maxRowsPerRange = messages / 10
	)

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("fetchseqcost_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("FetchSeqCost_%d", ts), messages)
	_, err := database.GetWritePool().Exec(ctx, "ANALYZE messages, message_state")
	require.NoError(t, err)

	fetchCost := func(set imap.SeqSet) float64 {
		t.Helper()
		tracer := &queryCapturingTracer{}
		pool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
		defer pool.Close()
		traced := &Database{WritePool: database.GetWritePool(), ReadPool: pool, fetchChunkSize: database.fetchChunkSize}

		fetched := 0
		require.NoError(t, traced.StreamMessagesByNumSet(ctx, mailboxID, set, func(chunk []Message) error {
			fetched += len(chunk)
			return nil
		}))
		require.Equal(t, len(set), fetched, "every sequence number named should fetch one message")

		var rows float64
		for _, q := range tracer.captured() {
			for _, r := range explainRowsPerNode(t, ctx, database.GetReadPool(), q) {
				rows += r
			}
		}
		return rows
	}

	// Sequence numbers near the end of the mailbox, the most expensive to rank.
	one := imap.SeqSet{{Start: messages, Stop: messages}}
	var many imap.SeqSet
	for i := range ranges {
		n := uint32(messages - 2*i)
		many = append(many, imap.SeqRange{Start: n, Stop: n})
	}

	oneCost, manyCost := fetchCost(one), fetchCost(many)
	perRange := (manyCost - oneCost) / (ranges - 1)
	t.Logf("rows for 1 sequence number: %.0f, for %d: %.0f (%.0f per further range, mailbox of %d)",
		oneCost, ranges, manyCost, perRange, messages)
	require.LessOrEqualf(t, perRange, float64(maxRowsPerRange),
		"each further sequence number cost %.0f rows in a mailbox of %d; mapping the set to UIDs "+
			"must be one pass over the mailbox, not one per range", perRange, messages)
}
