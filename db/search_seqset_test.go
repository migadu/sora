package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// mapSeqNumCriteriaToUID names by UID the messages a criteria's sequence sets name,
// wherever in the tree they are: a sequence number past the last message drops its
// range, a range ending past it runs to the last message, and a set naming no message
// at all matches nothing.
func TestMapSeqNumCriteriaToUID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("seqmap_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("SeqMap_%d", ts), 10)
	// Expunging UIDs 2 and 5 leaves sequence numbers 1..8 on UIDs 1,3,4,6,7,8,9,10.
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now() WHERE mailbox_id = $1 AND uid IN (2, 5)`, mailboxID)
	require.NoError(t, err)

	seqs := func(ranges ...[2]uint32) imap.SeqSet {
		var set imap.SeqSet
		for _, r := range ranges {
			set = append(set, imap.SeqRange{Start: r[0], Stop: r[1]})
		}
		return set
	}
	uids := func(ranges ...[2]imap.UID) imap.UIDSet {
		var set imap.UIDSet
		for _, r := range ranges {
			set = append(set, imap.UIDRange{Start: r[0], Stop: r[1]})
		}
		return set
	}

	cases := []struct {
		name     string
		criteria imap.SearchCriteria
		want     imap.SearchCriteria
	}{
		{
			name:     "range",
			criteria: imap.SearchCriteria{SeqNum: []imap.SeqSet{seqs([2]uint32{2, 4})}},
			want:     imap.SearchCriteria{UID: []imap.UIDSet{uids([2]imap.UID{3, 6})}},
		},
		{
			name:     "single numbers and a star",
			criteria: imap.SearchCriteria{SeqNum: []imap.SeqSet{seqs([2]uint32{8, 8}, [2]uint32{1, 1}, [2]uint32{6, 0})}},
			want:     imap.SearchCriteria{UID: []imap.UIDSet{uids([2]imap.UID{10, 10}, [2]imap.UID{1, 1}, [2]imap.UID{8, 0})}},
		},
		{
			name:     "a range ending past the last message runs to it",
			criteria: imap.SearchCriteria{SeqNum: []imap.SeqSet{seqs([2]uint32{7, 50})}},
			want:     imap.SearchCriteria{UID: []imap.UIDSet{uids([2]imap.UID{9, 0})}},
		},
		{
			name:     "a range starting past the last message is dropped",
			criteria: imap.SearchCriteria{SeqNum: []imap.SeqSet{seqs([2]uint32{3, 3}, [2]uint32{20, 30})}},
			want:     imap.SearchCriteria{UID: []imap.UIDSet{uids([2]imap.UID{4, 4})}},
		},
		{
			name:     "a set naming no message matches nothing",
			criteria: imap.SearchCriteria{SeqNum: []imap.SeqSet{seqs([2]uint32{20, 30})}},
			want:     imap.SearchCriteria{UID: []imap.UIDSet{uids([2]imap.UID{0, 0})}},
		},
		{
			name: "existing UID sets are kept, sets in NOT and OR are mapped",
			criteria: imap.SearchCriteria{
				UID:    []imap.UIDSet{uids([2]imap.UID{1, 100})},
				SeqNum: []imap.SeqSet{seqs([2]uint32{1, 2}), seqs([2]uint32{5, 5})},
				Not:    []imap.SearchCriteria{{SeqNum: []imap.SeqSet{seqs([2]uint32{3, 3})}}},
				Or: [][2]imap.SearchCriteria{{
					{SeqNum: []imap.SeqSet{seqs([2]uint32{4, 4})}},
					{Flag: []imap.Flag{imap.FlagSeen}},
				}},
			},
			want: imap.SearchCriteria{
				UID: []imap.UIDSet{uids([2]imap.UID{1, 100}), uids([2]imap.UID{1, 3}), uids([2]imap.UID{7, 7})},
				Not: []imap.SearchCriteria{{UID: []imap.UIDSet{uids([2]imap.UID{4, 4})}}},
				Or: [][2]imap.SearchCriteria{{
					{UID: []imap.UIDSet{uids([2]imap.UID{6, 6})}},
					{Flag: []imap.Flag{imap.FlagSeen}},
				}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.criteria
			require.NoError(t, database.mapSeqNumCriteriaToUID(ctx, mailboxID, &got))
			require.Equal(t, tc.want, got)
		})
	}
}

// Naming more sequence numbers in a search must not cost a pass over the mailbox each.
// Search rate limiting treats searches by sequence set as free, on the grounds that
// they cost what a FETCH of the same messages costs; that holds only if mapping the
// set to UIDs is one pass however many ranges it has.
//
// Measured like TestChunkedFetchSequenceHydrationIsLinear: every statement the search
// issues is replayed under EXPLAIN (ANALYZE) and the rows PostgreSQL produced are summed.
func TestSeqSetSearchCostDoesNotGrowWithRanges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const (
		messages = 2000
		ranges   = 100
		// Each further range may add the rows for the message it names, a few dozen
		// across the search and the sequence hydration, but nothing like a pass over
		// the mailbox, which resolving ranges one at a time cost (about 2 x messages).
		maxRowsPerRange = messages / 10
	)

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("seqcost_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("SeqCost_%d", ts), messages)
	_, err := database.GetWritePool().Exec(ctx, "ANALYZE messages, message_state")
	require.NoError(t, err)

	searchCost := func(set imap.SeqSet) float64 {
		t.Helper()
		tracer := &queryCapturingTracer{}
		pool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
		defer pool.Close()
		traced := &Database{WritePool: database.GetWritePool(), ReadPool: pool}

		found, err := traced.SearchMessagesWithCriteria(ctx, mailboxID, accountID,
			&imap.SearchCriteria{SeqNum: []imap.SeqSet{set}}, 0, messages)
		require.NoError(t, err)
		require.Len(t, found, len(set), "every sequence number named should match one message")

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

	oneCost, manyCost := searchCost(one), searchCost(many)
	perRange := (manyCost - oneCost) / (ranges - 1)
	t.Logf("rows for 1 sequence number: %.0f, for %d: %.0f (%.0f per further range, mailbox of %d)",
		oneCost, ranges, manyCost, perRange, messages)
	require.LessOrEqualf(t, perRange, float64(maxRowsPerRange),
		"each further sequence number cost %.0f rows in a mailbox of %d; mapping the set to UIDs "+
			"must be one pass over the mailbox, not one per range", perRange, messages)
}

// UID THREAD of a few UIDs reads those messages and no others, however large the
// mailbox: search rate limiting lets it through uncharged on that ground. (THREAD in
// sequence numbers ranks the whole mailbox to number its result, so it is charged.)
func TestUIDThreadByUIDSetReadsOnlyThoseMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const (
		messages = 2000
		named    = 10
		// The index probe and the row for each message named, with room to spare;
		// a scan of the mailbox would be hundreds of times this.
		maxRowsPerMessage = 5
	)

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("threadcost_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("ThreadCost_%d", ts), messages)
	_, err := database.GetWritePool().Exec(ctx, "ANALYZE messages, message_state")
	require.NoError(t, err)

	tracer := &queryCapturingTracer{}
	pool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
	defer pool.Close()
	traced := &Database{WritePool: database.GetWritePool(), ReadPool: pool}

	criteria := &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: messages - named + 1, Stop: messages}}}}
	found, err := traced.GetMessagesForThreading(ctx, mailboxID, accountID, criteria, true, false)
	require.NoError(t, err)
	require.Len(t, found, named)

	var rows float64
	for _, q := range tracer.captured() {
		for _, r := range explainRowsPerNode(t, ctx, database.GetReadPool(), q) {
			rows += r
		}
	}
	t.Logf("UID THREAD of %d UIDs in a mailbox of %d read %.0f rows", named, messages, rows)
	require.LessOrEqualf(t, rows, float64(named*maxRowsPerMessage),
		"UID THREAD of %d UIDs read %.0f rows in a mailbox of %d; it must read only the messages named",
		named, rows, messages)
}
