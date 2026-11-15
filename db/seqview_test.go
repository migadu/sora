package db

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// In a session's view (WithSeqView) a message expunged since the view keeps its
// sequence number, and one created since has none before the view's last message.
// Every statement that numbers messages must agree, whichever path it takes: the
// sequence-set resolution, the forward and backward hydration sweeps, the windows of a
// chunked fetch, 1:*, SEARCH and THREAD. "*" is the last row counted (UID 11 here):
// the session never sends it, and names no number past what its client knows.
func TestSeqViewNumbersMessagesAsOfTheView(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("seqview_%d@example.com", ts), "password")
	// UIDs 1..10, created at modseqs 1..10.
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("SeqView_%d", ts), 10)
	const view = 10
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := database.GetWritePool().Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	// UID 3 was expunged before the view; UIDs 2, 5 and 9 after it, so the view holds them.
	exec(`UPDATE messages SET expunged_at = now(), expunged_modseq = 4 WHERE mailbox_id = $1 AND uid = 3`, mailboxID)
	exec(`UPDATE messages SET expunged_at = now(), expunged_modseq = $2 WHERE mailbox_id = $1 AND uid IN (2, 5, 9)`, mailboxID, view+1)
	// UID 11 arrived after the view.
	exec(`INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, content_hash, s3_domain, s3_localpart,
			size, internal_date, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort,
			to_name_sort, to_email_sort, cc_email_sort, recipients_json, message_id, sent_date, subject, body_structure, in_reply_to)
		SELECT account_id, mailbox_id, mailbox_path, 11, content_hash || '_11', s3_domain, s3_localpart || '_11',
			size, internal_date, uploaded, $2, subject_sort, from_name_sort, from_email_sort,
			to_name_sort, to_email_sort, cc_email_sort, recipients_json, '<seqview11@example.com>', sent_date, subject, body_structure, in_reply_to
		FROM messages WHERE mailbox_id = $1 AND uid = 10`, mailboxID, view+2)
	exec(`UPDATE mailboxes SET highest_uid = 11 WHERE id = $1`, mailboxID)

	// The view numbers UIDs 1,2,4,5,6,7,8,9,10 as 1..9; of those, 2, 5 and 9 are gone.
	// UID 11 comes after the view's last message.
	viewSeq := map[imap.UID]uint32{1: 1, 4: 3, 6: 5, 7: 6, 8: 7, 10: 9, 11: 10}
	liveSeq := map[imap.UID]uint32{1: 1, 4: 2, 6: 3, 7: 4, 8: 5, 10: 6, 11: 7}

	stream := func(t *testing.T, ctx context.Context, set imap.NumSet, want map[imap.UID]uint32) []imap.UID {
		t.Helper()
		var got []imap.UID
		require.NoError(t, database.StreamMessagesByNumSet(ctx, mailboxID, set, func(chunk []Message) error {
			for _, msg := range chunk {
				got = append(got, msg.UID)
				require.Equalf(t, want[msg.UID], msg.Seq, "UID %d has the wrong sequence number", msg.UID)
			}
			return nil
		}))
		return got
	}

	viewCtx := WithSeqView(ctx, view)
	for _, chunk := range []int{5000, 2} {
		t.Run(fmt.Sprintf("chunk %d", chunk), func(t *testing.T) {
			saved := database.fetchChunkSize
			database.fetchChunkSize = chunk
			defer func() { database.fetchChunkSize = saved }()

			cases := []struct {
				name string
				set  imap.NumSet
				want []imap.UID
			}{
				{"forward sweep", imap.SeqSet{{Start: 3, Stop: 5}}, []imap.UID{4, 6}},
				{"backward sweep", imap.SeqSet{{Start: 6, Stop: 9}}, []imap.UID{7, 8, 10}},
				{"star is the last row counted", imap.SeqSet{{Start: 6, Stop: 0}}, []imap.UID{7, 8, 10, 11}},
				{"a held message names nothing", imap.SeqSet{{Start: 8, Stop: 8}}, nil},
				{"the view's last message", imap.SeqSet{{Start: 9, Stop: 9}}, []imap.UID{10}},
				{"1:* numbers in the view", imap.SeqSet{{Start: 1, Stop: 0}}, []imap.UID{1, 4, 6, 7, 8, 10, 11}},
				{"1:9 is the view", imap.SeqSet{{Start: 1, Stop: 9}}, []imap.UID{1, 4, 6, 7, 8, 10}},
				{"UIDs are numbered in the view too", imap.UIDSetNum(1, 6, 11), []imap.UID{1, 6, 11}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					require.Equal(t, tc.want, stream(t, viewCtx, tc.set, viewSeq))
				})
			}
		})
	}

	t.Run("without a view the live messages are numbered", func(t *testing.T) {
		require.Equal(t, []imap.UID{6, 7, 8}, stream(t, ctx, imap.SeqSet{{Start: 3, Stop: 5}}, liveSeq))
		require.Equal(t, []imap.UID{1, 4, 6, 7, 8, 10, 11}, stream(t, ctx, imap.SeqSet{{Start: 1, Stop: 0}}, liveSeq))
	})

	t.Run("search", func(t *testing.T) {
		results, err := database.SearchMessagesWithCriteria(viewCtx, mailboxID, accountID,
			&imap.SearchCriteria{SeqNum: []imap.SeqSet{{{Start: 3, Stop: 0}}}}, 0, 10)
		require.NoError(t, err)
		got := map[imap.UID]uint32{}
		for _, r := range results {
			got[r.UID] = r.Seq
		}
		require.Equal(t, map[imap.UID]uint32{4: 3, 6: 5, 7: 6, 8: 7, 10: 9, 11: 10}, got)
	})

	t.Run("thread", func(t *testing.T) {
		results, err := database.GetMessagesForThreading(viewCtx, mailboxID, accountID, &imap.SearchCriteria{}, false, true, 0)
		require.NoError(t, err)
		var uids []imap.UID
		for _, r := range results {
			uids = append(uids, r.UID)
			require.Equalf(t, viewSeq[r.UID], r.Seq, "UID %d has the wrong sequence number", r.UID)
		}
		require.True(t, slices.Equal([]imap.UID{1, 4, 6, 7, 8, 10, 11}, uids), "got %v", uids)
	})
}

// Numbering in a view must cost what numbering without one costs, plus the few held
// rows: a session is always in a view, so a UNION that makes PostgreSQL read and sort
// every live UID of the mailbox before it can rank one turns FETCH 3, which reads three
// index entries without a view, into a pass over the mailbox for every such command.
func TestSeqViewNumberingCostsWhatTheLiveNumberingCosts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const (
		messages = 2000
		// The held branch and its sort: a handful of rows. A sort of the mailbox's
		// live UIDs costs 2 x messages on its own.
		maxExtraRows = 100
	)

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("seqviewcost_%d@example.com", ts), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("SeqViewCost_%d", ts), messages)
	// The view holds UID 1, expunged after it.
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE messages SET expunged_at = now(), expunged_modseq = $2 WHERE mailbox_id = $1 AND uid = 1`, mailboxID, messages+1)
	require.NoError(t, err)
	_, err = database.GetWritePool().Exec(ctx, "ANALYZE messages, message_state")
	require.NoError(t, err)

	cost := func(ctx context.Context, set imap.SeqSet, want []imap.UID) float64 {
		t.Helper()
		tracer := &queryCapturingTracer{}
		pool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
		defer pool.Close()
		traced := &Database{WritePool: database.GetWritePool(), ReadPool: pool}

		var got []imap.UID
		require.NoError(t, traced.StreamMessagesByNumSet(ctx, mailboxID, set, func(chunk []Message) error {
			for _, msg := range chunk {
				got = append(got, msg.UID)
			}
			return nil
		}))
		require.Equal(t, want, got)

		var rows float64
		for _, q := range tracer.captured() {
			for _, r := range explainRowsPerNode(t, ctx, database.GetReadPool(), q) {
				rows += r
			}
		}
		return rows
	}

	// Without a view 2:3 are UIDs 3 and 4; in the view (UID 1 still held) UIDs 2 and 3.
	live := cost(ctx, imap.SeqSet{{Start: 2, Stop: 3}}, []imap.UID{3, 4})
	view := cost(WithSeqView(ctx, messages), imap.SeqSet{{Start: 2, Stop: 3}}, []imap.UID{2, 3})
	t.Logf("rows for FETCH 2:3 in a mailbox of %d: %.0f without a view, %.0f in a view", messages, live, view)
	require.LessOrEqualf(t, view, live+maxExtraRows,
		"numbering in a view read %.0f rows against %.0f without one: the held rows must be merged "+
			"into the live index order, not sorted together with every live UID", view, live)
}
