package db

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// pollStep names a point between two of the statements PollMailbox issues.
type pollStep int

const (
	// beforeChanges is just before the statement that reads what changed since the cursor.
	beforeChanges pollStep = iota
	// beforeNumbering is just before the batch that numbers the changed messages.
	beforeNumbering
)

// pollStepTracer runs inject once, from the poll's own goroutine, just before PollMailbox
// sends the statement at step. inject writes through another pool, so its transaction
// commits while the poll is between two of its statements, as a concurrent delivery or
// expunge from another session can.
type pollStepTracer struct {
	step   pollStep
	inject func()
	fired  atomic.Bool
}

func (tr *pollStepTracer) at(step pollStep) {
	if step == tr.step && tr.fired.CompareAndSwap(false, true) {
		tr.inject()
	}
}

func (tr *pollStepTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// The changes query is the only statement of the poll that is a UNION.
	if strings.Contains(data.SQL, "UNION") {
		tr.at(beforeChanges)
	}
	return ctx
}

func (tr *pollStepTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (tr *pollStepTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	// The sequence numbering is the only batch of the poll.
	tr.at(beforeNumbering)
	return ctx
}

func (tr *pollStepTracer) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}

func (tr *pollStepTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

// pollClient is a client's view of a selected mailbox, kept from the polls it is sent in
// the order server/imap/poll.go sends them: the expunges at their sequence numbers, then
// EXISTS up to NumMessages (the new messages take the numbers past the last one), then
// a FETCH for each changed message at its sequence number. The cursor moves as Poll
// moves it. Every response must name a message the client can place (RFC 9051 §2.3.1.2:
// a client learns the sequence numbers of new messages from EXISTS).
type pollClient struct {
	uids   []imap.UID
	cursor uint64
}

func (c *pollClient) apply(t *testing.T, poll *MailboxPoll) {
	t.Helper()

	for _, u := range poll.Updates {
		if !u.IsExpunge {
			continue
		}
		require.Truef(t, u.SeqNum >= 1 && int(u.SeqNum) <= len(c.uids) && c.uids[u.SeqNum-1] == u.UID,
			"* %d EXPUNGE for UID %d does not name that message in the client's view %v", u.SeqNum, u.UID, c.uids)
		c.uids = slices.Delete(c.uids, int(u.SeqNum)-1, int(u.SeqNum))
	}

	var added []imap.UID
	for _, u := range poll.Updates {
		if !u.IsExpunge && !slices.Contains(c.uids, u.UID) {
			added = append(added, u.UID)
		}
	}
	slices.Sort(added)
	c.uids = append(c.uids, added...)
	require.Equalf(t, int(poll.NumMessages), len(c.uids),
		"the poll announces * %d EXISTS, but its updates describe %d messages %v", poll.NumMessages, len(c.uids), c.uids)

	for _, u := range poll.Updates {
		if u.IsExpunge {
			continue
		}
		require.Truef(t, u.SeqNum >= 1 && u.SeqNum <= poll.NumMessages && c.uids[u.SeqNum-1] == u.UID,
			"* %d FETCH (UID %d) does not name that message in the client's view %v after * %d EXISTS",
			u.SeqNum, u.UID, c.uids, poll.NumMessages)
	}

	if len(poll.Updates) > 0 {
		for _, u := range poll.Updates {
			c.cursor = max(c.cursor, u.EffectiveModSeq)
		}
		c.cursor = max(c.cursor, poll.PhantomModSeq)
	} else {
		c.cursor = max(c.cursor, poll.ModSeq, poll.PhantomModSeq)
	}
}

// TestPollMailboxReadsOneSnapshot is the regression test for #1234: PollMailbox counted the
// messages, read the changes and numbered them in separate statements, each in its own
// READ COMMITTED snapshot. A delivery or expunge committing between two of them made the
// poll describe one mailbox in its count and another in its updates: a FETCH numbered past
// the EXISTS it was sent with, an EXPUNGE without the count dropping, or a FETCH at the
// sequence number of a different message.
func TestPollMailboxReadsOneSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()

	insert := func(t *testing.T, ctx context.Context, accountID, mailboxID int64, mailboxName string, uids ...uint32) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		for _, uid := range uids {
			insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, nil)
		}
		require.NoError(t, tx.Commit(ctx))
	}
	expunge := func(t *testing.T, ctx context.Context, mailboxID int64, uid imap.UID) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = database.ExpungeMessageUIDs(ctx, tx, mailboxID, uid)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}

	cases := []struct {
		name  string
		step  pollStep
		write func(t *testing.T, ctx context.Context, accountID, mailboxID int64, mailboxName string)
	}{
		{
			name: "delivery before the changes are read",
			step: beforeChanges,
			write: func(t *testing.T, ctx context.Context, accountID, mailboxID int64, mailboxName string) {
				insert(t, ctx, accountID, mailboxID, mailboxName, 5)
			},
		},
		{
			name: "expunge before the changes are read",
			step: beforeChanges,
			write: func(t *testing.T, ctx context.Context, _, mailboxID int64, _ string) {
				expunge(t, ctx, mailboxID, 2)
			},
		},
		{
			name: "delivery before the changes are numbered",
			step: beforeNumbering,
			write: func(t *testing.T, ctx context.Context, accountID, mailboxID int64, mailboxName string) {
				insert(t, ctx, accountID, mailboxID, mailboxName, 5)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ts := time.Now().UnixNano()
			accountID := createTestAccount(t, database, fmt.Sprintf("pollsnapshot_%d@example.com", ts), "password")
			mailboxName := fmt.Sprintf("PollSnapshot_%d", ts)
			mailboxID := createTestMailbox(t, database, accountID, mailboxName)

			// The client has the mailbox selected with UIDs 1-3 and is up to date.
			insert(t, ctx, accountID, mailboxID, mailboxName, 1, 2, 3)
			client := &pollClient{uids: []imap.UID{1, 2, 3}, cursor: getHighestModSeq(t, database, ctx, mailboxID)}

			// A delivery gives its next poll something to report...
			insert(t, ctx, accountID, mailboxID, mailboxName, 4)

			// ...and another write commits in the middle of that poll.
			tracer := &pollStepTracer{step: tc.step, inject: func() { tc.write(t, ctx, accountID, mailboxID, mailboxName) }}
			tracedPool := newCapturingPool(t, ctx, database.GetReadPool(), tracer)
			defer tracedPool.Close()
			traced := &Database{WritePool: database.GetWritePool(), ReadPool: tracedPool}

			poll, err := traced.PollMailbox(ctx, mailboxID, client.cursor)
			require.NoError(t, err)
			require.True(t, tracer.fired.Load(), "harness broken: the concurrent write was never injected")
			client.apply(t, poll)

			// The next poll reports whatever the first one left out.
			poll, err = database.PollMailbox(ctx, mailboxID, client.cursor)
			require.NoError(t, err)
			client.apply(t, poll)

			var live []imap.UID
			rows, err := database.GetReadPool().Query(ctx,
				`SELECT uid FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL ORDER BY uid`, mailboxID)
			require.NoError(t, err)
			for rows.Next() {
				var uid uint32
				require.NoError(t, rows.Scan(&uid))
				live = append(live, imap.UID(uid))
			}
			require.NoError(t, rows.Err())
			require.Equal(t, live, client.uids, "after the next poll the client's view must be the mailbox")
		})
	}
}
