package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQResyncReadsInSeqView pins the reads a QRESYNC SELECT makes after its summary
// (#1293). In a view (WithSeqView) at the summary's modseq they describe the mailbox as
// it stood then, whatever was written since: the changes are those of the view's
// messages up to the view, numbered in it; a message the view holds is active although it
// has since been expunged; the first unseen message is one of the view's. Without a view
// they read the mailbox as it is now.
func TestQResyncReadsInSeqView(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("qresyncview_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("QResyncView_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	write := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, f(tx))
		require.NoError(t, tx.Commit(ctx))
	}
	insert := func(uid uint32, flags ...imap.Flag) {
		t.Helper()
		write(func(tx pgx.Tx) error {
			insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, flags)
			return nil
		})
	}
	addFlag := func(uid imap.UID, flag imap.Flag) {
		t.Helper()
		write(func(tx pgx.Tx) error {
			_, _, err := database.AddMessageFlags(ctx, tx, uid, mailboxID, []imap.Flag{flag})
			return err
		})
	}

	// The client has UIDs 1-3 at modseq since; 1 and 2 are \Seen.
	insert(1, imap.FlagSeen)
	insert(2, imap.FlagSeen)
	insert(3)
	since := getHighestModSeq(t, database, ctx, mailboxID)

	// Before the summary: UID 4 arrives, 3 is flagged, 2 marked \Deleted.
	insert(4)
	addFlag(3, imap.FlagFlagged)
	addFlag(2, imap.FlagDeleted)
	summary := getHighestModSeq(t, database, ctx, mailboxID)

	// After the summary: UID 5 arrives, 1 is answered, 2 is expunged.
	insert(5)
	addFlag(1, imap.FlagAnswered)
	write(func(tx pgx.Tx) error {
		_, err := database.ExpungeMessageUIDs(ctx, tx, mailboxID, 2)
		return err
	})

	type change struct {
		UID    imap.UID
		SeqNum uint32
	}
	changes := func(ctx context.Context) []change {
		t.Helper()
		msgs, err := database.GetMessagesChangedSince(ctx, mailboxID, since)
		require.NoError(t, err)
		out := make([]change, 0, len(msgs))
		for _, m := range msgs {
			out = append(out, change{m.UID, m.SeqNum})
			if seqViewOf(ctx) > 0 {
				assert.LessOrEqualf(t, m.ModSeq, summary, "UID %d is reported with a change past the view", m.UID)
			}
			if m.UID == 2 {
				assert.Contains(t, m.Flags, imap.FlagDeleted, "UID 2 is reported with its flags as of the view")
			}
		}
		return out
	}
	known := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 4}}

	t.Run("in the view at the summary", func(t *testing.T) {
		view := WithSeqView(ctx, summary)

		assert.Equal(t, []change{{2, 2}, {3, 3}, {4, 4}}, changes(view),
			"the changes of the mailbox [1 2 3 4] up to the summary, numbered in it")

		active, err := database.GetActiveUIDsInSet(view, mailboxID, known)
		require.NoError(t, err)
		assert.Equal(t, []imap.UID{1, 2, 3, 4}, active, "UID 2 is still in the mailbox at the summary")

		unseen, err := database.GetFirstUnseenSeqNum(view, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, uint32(3), unseen, "UID 3 is the first unseen message of [1 2 3 4]")
	})

	t.Run("without a view", func(t *testing.T) {
		assert.Equal(t, []change{{1, 1}, {3, 2}, {4, 3}, {5, 4}}, changes(ctx),
			"the changes of the mailbox [1 3 4 5] as it is now")

		active, err := database.GetActiveUIDsInSet(ctx, mailboxID, known)
		require.NoError(t, err)
		assert.Equal(t, []imap.UID{1, 3, 4}, active)

		unseen, err := database.GetFirstUnseenSeqNum(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, uint32(2), unseen, "UID 3 is the second message of [1 3 4 5]")
	})
}
