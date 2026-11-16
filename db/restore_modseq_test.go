package db

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// A restored message appears in its mailbox, so it is a new message to every client
// that synchronizes by mod-sequence. RFC 7162 §3.1: "When a message is appended to a
// mailbox (via the IMAP APPEND command, COPY to the mailbox, or using an external
// mechanism), the server generates a new modification sequence that is higher than the
// highest modification sequence of all messages in the mailbox and assigns it to the
// appended message." HIGHESTMODSEQ is "the highest mod-sequence value of all messages
// in the mailbox" (§3.1.2.1), so it rises with it.
func TestRestoreMessages_RestoredMessageGetsAFreshModSeq(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	restoredID := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Restored", "<restored@example.com>")
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Kept", "<kept@example.com>")

	var oldUID imap.UID
	require.NoError(t, db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", restoredID).Scan(&oldUID))
	expungeMessage(t, db, inboxID, oldUID)

	// Where a client stands once it has seen the expunge.
	before, err := db.GetMailboxSummary(ctx, inboxID)
	require.NoError(t, err)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	n, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: testEmail, MessageIDs: []int64{restoredID}})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.NoError(t, tx.Commit(ctx))

	var newUID imap.UID
	var createdModSeq, modSeq uint64
	require.NoError(t, db.GetReadPool().QueryRow(ctx, `
		SELECT m.uid, m.created_modseq, GREATEST(m.created_modseq, COALESCE(ms.updated_modseq, 0))
		FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.id = $1`, restoredID).Scan(&newUID, &createdModSeq, &modSeq))
	require.Greater(t, uint64(newUID), uint64(oldUID), "a restored message gets a UID above every UID the mailbox had")
	require.Greater(t, createdModSeq, before.HighestModSeq,
		"the restored message is created anew: its created_modseq must be above the mailbox's HIGHESTMODSEQ before the restore")

	after, err := db.GetMailboxSummary(ctx, inboxID)
	require.NoError(t, err)
	require.Equal(t, 2, after.NumMessages)
	require.GreaterOrEqual(t, after.HighestModSeq, modSeq,
		"HIGHESTMODSEQ must not be below the restored message's MODSEQ")

	// A session whose poll cursor stands at the expunge is told about a new message.
	poll, err := db.PollMailbox(ctx, inboxID, before.HighestModSeq)
	require.NoError(t, err)
	var reported []imap.UID
	for _, u := range poll.Updates {
		if !u.IsExpunge {
			reported = append(reported, u.UID)
		}
	}
	require.Equal(t, []imap.UID{newUID}, reported, "the poll must report the restored message")
	require.Equal(t, uint32(2), poll.NumMessages)
	require.GreaterOrEqual(t, poll.ModSeq, modSeq)

	// A QRESYNC SELECT from the same point, in the view of the HIGHESTMODSEQ it sends.
	changed, err := db.GetMessagesChangedSince(WithSeqView(ctx, after.HighestModSeq), inboxID, before.HighestModSeq)
	require.NoError(t, err)
	var changedUIDs []imap.UID
	for _, m := range changed {
		changedUIDs = append(changedUIDs, m.UID)
	}
	require.Equal(t, []imap.UID{newUID}, changedUIDs, "QRESYNC must report the restored message")
}
