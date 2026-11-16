package db

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// A restore brings a message back under a new UID, but the expunge of its old UID still
// happened, and the expunged row is the only record of it: which UID went, and when
// (expunged_modseq). Rewriting that row in place (#1712) lost it, so a session that had
// not yet been told of the expunge was never sent it, and QRESYNC and UID FETCH
// (CHANGEDSINCE ... VANISHED) never reported the old UID. RFC 7162 §3.2.5.1: the server
// sends the client the expunges "that have occurred in this mailbox since the provided
// modification sequence", and "If the client did not provide the list of UIDs, the server
// acts as if the client has specified "1:<maxuid>"".
func TestRestoreMessages_KeepsTheExpungeOfTheOldUID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	restoredID := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Restored", "<history-restored@example.com>")
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Second", "<history-second@example.com>")
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Third", "<history-third@example.com>")

	var oldUID imap.UID
	var contentHash string
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT uid, content_hash FROM messages WHERE id = $1", restoredID).Scan(&oldUID, &contentHash))

	// Where a client stands that synchronized before the expunge.
	before, err := db.GetMailboxSummary(ctx, inboxID)
	require.NoError(t, err)

	expungeMessage(t, db, inboxID, oldUID)

	inbox := "INBOX"
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	n, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: testEmail, MailboxPath: &inbox})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.NoError(t, tx.Commit(ctx))

	var newUID imap.UID
	require.NoError(t, db.GetReadPool().QueryRow(ctx, `
		SELECT uid FROM messages
		WHERE mailbox_id = $1 AND content_hash = $2 AND expunged_at IS NULL`,
		inboxID, contentHash).Scan(&newUID))
	require.Greater(t, uint64(newUID), uint64(oldUID)+2, "the restored message gets a UID above every UID the mailbox had")

	after, err := db.GetMailboxSummary(ctx, inboxID)
	require.NoError(t, err)

	t.Run("a session that was not told of the expunge is told now", func(t *testing.T) {
		poll, err := db.PollMailbox(ctx, inboxID, before.HighestModSeq)
		require.NoError(t, err)
		var expunged, created []imap.UID
		for _, u := range poll.Updates {
			if u.IsExpunge {
				expunged = append(expunged, u.UID)
			} else {
				created = append(created, u.UID)
			}
		}
		require.Equal(t, []imap.UID{oldUID}, expunged, "the poll must report the old UID's expunge")
		require.Equal(t, []imap.UID{newUID}, created, "the poll must report the restored message as new")
		require.Equal(t, uint32(3), poll.NumMessages)
	})

	t.Run("QRESYNC reports the old UID as vanished", func(t *testing.T) {
		vanished, err := db.GetVanishedUIDs(ctx, inboxID, before.HighestModSeq, after.HighestModSeq)
		require.NoError(t, err)
		require.Equal(t, []imap.UID{oldUID}, vanished)
	})

	t.Run("UID FETCH VANISHED reports the old UID", func(t *testing.T) {
		vanished, err := db.GetVanishedUIDsForFetch(ctx, inboxID, before.HighestModSeq)
		require.NoError(t, err)
		require.Equal(t, []imap.UID{oldUID}, vanished)
	})

	t.Run("the mailbox's counts take the restored message", func(t *testing.T) {
		require.Equal(t, 3, after.NumMessages)
		var cached, live int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT unseen_count, `+liveUnseenCount("$1")+` FROM mailbox_stats WHERE mailbox_id = $1`,
			inboxID).Scan(&cached, &live))
		require.Equal(t, live, cached, "unseen_count must match the live unseen count")
		require.Zero(t, cached, "every message, the restored one included, is \\Seen")
	})

	t.Run("a restored message is not deleted any more", func(t *testing.T) {
		deleted, err := db.ListDeletedMessages(ctx, ListDeletedMessagesParams{Email: testEmail, MailboxPath: &inbox})
		require.NoError(t, err)
		require.Empty(t, deleted, "a restored message must not be listed as deleted")

		ids, err := db.GetRestorableMessageIDs(ctx, RestoreMessagesParams{Email: testEmail, MailboxPath: &inbox})
		require.NoError(t, err)
		require.Empty(t, ids, "a restored message must not be restorable again")

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		n, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: testEmail, MessageIDs: []int64{restoredID}})
		require.NoError(t, err)
		require.Zero(t, n, "restoring the same message again must restore nothing")
		require.NoError(t, tx.Commit(ctx))

		var live int
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `
			SELECT COUNT(*) FROM messages
			WHERE mailbox_id = $1 AND content_hash = $2 AND expunged_at IS NULL`,
			inboxID, contentHash).Scan(&live))
		require.Equal(t, 1, live)
	})
}
