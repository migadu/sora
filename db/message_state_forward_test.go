package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// COPY and MOVE give the new message its source's flags. A source without a
// message_state row has none, so the new message gets a row with none, not a missing
// row of its own (#1151).
func TestCopyMoveOfMessageWithoutStateWritesState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archiveID := createTestMailbox(t, db, accountID, "Archive")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	legacyIDs := make(map[imap.UID]int64)
	insert := func(n int) imap.UID {
		t.Helper()
		hash := fmt.Sprintf("statelesscopy-%d-%d", base, n)
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		id, uid, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "statelesscopy", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash), InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: fmt.Sprintf("message %d", n), BodyStructure: &bs,
		}, PendingUpload{InstanceID: "test", ContentHash: hash, Size: 100, AccountID: accountID})
		require.NoError(t, err)
		// The message as an older build left it.
		_, err = tx.Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, id)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		legacyIDs[imap.UID(uid)] = id
		return imap.UID(uid)
	}
	copySrc, moveSrc, sameSrc := insert(1), insert(2), insert(3)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	copied, _, err := db.CopyMessages(ctx, tx, &[]imap.UID{copySrc}, inboxID, archiveID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	moved, err := db.MoveMessages(ctx, tx, &[]imap.UID{moveSrc}, inboxID, archiveID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	sameMoved, err := db.MoveMessages(ctx, tx, &[]imap.UID{sameSrc}, inboxID, inboxID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	for _, p := range []struct {
		name      string
		mailboxID int64
		uid       imap.UID
	}{
		{"COPY", archiveID, copied[copySrc]},
		{"MOVE", archiveID, moved[moveSrc]},
		{"MOVE within the mailbox", inboxID, sameMoved[sameSrc]},
	} {
		t.Run(p.name, func(t *testing.T) {
			require.NotZero(t, p.uid)
			var flags int
			var keywords []byte
			err := db.GetReadPool().QueryRow(ctx, `
				SELECT ms.flags, ms.custom_flags
				FROM messages m
				JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = $1 AND m.uid = $2 AND m.expunged_at IS NULL`, p.mailboxID, p.uid).Scan(&flags, &keywords)
			require.NoError(t, err, "the new message must have a message_state row")
			assert.Equal(t, 0, flags)
			assert.JSONEq(t, `[]`, string(keywords))
		})
	}
	// Forward-only: copying repairs only the destination row. The legacy source
	// remains untouched, including the absence of its state row.
	var legacyHasState bool
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id = $1)`, legacyIDs[copySrc]).Scan(&legacyHasState))
	assert.False(t, legacyHasState, "the existing source must not be backfilled")

	summary, err := db.GetMailboxSummary(ctx, archiveID)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.UnseenCount, "the copy and the moved message are unseen in the destination")
}
