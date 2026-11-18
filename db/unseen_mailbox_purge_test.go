//go:build integration

package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// Deleting a mailbox detaches its message_state rows (mailbox_id = NULL), an UPDATE the
// stats triggers give no unseen delta (#2023). That is right only because PurgeMailboxStep
// detaches them in a step that found no live message under the mailbox lock: the expunge
// steps before it have already taken every message out of unseen_count, reading its flags
// from the still-attached state row. This pins that: after every committed step the cached
// unseen_count equals the live count, and the detach steps start at zero.
func TestPurgeMailboxStepKeepsUnseenCountExact(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	mailbox := createPurgeTestMailbox(t, db, accountID, "UnseenPurgeBox")
	for i, flags := range [][]imap.Flag{{}, {imap.FlagSeen}, {}, {imap.FlagSeen, imap.FlagFlagged}, {}} {
		inTx(t, db, func(tx pgx.Tx) {
			hash := fmt.Sprintf("unseen-purge-%d-%d", i, time.Now().UnixNano())
			_, _, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
				AccountID: accountID, MailboxID: mailbox, MailboxName: "UnseenPurgeBox",
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + hash + "@example.com>",
				Flags: flags, InternalDate: time.Now(), Size: 1024,
				Subject: "Unseen purge", PlaintextBody: "test", SentDate: time.Now(),
			}, PendingUpload{AccountID: accountID, ContentHash: hash})
			require.NoError(t, err)
		})
	}

	live := func() int64 {
		t.Helper()
		var n int64
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `SELECT `+liveUnseenCount("$1"), mailbox).Scan(&n))
		return n
	}
	detachedState := func() int {
		t.Helper()
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `
			SELECT COUNT(*) FROM message_state ms JOIN messages m ON m.id = ms.message_id
			WHERE m.account_id = $1 AND ms.mailbox_id IS NULL`, accountID).Scan(&n))
		return n
	}
	require.Equal(t, int64(3), readUnseenCount(ctx, t, db, mailbox))
	require.Equal(t, int64(3), live())

	done := false
	for i := 0; i < 50 && !done; i++ {
		inTx(t, db, func(tx pgx.Tx) {
			var err error
			done, err = db.PurgeMailboxStep(ctx, tx, mailbox, accountID, 1)
			require.NoError(t, err)
		})
		if done {
			break
		}
		require.Equal(t, live(), readUnseenCount(ctx, t, db, mailbox),
			"step %d: the cached unseen_count must equal the live count", i)
		if detachedState() > 0 {
			require.Zero(t, readUnseenCount(ctx, t, db, mailbox),
				"step %d: state rows are detached only once nothing in the mailbox is counted unseen", i)
		}
	}
	require.True(t, done, "the purge must complete in a bounded number of steps")
	require.Equal(t, 5, detachedState(), "every state row was detached, none deleted")
}
