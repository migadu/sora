//go:build integration
// +build integration

package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// TestExpungeMessagesByIDsSerializesWithFlagChange races ExpungeMessagesByIDs (sora-admin
// mailbox purge) against a \Seen STORE on the same unseen message. The purge expunges a
// mailbox and its children in one call, and the race is on the child, so every affected
// mailbox has to be locked, not only the first.
//
// Without the mailbox row lock the expunge does not wait for the STORE at its start: its
// stats trigger reads the message as still unseen and then queues on the mailbox_stats
// row behind the STORE, whose trigger has already charged the same message. Both
// decrement unseen_count, and the cache ends one below the real count.
func TestExpungeMessagesByIDsSerializesWithFlagChange(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	accountID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("purge_race_%d@example.com", time.Now().UnixNano()),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Purge", nil))
	require.NoError(t, tx.Commit(ctx))
	parent, err := db.GetMailboxByName(ctx, accountID, "Purge")
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Purge/Child", &parent.ID))
	require.NoError(t, tx.Commit(ctx))
	child, err := db.GetMailboxByName(ctx, accountID, "Purge/Child")
	require.NoError(t, err)

	// Two unseen messages in each mailbox.
	type msgRef struct {
		id  int64
		uid imap.UID
	}
	insert := func(mbox *DBMailbox, n int) msgRef {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		tag := fmt.Sprintf("purge-race-%d-%d-%d", mbox.ID, n, time.Now().UnixNano())
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
			S3Domain: "example.com", S3Localpart: tag,
			ContentHash: tag, MessageID: "<" + tag + "@example.com>",
			Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
			Subject: "Purge race", PlaintextBody: "test", SentDate: time.Now(),
		}
		id, uid, err := db.InsertMessage(ctx, tx, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return msgRef{id: id, uid: imap.UID(uid)}
	}
	parent1 := insert(parent, 1)
	insert(parent, 2)
	child1 := insert(child, 1)
	insert(child, 2)

	for _, mbox := range []*DBMailbox{parent, child} {
		require.Equal(t, int64(2), readUnseenCount(ctx, t, db, mbox.ID), "mailbox %s before", mbox.Name)
		require.Equal(t, int64(2), authoritativeUnseenCount(ctx, t, db, mbox.ID), "mailbox %s before", mbox.Name)
	}

	// tx1: mark the child's first message \Seen and hold the transaction open.
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)
	_, _, err = db.AddMessageFlags(ctx, tx1, child1.uid, child.ID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)

	// tx2: purge the first message of each mailbox, concurrently.
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	var pid2 int
	require.NoError(t, tx2.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid2))

	type expungeResult struct {
		n   int64
		err error
	}
	done := make(chan expungeResult, 1)
	go func() {
		n, err := db.ExpungeMessagesByIDs(ctx, tx2, []int64{parent1.id, child1.id})
		done <- expungeResult{n: n, err: err}
	}()

	// tx2 must block on tx1 (with or without the fix, it waits on some lock tx1 holds);
	// committing tx1 before it got there would not race anything.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) FROM pg_stat_activity WHERE pid = $1`,
			pid2).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case res := <-done:
			t.Fatalf("ExpungeMessagesByIDs finished without waiting for the concurrent STORE: %+v", res)
		default:
		}
		require.False(t, time.Now().After(deadline), "ExpungeMessagesByIDs never waited on the concurrent STORE")
		time.Sleep(5 * time.Millisecond)
	}

	require.NoError(t, tx1.Commit(ctx))
	res := <-done
	require.NoError(t, res.err)
	require.Equal(t, int64(2), res.n, "both messages should be newly expunged")
	require.NoError(t, tx2.Commit(ctx))

	// Each mailbox keeps exactly one unseen message: the parent's second (its first was
	// expunged unseen) and the child's second (its first was read, then expunged).
	for _, mbox := range []*DBMailbox{parent, child} {
		cached := readUnseenCount(ctx, t, db, mbox.ID)
		actual := authoritativeUnseenCount(ctx, t, db, mbox.ID)
		require.Equal(t, int64(1), actual, "mailbox %s: authoritative unseen count", mbox.Name)
		require.Equal(t, actual, cached, "mailbox %s: cached unseen_count drifted from the authoritative count", mbox.Name)
	}
}
