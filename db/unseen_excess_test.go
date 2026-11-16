//go:build integration
// +build integration

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

// TestFindExcessUnseenCounts covers the drift that hard deletes before #1564 left: a live
// unseen message deleted directly stayed counted in unseen_count. The self-heal only
// recomputes a negative count, so the scan must find the mailboxes whose cached count is
// above the authoritative one, batch by batch, and nothing else.
func TestFindExcessUnseenCounts(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	var accountID int64
	mailboxes := map[string]*DBMailbox{}
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:    fmt.Sprintf("unseen_excess_%d@example.com", time.Now().UnixNano()),
			Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		for _, name := range []string{"INBOX", "Drifted", "Below"} {
			require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
		}
	})
	for _, name := range []string{"INBOX", "Drifted", "Below"} {
		mbox, err := db.GetMailboxByName(ctx, accountID, name)
		require.NoError(t, err)
		mailboxes[name] = mbox
	}
	insertUnseen := func(mbox *DBMailbox, n int) (ids []int64) {
		for i := 0; i < n; i++ {
			inTx(t, db, func(tx pgx.Tx) {
				hash := fmt.Sprintf("unseen-excess-%d", time.Now().UnixNano())
				id, _, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
					AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
					S3Domain: "example.com", S3Localpart: "user",
					ContentHash: hash, MessageID: "<" + hash + "@example.com>",
					Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
					Subject: "Unseen", PlaintextBody: "test", SentDate: time.Now(),
				}, PendingUpload{AccountID: accountID, ContentHash: hash})
				require.NoError(t, err)
				ids = append(ids, id)
			})
		}
		return ids
	}

	// INBOX is right: two unseen messages, counted two.
	insertUnseen(mailboxes["INBOX"], 2)
	// Drifted: two of its three unseen messages are deleted the way the hard deletes
	// before #1564 did, which leaves them counted.
	drifted := insertUnseen(mailboxes["Drifted"], 3)
	_, err := db.GetWritePool().Exec(ctx, `DELETE FROM messages WHERE id = ANY($1)`, drifted[:2])
	require.NoError(t, err)
	require.Equal(t, int64(3), readUnseenCount(ctx, t, db, mailboxes["Drifted"].ID))
	require.Equal(t, int64(1), authoritativeUnseenCount(ctx, t, db, mailboxes["Drifted"].ID))
	// Below has drifted the other way, which the self-heal handles once it goes negative.
	insertUnseen(mailboxes["Below"], 2)
	_, err = db.GetWritePool().Exec(ctx,
		`UPDATE mailbox_stats SET unseen_count = unseen_count - 1 WHERE mailbox_id = $1`, mailboxes["Below"].ID)
	require.NoError(t, err)

	want := []MailboxUnseenExcess{{
		MailboxID: mailboxes["Drifted"].ID, AccountID: accountID, Name: "Drifted", Cached: 3, Actual: 1,
	}}

	// scan pages through the account's mailboxes limit at a time, as the repair does.
	scan := func(limit int) (excess []MailboxUnseenExcess, checked []int64) {
		t.Helper()
		var after int64
		for {
			batch, err := db.FindExcessUnseenCounts(ctx, accountID, after, limit)
			require.NoError(t, err)
			require.LessOrEqual(t, batch.Checked, limit)
			excess = append(excess, batch.Excess...)
			if batch.Checked == 0 {
				return excess, checked
			}
			require.Greater(t, batch.LastMailboxID, after, "the batches move forward")
			after = batch.LastMailboxID
			checked = append(checked, after)
		}
	}

	t.Run("one batch", func(t *testing.T) {
		excess, _ := scan(100)
		require.Equal(t, want, excess)
	})
	t.Run("batches of one", func(t *testing.T) {
		excess, checked := scan(1)
		require.Equal(t, want, excess)
		require.Equal(t, []int64{mailboxes["INBOX"].ID, mailboxes["Drifted"].ID, mailboxes["Below"].ID}, checked,
			"each mailbox with unseen messages is checked once, in id order")
	})
	t.Run("all accounts", func(t *testing.T) {
		batch, err := db.FindExcessUnseenCounts(ctx, 0, mailboxes["Drifted"].ID-1, 1)
		require.NoError(t, err)
		require.Equal(t, want, batch.Excess)
	})
	t.Run("repaired", func(t *testing.T) {
		inTx(t, db, func(tx pgx.Tx) {
			unseen, err := db.RecomputeMailboxUnseen(ctx, tx, mailboxes["Drifted"].ID)
			require.NoError(t, err)
			require.Equal(t, int64(1), unseen)
		})
		excess, _ := scan(100)
		require.Empty(t, excess)
	})
}
