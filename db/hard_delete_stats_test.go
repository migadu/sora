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

// hardDeleteMaxAttempts is the upload attempts limit the hard-delete tests run with.
const hardDeleteMaxAttempts = 5

// hardDeleteFixture is an account with an unseen bystander in INBOX and unseen messages
// with one lost body (its upload has used up its attempts) in some of INBOX and Archive.
type hardDeleteFixture struct {
	accountID int64
	inbox     *DBMailbox
	archive   *DBMailbox
	hash      string     // the lost body
	ids       []int64    // the messages with the lost body
	uids      []imap.UID // their UIDs, in the same order
}

func setupHardDeleteFixture(t *testing.T, db *Database, mailboxes ...string) hardDeleteFixture {
	t.Helper()
	ctx := context.Background()
	var f hardDeleteFixture
	email := fmt.Sprintf("hard_delete_%d@example.com", time.Now().UnixNano())
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		f.accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, f.accountID, "INBOX", nil))
		require.NoError(t, db.CreateMailbox(ctx, tx, f.accountID, "Archive", nil))
	})
	var err error
	f.inbox, err = db.GetMailboxByName(ctx, f.accountID, "INBOX")
	require.NoError(t, err)
	f.archive, err = db.GetMailboxByName(ctx, f.accountID, "Archive")
	require.NoError(t, err)

	insert := func(mbox *DBMailbox, hash string) (id int64, uid imap.UID) {
		inTx(t, db, func(tx pgx.Tx) {
			tag := fmt.Sprintf("%s-%d", hash, mbox.ID)
			opts := &InsertMessageOptions{
				AccountID: f.accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + tag + "@example.com>",
				Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
				Subject: "Hard delete", PlaintextBody: "test", SentDate: time.Now(),
			}
			var u int64
			var err error
			id, u, err = db.InsertMessage(ctx, tx, opts, PendingUpload{AccountID: f.accountID, ContentHash: hash})
			require.NoError(t, err)
			uid = imap.UID(u)
		})
		return id, uid
	}
	insert(f.inbox, fmt.Sprintf("hard-delete-bystander-%d", time.Now().UnixNano()))
	f.hash = fmt.Sprintf("hard-delete-lost-%d", time.Now().UnixNano())
	for _, name := range mailboxes {
		mbox := f.inbox
		if name == "Archive" {
			mbox = f.archive
		}
		id, uid := insert(mbox, f.hash)
		f.ids = append(f.ids, id)
		f.uids = append(f.uids, uid)
	}
	_, err = db.GetWritePool().Exec(ctx,
		`UPDATE pending_uploads SET attempts = $3 WHERE account_id = $1 AND content_hash = $2`,
		f.accountID, f.hash, hardDeleteMaxAttempts)
	require.NoError(t, err)

	for _, mbox := range []*DBMailbox{f.inbox, f.archive} {
		require.Equal(t, authoritativeUnseenCount(ctx, t, db, mbox.ID), readUnseenCount(ctx, t, db, mbox.ID),
			"mailbox %s before the delete", mbox.Name)
	}
	return f
}

// requireHardDeleteStats checks that INBOX and Archive have their cached counts right
// and that the bystander is still counted.
func requireHardDeleteStats(t *testing.T, db *Database, f hardDeleteFixture) {
	t.Helper()
	ctx := context.Background()
	for _, mbox := range []*DBMailbox{f.inbox, f.archive} {
		require.Equal(t, authoritativeUnseenCount(ctx, t, db, mbox.ID), readUnseenCount(ctx, t, db, mbox.ID),
			"mailbox %s: cached unseen_count drifted from the authoritative count", mbox.Name)
		var cached, live int64
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT COALESCE((SELECT message_count FROM mailbox_stats WHERE mailbox_id = $1), 0),
			       (SELECT count(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL)
		`, mbox.ID).Scan(&cached, &live))
		require.Equal(t, live, cached, "mailbox %s: cached message_count drifted from the live count", mbox.Name)
	}
	require.Equal(t, int64(1), readUnseenCount(ctx, t, db, f.inbox.ID), "the bystander stays unseen in INBOX")
}

// TestHardDeleteOfLiveMessageKeepsMailboxStats hard-deletes live, unseen messages through
// each path that does so, next to an unseen message that stays, and checks the cached
// mailbox counts against the authoritative ones.
//
// A DELETE on messages removes the message_state row by cascade before either statement
// trigger runs, so the messages trigger cannot read the flags and the message_state
// trigger cannot see that the message was live: a live message deleted directly stayed
// counted in unseen_count.
func TestHardDeleteOfLiveMessageKeepsMailboxStats(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tests := []struct {
		name      string
		mailboxes []string
		delete    func(t *testing.T, f hardDeleteFixture) int64
	}{
		{
			name:      "DeleteFailedUpload",
			mailboxes: []string{"INBOX", "Archive"},
			delete: func(t *testing.T, f hardDeleteFixture) (n int64) {
				inTx(t, db, func(tx pgx.Tx) {
					var err error
					n, err = db.DeleteFailedUpload(ctx, tx, f.hash, f.accountID, hardDeleteMaxAttempts)
					require.NoError(t, err)
				})
				return n
			},
		},
		{
			name:      "DeleteMessageByHashAndMailbox",
			mailboxes: []string{"INBOX"},
			delete: func(t *testing.T, f hardDeleteFixture) (n int64) {
				inTx(t, db, func(tx pgx.Tx) {
					var err error
					n, err = db.DeleteMessageByHashAndMailbox(ctx, tx, f.accountID, f.inbox.ID, f.hash)
					require.NoError(t, err)
				})
				return n
			},
		},
		{
			name:      "PurgeMessagesByIDs",
			mailboxes: []string{"INBOX", "Archive"},
			delete: func(t *testing.T, f hardDeleteFixture) int64 {
				n, err := db.PurgeMessagesByIDs(ctx, f.ids)
				require.NoError(t, err)
				return n
			},
		},
		{
			name:      "CleanupFailedUploads",
			mailboxes: []string{"INBOX", "Archive"},
			delete: func(t *testing.T, f hardDeleteFixture) int64 {
				_, err := db.GetWritePool().Exec(ctx,
					`UPDATE messages SET created_at = now() - interval '2 hours' WHERE account_id = $1 AND content_hash = $2`,
					f.accountID, f.hash)
				require.NoError(t, err)
				inTx(t, db, func(tx pgx.Tx) {
					_, err := db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
					require.NoError(t, err)
				})
				// The reaper works on the whole database; count only this test's rows.
				var left int64
				require.NoError(t, db.GetWritePool().QueryRow(ctx,
					`SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2`,
					f.accountID, f.hash).Scan(&left))
				return int64(len(f.ids)) - left
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := setupHardDeleteFixture(t, db, tc.mailboxes...)
			require.Equal(t, int64(len(f.ids)), tc.delete(t, f), "every live message with the lost body is deleted")
			requireHardDeleteStats(t, db, f)
		})
	}
}

// TestDeleteFailedUploadSerializesWithFlagChange races the uploader resolve's
// DeleteFailedUpload against a \Seen STORE on one of the unseen messages it deletes, the
// one in Archive. Unless the delete waits for the STORE's mailbox lock before it takes
// the message out of the counts, it reads the message as still unseen while the STORE's
// trigger has already charged the same message, and both decrement unseen_count.
func TestDeleteFailedUploadSerializesWithFlagChange(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	f := setupHardDeleteFixture(t, db, "INBOX", "Archive")

	// tx1: mark the Archive message \Seen and hold the transaction open.
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)
	_, _, err = db.AddMessageFlags(ctx, tx1, f.uids[1], f.archive.ID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	var pid2 int
	require.NoError(t, tx2.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid2))

	type deleteResult struct {
		n   int64
		err error
	}
	done := make(chan deleteResult, 1)
	go func() {
		n, err := db.DeleteFailedUpload(ctx, tx2, f.hash, f.accountID, hardDeleteMaxAttempts)
		done <- deleteResult{n: n, err: err}
	}()

	// tx2 must block on tx1 (with or without the mailbox lock it waits on some lock tx1
	// holds); committing tx1 before it got there would not race anything.
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
			t.Fatalf("DeleteFailedUpload finished without waiting for the concurrent STORE: %+v", res)
		default:
		}
		require.False(t, time.Now().After(deadline), "DeleteFailedUpload never waited on the concurrent STORE")
		time.Sleep(5 * time.Millisecond)
	}

	require.NoError(t, tx1.Commit(ctx))
	res := <-done
	require.NoError(t, res.err)
	require.Equal(t, int64(2), res.n, "both messages with the lost body are deleted")
	require.NoError(t, tx2.Commit(ctx))

	requireHardDeleteStats(t, db, f)
}
