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

// sharedLegacyFixture is a shared mailbox of one account holding, besides the owner's own
// unseen message, an unseen legacy row of a soft-deleted account: before shared mailbox
// ownership landed (June 2026), a message someone else added to a shared mailbox carried
// that person's account_id.
type sharedLegacyFixture struct {
	shared    *DBMailbox
	deletedID int64    // the soft-deleted account
	legacyID  int64    // its message in the shared mailbox
	legacyUID imap.UID // uid of that message
}

func setupSharedLegacyFixture(t *testing.T, db *Database, withOwnMailbox bool) sharedLegacyFixture {
	t.Helper()
	ctx := context.Background()
	ts := time.Now().UnixNano()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	ownerID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("hard_delete_shared_owner_%d@example.com", ts),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, ownerID, "Shared", nil))
	var deletedID int64
	require.NoError(t, tx.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&deletedID))
	if withOwnMailbox {
		require.NoError(t, db.CreateMailbox(ctx, tx, deletedID, "INBOX", nil))
	}
	require.NoError(t, tx.Commit(ctx))
	shared, err := db.GetMailboxByName(ctx, ownerID, "Shared")
	require.NoError(t, err)

	insert := func(accountID int64, mbox *DBMailbox) (int64, imap.UID) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		tag := fmt.Sprintf("hard-delete-shared-%d-%d-%d", accountID, mbox.ID, time.Now().UnixNano())
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
			S3Domain: "example.com", S3Localpart: tag,
			ContentHash: tag, MessageID: "<" + tag + "@example.com>",
			Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
			Subject: "Hard delete shared race", PlaintextBody: "test", SentDate: time.Now(),
		}
		id, uid, err := db.InsertMessage(ctx, tx, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id, imap.UID(uid)
	}
	insert(ownerID, shared)
	legacyID, legacyUID := insert(deletedID, shared)

	f := sharedLegacyFixture{shared: shared, deletedID: deletedID, legacyID: legacyID, legacyUID: legacyUID}
	if withOwnMailbox {
		own, err := db.GetMailboxByName(ctx, deletedID, "INBOX")
		require.NoError(t, err)
		insert(deletedID, own)
	}

	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = now() WHERE id = $1`, deletedID)
	require.NoError(t, err)

	require.Equal(t, int64(2), readUnseenCount(ctx, t, db, shared.ID), "shared mailbox before")
	require.Equal(t, int64(2), authoritativeUnseenCount(ctx, t, db, shared.ID), "shared mailbox before")
	return f
}

// raceHardDeleteWithSeenStore holds a \Seen STORE on the legacy message open (tx1), runs
// hardDelete in tx2 until it waits on a lock tx1 holds, then commits tx1 and tx2, so the
// two stats triggers race exactly as in production.
func raceHardDeleteWithSeenStore(t *testing.T, db *Database, f sharedLegacyFixture, hardDelete func(ctx context.Context, tx pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()

	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)
	_, _, err = db.AddMessageFlags(ctx, tx1, f.legacyUID, f.shared.ID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	var pid2 int
	require.NoError(t, tx2.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid2))

	done := make(chan error, 1)
	go func() { done <- hardDelete(ctx, tx2) }()

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
		case err := <-done:
			t.Fatalf("the hard delete finished without waiting for the concurrent STORE: %v", err)
		default:
		}
		require.False(t, time.Now().After(deadline), "the hard delete never waited on the concurrent STORE")
		time.Sleep(5 * time.Millisecond)
	}

	require.NoError(t, tx1.Commit(ctx))
	require.NoError(t, <-done)
	require.NoError(t, tx2.Commit(ctx))

	// The shared mailbox keeps exactly its owner's unseen message: the legacy one was
	// read, then expunged.
	cached := readUnseenCount(ctx, t, db, f.shared.ID)
	actual := authoritativeUnseenCount(ctx, t, db, f.shared.ID)
	require.Equal(t, int64(1), actual, "shared mailbox: authoritative unseen count")
	require.Equal(t, actual, cached, "shared mailbox: cached unseen_count drifted from the authoritative count")

	var expunged bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT expunged_at IS NOT NULL FROM messages WHERE id = $1`, f.legacyID).Scan(&expunged))
	require.True(t, expunged, "the deleted account's legacy message should be expunged")
}

// TestHardDeleteAccountStepSerializesWithFlagChangeInSharedMailbox races the tail of the
// account hard delete step, which expunges the account's messages left in other accounts'
// mailboxes once it owns none, against the shared mailbox owner's \Seen STORE on such a
// message. Without the mailbox row lock the expunge does not wait for the STORE at its
// start: its stats trigger reads the message as still unseen and then queues on the
// mailbox_stats row behind the STORE, whose trigger has already charged the same message.
// Both decrement unseen_count.
func TestHardDeleteAccountStepSerializesWithFlagChangeInSharedMailbox(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()

	f := setupSharedLegacyFixture(t, db, false)
	raceHardDeleteWithSeenStore(t, db, f, func(ctx context.Context, tx pgx.Tx) error {
		done, err := db.HardDeleteAccountStep(ctx, tx, f.deletedID, 0)
		if err == nil && done {
			return fmt.Errorf("the step that expunged the legacy message reported done")
		}
		return err
	})

	// The next step finds nothing left and finishes the account.
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	done, err := db.HardDeleteAccountStep(ctx, tx, f.deletedID, 0)
	require.NoError(t, err)
	require.True(t, done)
	require.NoError(t, tx.Commit(ctx))
}

// TestHardDeleteAccountsSerializesWithFlagChangeInSharedMailbox is the same race against
// the one-transaction HardDeleteAccounts. The account also owns a mailbox, so the
// lock covers both the mailboxes it owns and the shared one its legacy row sits in.
func TestHardDeleteAccountsSerializesWithFlagChangeInSharedMailbox(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()

	f := setupSharedLegacyFixture(t, db, true)
	raceHardDeleteWithSeenStore(t, db, f, func(ctx context.Context, tx pgx.Tx) error {
		return db.HardDeleteAccounts(ctx, tx, []int64{f.deletedID})
	})

	ctx := context.Background()
	var live int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL`, f.deletedID).Scan(&live))
	require.Equal(t, 0, live, "every message of the deleted account should be expunged")
	var owned int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM mailboxes WHERE account_id = $1`, f.deletedID).Scan(&owned))
	require.Equal(t, 0, owned, "the deleted account's own mailboxes should be gone")
}
