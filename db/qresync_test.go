package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMessagesChangedSince(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	testEmail := fmt.Sprintf("test_qresync_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// --- Scenario 1: No changes ---
	t.Run("NoChanges", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, nil)
		require.NoError(t, tx.Commit(ctx))

		modSeq := getHighestModSeq(t, db, ctx, mailboxID)
		require.Greater(t, modSeq, uint64(0))

		changed, err := db.GetMessagesChangedSince(ctx, mailboxID, modSeq)
		require.NoError(t, err)
		assert.Empty(t, changed, "Should be no changes since current modseq")

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 2: Sparse sequence hydration with changes ---
	t.Run("SparseSequenceHydration", func(t *testing.T) {
		// Set up initial state with 3 messages
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, nil) // Seq 1
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, nil) // Seq 2
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, nil) // Seq 3
		require.NoError(t, tx.Commit(ctx))

		modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

		// Modify UID 20 to change its flags
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, _, err = db.AddMessageFlags(ctx, tx, 20, mailboxID, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		// Query changes since modSeqBefore. Only UID 20 should be returned.
		changed, err := db.GetMessagesChangedSince(ctx, mailboxID, modSeqBefore)
		require.NoError(t, err)
		require.Len(t, changed, 1)

		msg := changed[0]
		assert.Equal(t, imap.UID(20), msg.UID)
		assert.Equal(t, uint32(2), msg.SeqNum, "SeqNum should be 2 despite sparse returned list")
		assert.Contains(t, msg.Flags, imap.FlagSeen)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 3: Sequence hydration after expunge ---
	t.Run("SequenceHydrationAfterExpunge", func(t *testing.T) {
		// Set up initial state with 3 messages
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 100, nil) // Seq 1
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 110, nil) // Seq 2
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 120, nil) // Seq 3
		require.NoError(t, tx.Commit(ctx))

		modSeqBeforeExpunge := getHighestModSeq(t, db, ctx, mailboxID)

		// Expunge UID 110 (original Seq 2)
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, 110)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		// Modify UID 120 (was original Seq 3, is now Seq 2)
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, _, err = db.AddMessageFlags(ctx, tx, 120, mailboxID, []imap.Flag{imap.FlagFlagged})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		// Query changes since modSeqBeforeExpunge. Only UID 120 should be returned as changed.
		changed, err := db.GetMessagesChangedSince(ctx, mailboxID, modSeqBeforeExpunge)
		require.NoError(t, err)
		require.Len(t, changed, 1)

		msg := changed[0]
		assert.Equal(t, imap.UID(120), msg.UID)
		assert.Equal(t, uint32(2), msg.SeqNum, "SeqNum of UID 120 should be 2 after UID 110 was expunged")
		assert.Contains(t, msg.Flags, imap.FlagFlagged)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})
}
