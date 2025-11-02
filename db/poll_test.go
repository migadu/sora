package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to insert a test message with specific UID and flags.
// This uses InsertMessageFromImporter to control the UID.
func insertTestMessageWithUIDForPoll(t *testing.T, db *Database, ctx context.Context, tx pgx.Tx, accountID, mailboxID int64, mailboxName string, uid uint32, flags []imap.Flag) {
	t.Helper()

	// Create a default body structure to avoid nil pointer panics during serialization.
	defaultBodyStructure := &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Size:    1024,
	}
	var bs imap.BodyStructure = defaultBodyStructure
	now := time.Now()
	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   fmt.Sprintf("test/poll_test/%d", uid),
		ContentHash:   fmt.Sprintf("polltest%d", uid),
		MessageID:     fmt.Sprintf("<polltest%d@example.com>", uid),
		Flags:         flags,
		InternalDate:  now,
		Size:          1024,
		Subject:       fmt.Sprintf("Poll Test Message %d", uid),
		PlaintextBody: "body",
		RawHeaders:    "headers",
		SentDate:      now,
		PreservedUID:  &uid, // Use the provided UID
		BodyStructure: &bs,  // Add a non-nil body structure
	}

	_, _, err := db.InsertMessageFromImporter(ctx, tx, options)
	require.NoError(t, err, "failed to insert test message with UID %d", uid)
}

// Helper to get the highest modseq for a mailbox from the cache table.
func getHighestModSeq(t *testing.T, db *Database, ctx context.Context, mailboxID int64) uint64 {
	t.Helper()
	var modseq uint64
	err := db.GetReadPool().QueryRow(ctx, "SELECT highest_modseq FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&modseq)
	if err == pgx.ErrNoRows {
		return 0
	}
	require.NoError(t, err)
	return modseq
}

func TestPollMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	testEmail := fmt.Sprintf("test_poll_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	err = db.CreateAccount(ctx, tx, req)
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

		poll, err := db.PollMailbox(ctx, mailboxID, modSeq)
		require.NoError(t, err)
		assert.Empty(t, poll.Updates, "Should be no updates when polling with current modseq")
		assert.Equal(t, uint32(1), poll.NumMessages)
		assert.Equal(t, modSeq, poll.ModSeq)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 2: New Message ---
	t.Run("NewMessage", func(t *testing.T) {
		modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, nil)
		require.NoError(t, tx.Commit(ctx))

		poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
		require.NoError(t, err)
		require.Len(t, poll.Updates, 1)
		update := poll.Updates[0]
		assert.False(t, update.IsExpunge)
		assert.Equal(t, imap.UID(20), update.UID)
		assert.Equal(t, uint32(1), update.SeqNum)
		assert.Equal(t, uint32(1), poll.NumMessages)
		assert.Greater(t, poll.ModSeq, modSeqBefore)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 3: Flag Update ---
	t.Run("FlagUpdate", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, nil)
		require.NoError(t, tx.Commit(ctx))

		modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, _, err = db.AddMessageFlags(ctx, tx, 30, mailboxID, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
		require.NoError(t, err)
		require.Len(t, poll.Updates, 1)
		update := poll.Updates[0]
		assert.False(t, update.IsExpunge)
		assert.Equal(t, imap.UID(30), update.UID)
		assert.Equal(t, uint32(1), update.SeqNum)
		assert.True(t, ContainsFlag(update.BitwiseFlags, FlagSeen))
		assert.Equal(t, uint32(1), poll.NumMessages)
		assert.Greater(t, poll.ModSeq, modSeqBefore)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 4: Expunged Message ---
	t.Run("ExpungedMessage", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 40, nil) // seq 1
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 50, nil) // seq 2
		require.NoError(t, tx.Commit(ctx))

		modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, 40)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
		require.NoError(t, err)
		require.Len(t, poll.Updates, 1)
		update := poll.Updates[0]
		assert.True(t, update.IsExpunge)
		assert.Equal(t, imap.UID(40), update.UID)
		assert.Equal(t, uint32(1), update.SeqNum, "SeqNum should be the original sequence number of the expunged message")
		assert.Equal(t, uint32(1), poll.NumMessages, "NumMessages should be the new total after expunge")
		assert.Greater(t, poll.ModSeq, modSeqBefore)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 5: Mixed Changes ---
	t.Run("MixedChanges", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 100, nil) // seq 1
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 110, nil) // seq 2
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 120, nil) // seq 3
		require.NoError(t, tx.Commit(ctx))

		modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		// Expunge UID 110 (original seq 2)
		_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, 110)
		require.NoError(t, err)
		// Update flags on UID 120 (original seq 3)
		_, _, err = db.AddMessageFlags(ctx, tx, 120, mailboxID, []imap.Flag{imap.FlagFlagged})
		require.NoError(t, err)
		// Insert new message
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 130, nil)
		require.NoError(t, tx.Commit(ctx))

		poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
		require.NoError(t, err)
		require.Len(t, poll.Updates, 3, "Should have 3 updates: 1 expunge, 1 flag change, 1 new message")

		// The query orders expunges first, then other updates.
		// Expunge of UID 110 (original seq 2)
		expungeUpdate := poll.Updates[0]
		assert.True(t, expungeUpdate.IsExpunge)
		assert.Equal(t, imap.UID(110), expungeUpdate.UID)
		assert.Equal(t, uint32(2), expungeUpdate.SeqNum)

		// Flag update of UID 120 (original seq 3, new seq 2)
		flagUpdate := poll.Updates[1]
		assert.False(t, flagUpdate.IsExpunge)
		assert.Equal(t, imap.UID(120), flagUpdate.UID)
		assert.Equal(t, uint32(2), flagUpdate.SeqNum)
		assert.True(t, ContainsFlag(flagUpdate.BitwiseFlags, FlagFlagged))

		// New message UID 130 (new seq 3)
		newMsgUpdate := poll.Updates[2]
		assert.False(t, newMsgUpdate.IsExpunge)
		assert.Equal(t, imap.UID(130), newMsgUpdate.UID)
		assert.Equal(t, uint32(3), newMsgUpdate.SeqNum)

		assert.Equal(t, uint32(3), poll.NumMessages, "Final message count should be 3")
		assert.Greater(t, poll.ModSeq, modSeqBefore)

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})
}
