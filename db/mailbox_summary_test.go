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
func insertTestMessageWithUID(t *testing.T, db *Database, ctx context.Context, tx pgx.Tx, accountID, mailboxID int64, mailboxName string, uid uint32, flags []imap.Flag) {
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
		S3Localpart:   fmt.Sprintf("test/summary_test/%d", uid),
		ContentHash:   fmt.Sprintf("summarytest%d", uid),
		MessageID:     fmt.Sprintf("<summarytest%d@example.com>", uid),
		Flags:         flags,
		InternalDate:  now,
		Size:          1024,
		Subject:       fmt.Sprintf("Summary Test Message %d", uid),
		PlaintextBody: "body",
		RawHeaders:    "headers",
		SentDate:      now,
		PreservedUID:  &uid, // Use the provided UID
		BodyStructure: &bs,  // Add a non-nil body structure
	}

	_, _, err := db.InsertMessageFromImporter(ctx, tx, options)
	require.NoError(t, err, "failed to insert test message with UID %d", uid)
}

func TestGetMailboxSummaryFirstUnseen(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	testEmail := fmt.Sprintf("test_summary_%d@example.com", time.Now().UnixNano())
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

	// --- Scenario 1: Empty mailbox ---
	t.Run("EmptyMailbox", func(t *testing.T) {
		summary, err := db.GetMailboxSummary(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 0, summary.UnseenCount, "UnseenCount should be 0 for empty mailbox")
		assert.Equal(t, uint32(0), summary.FirstUnseenSeqNum, "FirstUnseenSeqNum should be 0 for empty mailbox")
	})

	// --- Scenario 2: All messages are seen ---
	t.Run("AllMessagesSeen", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, []imap.Flag{imap.FlagSeen})
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, []imap.Flag{imap.FlagSeen})
		require.NoError(t, tx.Commit(ctx))

		summary, err := db.GetMailboxSummary(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 0, summary.UnseenCount, "UnseenCount should be 0 when all messages are seen")
		assert.Equal(t, uint32(0), summary.FirstUnseenSeqNum, "FirstUnseenSeqNum should be 0 when all messages are seen")

		// Cleanup for next scenario
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 3: All messages are unseen ---
	t.Run("AllMessagesUnseen", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, []imap.Flag{})
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, []imap.Flag{})
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, []imap.Flag{})
		require.NoError(t, tx.Commit(ctx))

		// Directly verify cache table
		var msgCount, unseenCount int
		err = db.GetReadPool().QueryRow(ctx, "SELECT message_count, unseen_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&msgCount, &unseenCount)
		require.NoError(t, err)
		assert.Equal(t, 3, msgCount, "Cache should have 3 messages")
		assert.Equal(t, 3, unseenCount, "Cache should have 3 unseen messages")

		summary, err := db.GetMailboxSummary(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 3, summary.UnseenCount, "UnseenCount should be 3")
		assert.Equal(t, uint32(1), summary.FirstUnseenSeqNum, "FirstUnseenSeqNum should be 1 when all are unseen")

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})

	// --- Scenario 4: First unseen message is in the middle ---
	t.Run("FirstUnseenInMiddle", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, []imap.Flag{imap.FlagSeen}) // Seq 1
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, []imap.Flag{imap.FlagSeen}) // Seq 2
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, []imap.Flag{})              // Seq 3 (First Unseen)
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 40, []imap.Flag{imap.FlagSeen}) // Seq 4
		insertTestMessageWithUID(t, db, ctx, tx, accountID, mailboxID, "INBOX", 50, []imap.Flag{})              // Seq 5
		require.NoError(t, tx.Commit(ctx))

		// Directly verify cache table
		var msgCount, unseenCount int
		err = db.GetReadPool().QueryRow(ctx, "SELECT message_count, unseen_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&msgCount, &unseenCount)
		require.NoError(t, err)
		assert.Equal(t, 5, msgCount, "Cache should have 5 messages")
		assert.Equal(t, 2, unseenCount, "Cache should have 2 unseen messages")

		summary, err := db.GetMailboxSummary(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 2, summary.UnseenCount, "UnseenCount should be 2")
		assert.Equal(t, uint32(3), summary.FirstUnseenSeqNum, "FirstUnseenSeqNum should be 3 (pointing to UID 30)")

		// Cleanup
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM messages WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	})
}
