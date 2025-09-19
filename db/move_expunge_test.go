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

// Database test helpers for move/expunge tests
func setupMoveExpungeTestDatabase(t *testing.T) (*Database, int64, int64, int64, imap.UID) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create source and destination mailboxes
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx2, accountID, "Sent", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox IDs
	srcMailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	destMailbox, err := db.GetMailboxByName(ctx, accountID, "Sent")
	require.NoError(t, err)

	// Insert a test message
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	now := time.Now()
	options := &InsertMessageOptions{
		UserID:        accountID,
		MailboxID:     srcMailbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/movetest",
		ContentHash:   "movetest123",
		MessageID:     "<movetest@example.com>",
		Flags:         []imap.Flag{imap.FlagSeen},
		InternalDate:  now,
		Size:          512,
		Subject:       "Move Test Message",
		PlaintextBody: "Test message for move operations",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "movetest123",
		InstanceID:  "test-instance",
		Size:        512,
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, uid, err := db.InsertMessage(ctx, tx3, options, upload)
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	return db, accountID, srcMailbox.ID, destMailbox.ID, imap.UID(uid)
}

// Helper function to get stats for a mailbox
func getMoveExpungeMailboxStats(t *testing.T, db *Database, ctx context.Context, mailboxID int64) (messageCount, unseenCount int, totalSize int64) {
	t.Helper()
	err := db.GetReadPool().QueryRow(ctx,
		"SELECT message_count, unseen_count, total_size FROM mailbox_stats WHERE mailbox_id = $1",
		mailboxID).Scan(&messageCount, &unseenCount, &totalSize)
	// If no row, stats are 0
	if err == pgx.ErrNoRows {
		return 0, 0, 0
	}
	require.NoError(t, err)
	return
}

// TestMoveMessages tests moving messages between mailboxes
func TestMoveMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, srcMailboxID, destMailboxID, messageUID := setupMoveExpungeTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Get initial stats
	srcMsgCountBefore, _, srcSizeBefore := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	destMsgCountBefore, _, destSizeBefore := getMoveExpungeMailboxStats(t, db, ctx, destMailboxID)
	assert.Equal(t, 1, srcMsgCountBefore)
	assert.Equal(t, int64(512), srcSizeBefore)

	// Test 1: Move message between mailboxes
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	uids := []imap.UID{messageUID}
	uidMapping, err := db.MoveMessages(ctx, tx, &uids, srcMailboxID, destMailboxID, accountID)
	assert.NoError(t, err)
	assert.NotEmpty(t, uidMapping)
	assert.Contains(t, uidMapping, messageUID)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify cache integrity after move
	srcMsgCountAfter, _, srcSizeAfter := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	destMsgCountAfter, _, destSizeAfter := getMoveExpungeMailboxStats(t, db, ctx, destMailboxID)

	assert.Equal(t, srcMsgCountBefore-1, srcMsgCountAfter, "Source message count should decrease")
	assert.Equal(t, srcSizeBefore-512, srcSizeAfter, "Source total size should decrease")
	assert.Equal(t, destMsgCountBefore+1, destMsgCountAfter, "Destination message count should increase")
	assert.Equal(t, destSizeBefore+512, destSizeAfter, "Destination total size should increase")

	var seqCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM message_sequences WHERE mailbox_id = $1", srcMailboxID).Scan(&seqCount)
	require.NoError(t, err)
	assert.Equal(t, 0, seqCount, "Source mailbox should have no entries in message_sequences")

	// Test 2: Verify message moved to destination
	destMessages, err := db.ListMessages(ctx, destMailboxID)
	assert.NoError(t, err)
	assert.Len(t, destMessages, 1)
	assert.Equal(t, "Move Test Message", destMessages[0].Subject)

	// Test 3: Verify message no longer in source (should be expunged)
	srcMessages, err := db.ListMessages(ctx, srcMailboxID)
	assert.NoError(t, err)
	assert.Empty(t, srcMessages) // Message should be moved out

	// Test 4: Try to move non-existent messages
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	nonExistentUIDs := []imap.UID{9999}
	uidMapping, err = db.MoveMessages(ctx, tx2, &nonExistentUIDs, srcMailboxID, destMailboxID, accountID)
	assert.NoError(t, err)
	assert.Empty(t, uidMapping) // No messages to move

	tx2.Rollback(ctx)

	t.Logf("Successfully tested MoveMessages with accountID: %d, srcMailbox: %d, destMailbox: %d", accountID, srcMailboxID, destMailboxID)
}

// TestExpungeMessageUIDs tests expunging messages by UID
func TestExpungeMessageUIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, srcMailboxID, _, messageUID := setupMoveExpungeTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First mark message as deleted
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	deletedFlags := []imap.Flag{imap.FlagSeen, imap.FlagDeleted}
	_, _, err = db.SetMessageFlags(ctx, tx, messageUID, srcMailboxID, deletedFlags)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get initial stats
	srcMsgCountBefore, _, _ := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	assert.Equal(t, 1, srcMsgCountBefore)

	// Test 1: Expunge the message
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	modSeq, err := db.ExpungeMessageUIDs(ctx, tx2, srcMailboxID, messageUID)
	assert.NoError(t, err)
	assert.Greater(t, modSeq, int64(0), "ModSeq should be positive when messages are expunged")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify cache integrity after expunge
	srcMsgCountAfter, _, _ := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	assert.Equal(t, srcMsgCountBefore-1, srcMsgCountAfter, "Message count should decrease after expunge")

	var seqCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM message_sequences WHERE mailbox_id = $1", srcMailboxID).Scan(&seqCount)
	require.NoError(t, err)
	assert.Equal(t, 0, seqCount, "Mailbox should have no entries in message_sequences after expunge")

	// Test 2: Verify message is expunged
	messages, err := db.ListMessages(ctx, srcMailboxID)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Message should be expunged

	// Test 3: Try to expunge non-existent message
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	modSeq2, err := db.ExpungeMessageUIDs(ctx, tx3, srcMailboxID, 9999)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), modSeq2, "ModSeq should be 0 when no messages are expunged")

	tx3.Rollback(ctx)

	t.Logf("Successfully tested ExpungeMessageUIDs with accountID: %d, mailboxID: %d, messageUID: %d", accountID, srcMailboxID, messageUID)
}

// TestCopyMessagesAdvanced tests advanced message copying scenarios
func TestCopyMessagesAdvanced(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, srcMailboxID, destMailboxID, messageUID := setupMoveExpungeTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Copy message to same mailbox (should fail)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	uids := []imap.UID{messageUID}
	_, err = db.CopyMessages(ctx, tx, &uids, srcMailboxID, srcMailboxID, accountID)
	assert.Error(t, err) // Should fail - same source and destination

	tx.Rollback(ctx)

	// Test 2: Copy message to different mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	// Get stats before copy
	srcMsgCountBefore, _, srcSizeBefore := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	destMsgCountBefore, _, destSizeBefore := getMoveExpungeMailboxStats(t, db, ctx, destMailboxID)

	uidMapping, err := db.CopyMessages(ctx, tx2, &uids, srcMailboxID, destMailboxID, accountID)
	assert.NoError(t, err)
	assert.NotEmpty(t, uidMapping)
	assert.Contains(t, uidMapping, messageUID)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify cache integrity after copy
	srcMsgCountAfter, _, srcSizeAfter := getMoveExpungeMailboxStats(t, db, ctx, srcMailboxID)
	destMsgCountAfter, _, destSizeAfter := getMoveExpungeMailboxStats(t, db, ctx, destMailboxID)

	assert.Equal(t, srcMsgCountBefore, srcMsgCountAfter, "Source message count should not change after copy")
	assert.Equal(t, srcSizeBefore, srcSizeAfter, "Source total size should not change after copy")
	assert.Equal(t, destMsgCountBefore+1, destMsgCountAfter, "Destination message count should increase after copy")
	assert.Equal(t, destSizeBefore+512, destSizeAfter, "Destination total size should increase after copy")

	// Test 3: Verify original message still exists
	srcMessages, err := db.ListMessages(ctx, srcMailboxID)
	assert.NoError(t, err)
	assert.Len(t, srcMessages, 1)

	// Test 4: Verify copy exists in destination
	destMessages, err := db.ListMessages(ctx, destMailboxID)
	assert.NoError(t, err)
	assert.Len(t, destMessages, 1)

	t.Logf("Successfully tested CopyMessagesAdvanced with accountID: %d, srcMailbox: %d, destMailbox: %d", accountID, srcMailboxID, destMailboxID)
}
