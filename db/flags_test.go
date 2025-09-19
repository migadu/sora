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

// Database test helpers for flag tests
func setupFlagTestDatabase(t *testing.T) (*Database, int64, int64, imap.UID) {
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

	// Create test mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox ID
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// Insert a test message
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	now := time.Now()
	options := &InsertMessageOptions{
		UserID:        accountID,
		MailboxID:     mailbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/flagtest",
		ContentHash:   "flagtest123",
		MessageID:     "<flagtest@example.com>",
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          512,
		Subject:       "Flag Test Message",
		PlaintextBody: "Test message for flag operations",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "flagtest123",
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

	return db, accountID, mailbox.ID, imap.UID(uid)
}

// Helper function to get stats for a mailbox
func getMailboxStats(t *testing.T, db *Database, ctx context.Context, mailboxID int64) (messageCount, unseenCount int, totalSize int64) {
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

// TestSetMessageFlags tests setting message flags
func TestSetMessageFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUID := setupFlagTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Initial state: 1 message, unseen.
	_, unseenBefore, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 1, unseenBefore, "Message should be initially unseen")

	// Test 1: Set flags on message
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	newFlags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged}
	updatedFlags, modSeq, err := db.SetMessageFlags(ctx, tx, messageUID, mailboxID, newFlags)
	assert.NoError(t, err)
	assert.ElementsMatch(t, newFlags, updatedFlags)
	assert.Greater(t, modSeq, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should be 0 now
	_, unseenAfter, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfter, "Unseen count should be 0 after setting \\Seen flag")

	// Test 2: Verify flags were set
	messages, err := db.GetMessagesByFlag(ctx, mailboxID, imap.FlagSeen)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, messageUID, messages[0].UID)

	t.Logf("Successfully tested SetMessageFlags with accountID: %d, mailboxID: %d, messageUID: %d", accountID, mailboxID, uint32(messageUID))
}

// TestAddMessageFlags tests adding message flags
func TestAddMessageFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUID := setupFlagTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Initial state: 1 message, unseen.
	_, unseenBefore, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 1, unseenBefore, "Message should be initially unseen")

	// Test 1: Add initial flags
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	initialFlags := []imap.Flag{imap.FlagSeen}
	updatedFlags, modSeq, err := db.AddMessageFlags(ctx, tx, messageUID, mailboxID, initialFlags)
	assert.NoError(t, err)
	assert.Contains(t, updatedFlags, imap.FlagSeen)
	assert.Greater(t, modSeq, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should be 0
	_, unseenAfterAdd, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfterAdd, "Unseen count should be 0 after adding \\Seen flag")

	// Test 2: Add additional flags
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	additionalFlags := []imap.Flag{imap.FlagFlagged}
	updatedFlags, modSeq2, err := db.AddMessageFlags(ctx, tx2, messageUID, mailboxID, additionalFlags)
	assert.NoError(t, err)
	assert.Contains(t, updatedFlags, imap.FlagSeen)
	assert.Contains(t, updatedFlags, imap.FlagFlagged)
	assert.Greater(t, modSeq2, modSeq)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should still be 0
	_, unseenAfterAdd2, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfterAdd2, "Unseen count should remain 0 after adding non-seen flag")

	t.Logf("Successfully tested AddMessageFlags with accountID: %d, mailboxID: %d, messageUID: %d", accountID, mailboxID, uint32(messageUID))
}

// TestRemoveMessageFlags tests removing message flags
func TestRemoveMessageFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUID := setupFlagTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First set some flags
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	initialFlags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagAnswered}
	_, _, err = db.SetMessageFlags(ctx, tx, messageUID, mailboxID, initialFlags)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should be 0
	_, unseenAfterSet, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfterSet, "Unseen count should be 0 after setting initial flags")

	// Test: Remove some flags
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	flagsToRemove := []imap.Flag{imap.FlagFlagged}
	updatedFlags, modSeq, err := db.RemoveMessageFlags(ctx, tx2, messageUID, mailboxID, flagsToRemove)
	assert.NoError(t, err)
	assert.Contains(t, updatedFlags, imap.FlagSeen)
	assert.Contains(t, updatedFlags, imap.FlagAnswered)
	assert.NotContains(t, updatedFlags, imap.FlagFlagged)
	assert.Greater(t, modSeq, int64(0))

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should still be 0
	_, unseenAfterRemove1, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfterRemove1, "Unseen count should remain 0 after removing non-seen flag")

	// Test 2: Remove the \Seen flag
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	_, _, err = db.RemoveMessageFlags(ctx, tx3, messageUID, mailboxID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// Verify cache: unseen count should be 1 again
	_, unseenAfterRemove2, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 1, unseenAfterRemove2, "Unseen count should be 1 after removing \\Seen flag")

	t.Logf("Successfully tested RemoveMessageFlags with accountID: %d, mailboxID: %d, messageUID: %d", accountID, mailboxID, uint32(messageUID))
}

// TestGetUniqueCustomFlagsForMailbox tests custom flag retrieval
func TestGetUniqueCustomFlagsForMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUID := setupFlagTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Mailbox with no custom flags
	customFlags, err := db.GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Empty(t, customFlags)

	// Test 2: Add some custom flags
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	flagsWithCustom := []imap.Flag{imap.FlagSeen, imap.Flag("CustomFlag1"), imap.Flag("CustomFlag2")}
	_, _, err = db.SetMessageFlags(ctx, tx, messageUID, mailboxID, flagsWithCustom)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Retrieve custom flags
	customFlags, err = db.GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Contains(t, customFlags, "CustomFlag1")
	assert.Contains(t, customFlags, "CustomFlag2")
	assert.NotContains(t, customFlags, "\\Seen") // Standard flags should not be included

	t.Logf("Successfully tested GetUniqueCustomFlagsForMailbox with accountID: %d, mailboxID: %d", accountID, mailboxID)
}
