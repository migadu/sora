package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRestoreTestDatabase creates a test account with mailboxes and messages
func setupRestoreTestDatabase(t *testing.T) (*Database, int64, string, int64, int64) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("restore_test_%d@example.com", time.Now().UnixNano())

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

	// Create mailboxes
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
	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	sent, err := db.GetMailboxByName(ctx, accountID, "Sent")
	require.NoError(t, err)

	return db, accountID, testEmail, inbox.ID, sent.ID
}

// insertTestMessage inserts a test message into a mailbox
func insertTestMessage(t *testing.T, db *Database, accountID, mailboxID int64, mailboxName, subject, messageID string) int64 {
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()
	options := &InsertMessageOptions{
		UserID:        accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   fmt.Sprintf("hash_%s", messageID),
		MessageID:     messageID,
		Flags:         []imap.Flag{imap.FlagSeen},
		InternalDate:  now,
		Size:          512,
		Subject:       subject,
		PlaintextBody: fmt.Sprintf("Test message body for %s", subject),
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: options.ContentHash,
		InstanceID:  "test-instance",
		Size:        512,
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	msgID, _, err := db.InsertMessage(ctx, tx, options, upload)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	return msgID
}

// expungeMessage marks a message as expunged
func expungeMessage(t *testing.T, db *Database, mailboxID int64, uid imap.UID) {
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, uid)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)
}

// TestRestoreMessages_ByMessageIDs tests restoring specific messages by their IDs
func TestRestoreMessages_ByMessageIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert test messages
	msgID1 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Test Message 1", "<msg1@example.com>")
	msgID2 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Test Message 2", "<msg2@example.com>")
	msgID3 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Test Message 3", "<msg3@example.com>")

	// Get UIDs for expunging
	var uid1, uid2, uid3 imap.UID
	err := db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID1).Scan(&uid1)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID2).Scan(&uid2)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID3).Scan(&uid3)
	require.NoError(t, err)

	// Expunge messages 1 and 2
	expungeMessage(t, db, inboxID, uid1)
	expungeMessage(t, db, inboxID, uid2)

	// Verify messages are expunged
	var expungedCount int
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NOT NULL",
		accountID).Scan(&expungedCount)
	require.NoError(t, err)
	assert.Equal(t, 2, expungedCount)

	// List deleted messages (wait a moment to ensure messages are committed)
	time.Sleep(100 * time.Millisecond)

	listParams := ListDeletedMessagesParams{
		Email: testEmail,
		Limit: 100,
	}
	t.Logf("Listing deleted messages for email: %q", testEmail)
	deletedMessages, err := db.ListDeletedMessages(ctx, listParams)
	if err != nil {
		t.Logf("ListDeletedMessages error: %v", err)
	}
	require.NoError(t, err)
	assert.Len(t, deletedMessages, 2)

	// Verify the deleted messages have the correct data
	for _, msg := range deletedMessages {
		assert.NotZero(t, msg.ID)
		assert.NotZero(t, msg.ExpungedAt)
		assert.Equal(t, "INBOX", msg.MailboxPath)
		assert.Contains(t, []string{"Test Message 1", "Test Message 2"}, msg.Subject)
	}

	// Restore only message 1 by ID
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	restoreParams := RestoreMessagesParams{
		Email:      testEmail,
		MessageIDs: []int64{msgID1},
	}
	restoredCount, err := db.RestoreMessages(ctx, tx, restoreParams)
	require.NoError(t, err)
	assert.Equal(t, int64(1), restoredCount)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify message 1 is restored (expunged_at is NULL)
	var expungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", msgID1).Scan(&expungedAt)
	require.NoError(t, err)
	assert.Nil(t, expungedAt, "Message 1 should be restored (expunged_at should be NULL)")

	// Verify message 2 is still deleted
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", msgID2).Scan(&expungedAt)
	require.NoError(t, err)
	assert.NotNil(t, expungedAt, "Message 2 should still be deleted")

	// Verify message 3 was never deleted
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", msgID3).Scan(&expungedAt)
	require.NoError(t, err)
	assert.Nil(t, expungedAt, "Message 3 should never have been deleted")

	// Verify the restored message got a new UID
	var newUID imap.UID
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID1).Scan(&newUID)
	require.NoError(t, err)
	assert.NotEqual(t, uid1, newUID, "Restored message should have a new UID")
}

// TestRestoreMessages_ByMailbox tests restoring all deleted messages from a specific mailbox
func TestRestoreMessages_ByMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, sentID := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert test messages in both mailboxes
	inboxMsgID1 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Inbox Message 1", "<inbox1@example.com>")
	inboxMsgID2 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Inbox Message 2", "<inbox2@example.com>")
	sentMsgID1 := insertTestMessage(t, db, accountID, sentID, "Sent", "Sent Message 1", "<sent1@example.com>")

	// Get UIDs
	var inboxUID1, inboxUID2, sentUID1 imap.UID
	err := db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", inboxMsgID1).Scan(&inboxUID1)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", inboxMsgID2).Scan(&inboxUID2)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", sentMsgID1).Scan(&sentUID1)
	require.NoError(t, err)

	// Expunge all messages
	expungeMessage(t, db, inboxID, inboxUID1)
	expungeMessage(t, db, inboxID, inboxUID2)
	expungeMessage(t, db, sentID, sentUID1)

	// Verify all messages are expunged
	var expungedCount int
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NOT NULL",
		accountID).Scan(&expungedCount)
	require.NoError(t, err)
	assert.Equal(t, 3, expungedCount)

	// Restore only INBOX messages
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	mailboxPath := "INBOX"
	restoreParams := RestoreMessagesParams{
		Email:       testEmail,
		MailboxPath: &mailboxPath,
	}
	restoredCount, err := db.RestoreMessages(ctx, tx, restoreParams)
	require.NoError(t, err)
	assert.Equal(t, int64(2), restoredCount, "Should restore 2 INBOX messages")

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify INBOX messages are restored
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id = $2 AND expunged_at IS NULL",
		accountID, inboxID).Scan(&expungedCount)
	require.NoError(t, err)
	assert.Equal(t, 2, expungedCount, "Both INBOX messages should be restored")

	// Verify Sent message is still deleted
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id = $2 AND expunged_at IS NOT NULL",
		accountID, sentID).Scan(&expungedCount)
	require.NoError(t, err)
	assert.Equal(t, 1, expungedCount, "Sent message should still be deleted")
}

// TestRestoreMessages_RecreateMailbox tests restoring messages when the original mailbox was deleted
func TestRestoreMessages_RecreateMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert a test message
	msgID := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Test Message", "<test@example.com>")

	// Get UID
	var uid imap.UID
	err := db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID).Scan(&uid)
	require.NoError(t, err)

	// Expunge the message
	expungeMessage(t, db, inboxID, uid)

	// Delete the INBOX mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.DeleteMailbox(ctx, tx, inboxID, accountID)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify mailbox is deleted
	var mailboxExists bool
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id = $1)", inboxID).Scan(&mailboxExists)
	require.NoError(t, err)
	assert.False(t, mailboxExists, "INBOX should be deleted")

	// Verify message has mailbox_id set to NULL but mailbox_path preserved
	var mailboxID *int64
	var mailboxPath string
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT mailbox_id, mailbox_path FROM messages WHERE id = $1", msgID).Scan(&mailboxID, &mailboxPath)
	require.NoError(t, err)
	assert.Nil(t, mailboxID, "Message mailbox_id should be NULL after mailbox deletion")
	assert.Equal(t, "INBOX", mailboxPath, "Message mailbox_path should be preserved")

	// Restore the message
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	restoreParams := RestoreMessagesParams{
		Email:      testEmail,
		MessageIDs: []int64{msgID},
	}
	restoredCount, err := db.RestoreMessages(ctx, tx2, restoreParams)
	require.NoError(t, err)
	assert.Equal(t, int64(1), restoredCount)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify mailbox was recreated
	recreatedInbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	assert.NotNil(t, recreatedInbox)
	assert.NotEqual(t, inboxID, recreatedInbox.ID, "Recreated mailbox should have a new ID")

	// Verify message is restored to the new mailbox
	var restoredMailboxID int64
	var expungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT mailbox_id, expunged_at FROM messages WHERE id = $1", msgID).Scan(&restoredMailboxID, &expungedAt)
	require.NoError(t, err)
	assert.Equal(t, recreatedInbox.ID, restoredMailboxID, "Message should be in the recreated mailbox")
	assert.Nil(t, expungedAt, "Message should be restored (expunged_at should be NULL)")
}

// TestRestoreMessages_ByTimeRange tests restoring messages deleted within a time range
func TestRestoreMessages_ByTimeRange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert test messages
	msgID1 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Old Message", "<old@example.com>")
	msgID2 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Recent Message", "<recent@example.com>")

	// Get UIDs
	var uid1, uid2 imap.UID
	err := db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID1).Scan(&uid1)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", msgID2).Scan(&uid2)
	require.NoError(t, err)

	// Expunge first message
	expungeMessage(t, db, inboxID, uid1)

	// Manually set expunged_at to simulate old deletion
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err = db.GetWritePool().Exec(ctx,
		"UPDATE messages SET expunged_at = $1 WHERE id = $2", oldTime, msgID1)
	require.NoError(t, err)

	// Wait a moment to ensure time difference
	time.Sleep(100 * time.Millisecond)

	// Expunge second message (will have recent expunged_at)
	expungeMessage(t, db, inboxID, uid2)

	// Restore only messages deleted in the last 24 hours
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	since := time.Now().Add(-24 * time.Hour)
	restoreParams := RestoreMessagesParams{
		Email: testEmail,
		Since: &since,
	}
	restoredCount, err := db.RestoreMessages(ctx, tx, restoreParams)
	require.NoError(t, err)
	assert.Equal(t, int64(1), restoredCount, "Should restore only the recently deleted message")

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify only message 2 is restored
	var msg1ExpungedAt, msg2ExpungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx, "SELECT expunged_at FROM messages WHERE id = $1", msgID1).Scan(&msg1ExpungedAt)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT expunged_at FROM messages WHERE id = $1", msgID2).Scan(&msg2ExpungedAt)
	require.NoError(t, err)

	assert.NotNil(t, msg1ExpungedAt, "Old message should still be deleted")
	assert.Nil(t, msg2ExpungedAt, "Recent message should be restored")
}

// TestListDeletedMessages_WithFilters tests listing deleted messages with various filters
func TestListDeletedMessages_WithFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, sentID := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert and expunge multiple messages
	inboxMsgID1 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Inbox Old", "<inbox_old@example.com>")
	inboxMsgID2 := insertTestMessage(t, db, accountID, inboxID, "INBOX", "Inbox Recent", "<inbox_recent@example.com>")
	sentMsgID := insertTestMessage(t, db, accountID, sentID, "Sent", "Sent Message", "<sent@example.com>")

	// Get UIDs and expunge
	var uid1, uid2, uid3 imap.UID
	err := db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", inboxMsgID1).Scan(&uid1)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", inboxMsgID2).Scan(&uid2)
	require.NoError(t, err)
	err = db.GetReadPool().QueryRow(ctx, "SELECT uid FROM messages WHERE id = $1", sentMsgID).Scan(&uid3)
	require.NoError(t, err)

	expungeMessage(t, db, inboxID, uid1)
	expungeMessage(t, db, inboxID, uid2)
	expungeMessage(t, db, sentID, uid3)

	// Set old expunged_at for first message
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err = db.GetWritePool().Exec(ctx, "UPDATE messages SET expunged_at = $1 WHERE id = $2", oldTime, inboxMsgID1)
	require.NoError(t, err)

	// Test: List all deleted messages
	allParams := ListDeletedMessagesParams{
		Email: testEmail,
		Limit: 100,
	}
	allDeleted, err := db.ListDeletedMessages(ctx, allParams)
	require.NoError(t, err)
	assert.Len(t, allDeleted, 3, "Should find all 3 deleted messages")

	// Test: Filter by mailbox
	inboxPath := "INBOX"
	inboxParams := ListDeletedMessagesParams{
		Email:       testEmail,
		MailboxPath: &inboxPath,
		Limit:       100,
	}
	inboxDeleted, err := db.ListDeletedMessages(ctx, inboxParams)
	require.NoError(t, err)
	assert.Len(t, inboxDeleted, 2, "Should find 2 INBOX messages")
	for _, msg := range inboxDeleted {
		assert.Equal(t, "INBOX", msg.MailboxPath)
	}

	// Test: Filter by time range (last 24 hours)
	since := time.Now().Add(-24 * time.Hour)
	timeParams := ListDeletedMessagesParams{
		Email: testEmail,
		Since: &since,
		Limit: 100,
	}
	recentDeleted, err := db.ListDeletedMessages(ctx, timeParams)
	require.NoError(t, err)
	assert.Len(t, recentDeleted, 2, "Should find 2 recently deleted messages")

	// Test: Limit results
	limitParams := ListDeletedMessagesParams{
		Email: testEmail,
		Limit: 1,
	}
	limitedDeleted, err := db.ListDeletedMessages(ctx, limitParams)
	require.NoError(t, err)
	assert.Len(t, limitedDeleted, 1, "Should respect limit")

	// Test: Combined filters (INBOX + recent)
	combinedParams := ListDeletedMessagesParams{
		Email:       testEmail,
		MailboxPath: &inboxPath,
		Since:       &since,
		Limit:       100,
	}
	combinedDeleted, err := db.ListDeletedMessages(ctx, combinedParams)
	require.NoError(t, err)
	assert.Len(t, combinedDeleted, 1, "Should find 1 recently deleted INBOX message")
	assert.Equal(t, "INBOX", combinedDeleted[0].MailboxPath)
	assert.Contains(t, combinedDeleted[0].Subject, "Recent")
}

// TestRestoreMessages_InvalidAccount tests error handling for non-existent account
func TestRestoreMessages_InvalidAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Try to list deleted messages for non-existent account
	listParams := ListDeletedMessagesParams{
		Email: "nonexistent@example.com",
		Limit: 100,
	}
	_, err := db.ListDeletedMessages(ctx, listParams)
	assert.Error(t, err, "Should fail for non-existent account")
	assert.Contains(t, err.Error(), "account not found")

	// Try to restore messages for non-existent account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	restoreParams := RestoreMessagesParams{
		Email:      "nonexistent@example.com",
		MessageIDs: []int64{999},
	}
	_, err = db.RestoreMessages(ctx, tx, restoreParams)
	assert.Error(t, err, "Should fail for non-existent account")
	assert.Contains(t, err.Error(), "account not found")
}

// TestRestoreMessages_PreservesFlags tests that message flags are preserved during restoration
func TestRestoreMessages_PreservesFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert a message with specific flags
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()
	options := &InsertMessageOptions{
		UserID:        accountID,
		MailboxID:     inboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   "hash_flags_test",
		MessageID:     "<flags_test@example.com>",
		Flags:         []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.Flag("$Important")},
		InternalDate:  now,
		Size:          512,
		Subject:       "Test Message with Flags",
		PlaintextBody: "Test message body",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: options.ContentHash,
		InstanceID:  "test-instance",
		Size:        512,
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	msgID, _, err := db.InsertMessage(ctx, tx, options, upload)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get original message state
	var originalUID imap.UID
	var originalFlags int
	var originalCustomFlags []byte
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT uid, flags, custom_flags FROM messages WHERE id = $1",
		msgID).Scan(&originalUID, &originalFlags, &originalCustomFlags)
	require.NoError(t, err)

	// Verify original flags
	assert.NotZero(t, originalFlags, "Original flags should be set")
	assert.NotEmpty(t, originalCustomFlags, "Original custom flags should be set")

	// Expunge the message
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	_, err = db.ExpungeMessageUIDs(ctx, tx2, inboxID, originalUID)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify message is expunged
	var expungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", msgID).Scan(&expungedAt)
	require.NoError(t, err)
	assert.NotNil(t, expungedAt, "Message should be expunged")

	// Restore the message
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	restoreParams := RestoreMessagesParams{
		Email:      testEmail,
		MessageIDs: []int64{msgID},
	}
	restoredCount, err := db.RestoreMessages(ctx, tx3, restoreParams)
	require.NoError(t, err)
	assert.Equal(t, int64(1), restoredCount)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// Verify message is restored and flags are preserved
	var restoredUID imap.UID
	var restoredFlags int
	var restoredCustomFlags []byte
	var restoredExpungedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT uid, flags, custom_flags, expunged_at FROM messages WHERE id = $1",
		msgID).Scan(&restoredUID, &restoredFlags, &restoredCustomFlags, &restoredExpungedAt)
	require.NoError(t, err)

	// Assertions
	assert.Nil(t, restoredExpungedAt, "Message should be restored (expunged_at should be NULL)")
	assert.NotEqual(t, originalUID, restoredUID, "UID should be different after restore")
	assert.Equal(t, originalFlags, restoredFlags, "Bitwise flags should be preserved")
	assert.JSONEq(t, string(originalCustomFlags), string(restoredCustomFlags), "Custom flags should be preserved")

	// Verify the actual flag values
	assert.Equal(t, FlagSeen|FlagFlagged, restoredFlags, "Should have Seen and Flagged flags")

	// Parse and verify custom flags
	var customFlags []string
	err = json.Unmarshal(restoredCustomFlags, &customFlags)
	require.NoError(t, err)
	assert.Contains(t, customFlags, "$Important", "Should have $Important custom flag")
}

// TestRestoreMessages_PreservesMessageMetadata tests that all message metadata is preserved
func TestRestoreMessages_PreservesMessageMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert a message with comprehensive metadata
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	sentDate := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	internalDate := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)

	options := &InsertMessageOptions{
		UserID:        accountID,
		MailboxID:     inboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   "hash_metadata_test",
		MessageID:     "<metadata_test@example.com>",
		Flags:         []imap.Flag{imap.FlagSeen},
		InternalDate:  internalDate,
		Size:          2048,
		Subject:       "Important Test Message",
		PlaintextBody: "This is a test message with metadata",
		SentDate:      sentDate,
		InReplyTo:     []string{"<parent@example.com>"},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: options.ContentHash,
		InstanceID:  "test-instance",
		Size:        2048,
		Attempts:    0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	msgID, _, err := db.InsertMessage(ctx, tx, options, upload)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get original message metadata
	type messageMetadata struct {
		UID          imap.UID
		Subject      string
		MessageID    string
		InReplyTo    *string
		SentDate     time.Time
		InternalDate time.Time
		Size         int
		ContentHash  string
	}

	var original messageMetadata
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT uid, subject, message_id, in_reply_to, sent_date, internal_date, size, content_hash
		FROM messages WHERE id = $1
	`, msgID).Scan(&original.UID, &original.Subject, &original.MessageID,
		&original.InReplyTo, &original.SentDate, &original.InternalDate,
		&original.Size, &original.ContentHash)
	require.NoError(t, err)

	// Expunge the message
	expungeMessage(t, db, inboxID, original.UID)

	// Restore the message
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	restoreParams := RestoreMessagesParams{
		Email:      testEmail,
		MessageIDs: []int64{msgID},
	}
	_, err = db.RestoreMessages(ctx, tx2, restoreParams)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get restored message metadata
	var restored messageMetadata
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT uid, subject, message_id, in_reply_to, sent_date, internal_date, size, content_hash
		FROM messages WHERE id = $1
	`, msgID).Scan(&restored.UID, &restored.Subject, &restored.MessageID,
		&restored.InReplyTo, &restored.SentDate, &restored.InternalDate,
		&restored.Size, &restored.ContentHash)
	require.NoError(t, err)

	// Verify all metadata is preserved except UID
	assert.NotEqual(t, original.UID, restored.UID, "UID should be different (new UID assigned)")
	assert.Equal(t, original.Subject, restored.Subject, "Subject should be preserved")
	assert.Equal(t, original.MessageID, restored.MessageID, "Message-ID should be preserved")
	assert.Equal(t, original.InReplyTo, restored.InReplyTo, "In-Reply-To should be preserved")
	assert.True(t, original.SentDate.Equal(restored.SentDate), "Sent date should be preserved")
	assert.True(t, original.InternalDate.Equal(restored.InternalDate), "Internal date should be preserved")
	assert.Equal(t, original.Size, restored.Size, "Size should be preserved")
	assert.Equal(t, original.ContentHash, restored.ContentHash, "Content hash should be preserved")
}
