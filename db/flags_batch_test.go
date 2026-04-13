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

// Helper function to setup a batch testing environment
func setupBatchFlagTestDatabase(t *testing.T, messageCount int) (*Database, int64, int64, []imap.UID) {
	db := setupTestDatabase(t)
	ctx := context.Background()
	testEmail := fmt.Sprintf("test_batch_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = tx2.Commit(ctx)
	require.NoError(t, err)

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	var uids []imap.UID
	now := time.Now()

	for i := 0; i < messageCount; i++ {
		tx3, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		hash := fmt.Sprintf("batchtest%d", i)
		options := &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailbox.ID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   fmt.Sprintf("test/%s", hash),
			ContentHash:   hash,
			MessageID:     fmt.Sprintf("<batch%d@example.com>", i),
			Flags:         []imap.Flag{},
			InternalDate:  now,
			Size:          512,
			Subject:       fmt.Sprintf("Batch Test Message %d", i),
			PlaintextBody: "Test message for batch flag operations",
			SentDate:      now.Add(-time.Hour),
			InReplyTo:     []string{},
		}

		upload := PendingUpload{
			AccountID:   accountID,
			ContentHash: hash,
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

		uids = append(uids, imap.UID(uid))
	}

	return db, accountID, mailbox.ID, uids
}

func TestSetMessageFlagsBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUIDs := setupBatchFlagTestDatabase(t, 3)
	defer db.Close()
	ctx := context.Background()

	_, unseenBefore, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 3, unseenBefore, "Messages should be initially unseen")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	newFlags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.Flag("CustomBatch")}
	results, err := db.SetMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags)
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	for _, res := range results {
		assert.ElementsMatch(t, newFlags, res.Flags)
		assert.Greater(t, res.ModSeq, int64(0))
		assert.Contains(t, messageUIDs, res.UID)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	_, unseenAfter, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfter, "Unseen count should be 0 after setting \\Seen flag in batch")
	t.Logf("Successfully tested SetMessageFlagsBatch with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

func TestAddMessageFlagsBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUIDs := setupBatchFlagTestDatabase(t, 2)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	addedFlags := []imap.Flag{imap.FlagSeen, imap.Flag("CustomAdded")}
	results, err := db.AddMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, addedFlags)
	assert.NoError(t, err)
	assert.Len(t, results, 2)

	for _, res := range results {
		assert.Contains(t, res.Flags, imap.FlagSeen)
		assert.Contains(t, res.Flags, imap.Flag("CustomAdded"))
		assert.Greater(t, res.ModSeq, int64(0))
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	_, unseenAfter, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenAfter, "Unseen count should be 0 after adding \\Seen flag in batch")
	t.Logf("Successfully tested AddMessageFlagsBatch with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

func TestRemoveMessageFlagsBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID, messageUIDs := setupBatchFlagTestDatabase(t, 2)
	defer db.Close()
	ctx := context.Background()

	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.SetMessageFlagsBatch(ctx, tx1, messageUIDs, mailboxID, []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.Flag("ToBeRemoved")})
	require.NoError(t, err)
	err = tx1.Commit(ctx)
	require.NoError(t, err)

	_, unseenBefore, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 0, unseenBefore, "Messages should be initially seen")

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	results, err := db.RemoveMessageFlagsBatch(ctx, tx2, messageUIDs, mailboxID, []imap.Flag{imap.FlagSeen, imap.Flag("ToBeRemoved")})
	assert.NoError(t, err)
	assert.Len(t, results, 2)

	for _, res := range results {
		assert.NotContains(t, res.Flags, imap.FlagSeen)
		assert.NotContains(t, res.Flags, imap.Flag("ToBeRemoved"))
		assert.Contains(t, res.Flags, imap.FlagFlagged)
	}

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	_, unseenAfter, _ := getMailboxStats(t, db, ctx, mailboxID)
	assert.Equal(t, 2, unseenAfter, "Unseen count should be back to 2 after removing \\Seen flag in batch")
	t.Logf("Successfully tested RemoveMessageFlagsBatch with accountID: %d, mailboxID: %d", accountID, mailboxID)
}
