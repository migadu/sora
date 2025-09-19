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

// setupCacheTestDatabase is a helper for cache integrity tests.
// It creates an account with two mailboxes (INBOX, Sent).
func setupCacheTestDatabase(t *testing.T) (db *Database, accountID, inboxID, sentID int64) {
	db = setupTestDatabase(t)
	ctx := context.Background()

	// Create account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	testEmail := fmt.Sprintf("cache_test_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err = db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create mailboxes
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "Sent", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	sent, err := db.GetMailboxByName(ctx, accountID, "Sent")
	require.NoError(t, err)

	return db, accountID, inbox.ID, sent.ID
}

// TestMessageSequencesOnInsert verifies the message_sequences cache after message insertions.
func TestMessageSequencesOnInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID, _ := setupCacheTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Insert 3 messages
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 10, nil)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 20, nil)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 30, nil)
	require.NoError(t, tx.Commit(ctx))

	// Verify sequence numbers
	var seqs []int
	rows, err := db.GetReadPool().Query(ctx, "SELECT seqnum FROM message_sequences WHERE mailbox_id = $1 ORDER BY uid", inboxID)
	require.NoError(t, err)
	seqs, err = pgx.CollectRows(rows, pgx.RowTo[int])
	require.NoError(t, err)

	assert.Equal(t, []int{1, 2, 3}, seqs, "Sequence numbers should be dense and ordered by UID")

	// Insert a message in the middle
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 15, nil)
	require.NoError(t, tx.Commit(ctx))

	// Verify sequence numbers are shifted correctly
	rows, err = db.GetReadPool().Query(ctx, "SELECT seqnum FROM message_sequences WHERE mailbox_id = $1 ORDER BY uid", inboxID)
	require.NoError(t, err)
	seqs, err = pgx.CollectRows(rows, pgx.RowTo[int])
	require.NoError(t, err)

	assert.Equal(t, []int{1, 2, 3, 4}, seqs, "Sequence numbers should be shifted correctly after middle insert")
}

// TestMessageSequencesOnExpunge verifies the message_sequences cache after expunging messages.
func TestMessageSequencesOnExpunge(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID, _ := setupCacheTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Insert 5 messages
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 10, nil) // seq 1
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 20, nil) // seq 2
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 30, nil) // seq 3
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 40, nil) // seq 4
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 50, nil) // seq 5
	require.NoError(t, tx.Commit(ctx))

	// Expunge a message from the middle (UID 30, seq 3)
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, inboxID, 30)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Verify sequence numbers are shifted down
	var uids []int
	rows, err := db.GetReadPool().Query(ctx, "SELECT uid FROM message_sequences WHERE mailbox_id = $1 ORDER BY seqnum", inboxID)
	require.NoError(t, err)
	uids, err = pgx.CollectRows(rows, pgx.RowTo[int])
	require.NoError(t, err)

	assert.Equal(t, []int{10, 20, 40, 50}, uids, "UIDs should correspond to new sequence numbers")
}

// TestMailboxStatsOnFlagUpdate verifies the mailbox_stats cache after flag updates.
func TestMailboxStatsOnFlagUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID, _ := setupCacheTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Insert one unseen message
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUID(t, db, ctx, tx, accountID, inboxID, "INBOX", 10, nil)
	require.NoError(t, tx.Commit(ctx))

	// Verify initial unseen count
	var unseenCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1", inboxID).Scan(&unseenCount)
	require.NoError(t, err)
	assert.Equal(t, 1, unseenCount)

	// Mark the message as seen
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = db.AddMessageFlags(ctx, tx, 10, inboxID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Verify unseen count is now 0
	err = db.GetReadPool().QueryRow(ctx, "SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1", inboxID).Scan(&unseenCount)
	require.NoError(t, err)
	assert.Equal(t, 0, unseenCount, "Unseen count should be 0 after marking message as seen")
}
