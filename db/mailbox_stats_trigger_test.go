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

// TestRestoreIntoEmptyMailboxKeepsMessageCount is a regression test for the mailbox_stats UPDATE-branch
// UPSERT fix (migration 000037). When a message is un-expunged/moved into a mailbox that has no
// mailbox_stats row yet (as `sora-admin messages restore` does after creating the target mailbox on
// the fly), the trigger's additions delta must CREATE the row. Before the fix it used a plain UPDATE
// that matched 0 rows and silently dropped the +1, leaving message_count missing/0.
func TestRestoreIntoEmptyMailboxKeepsMessageCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	accountID, _ := createStatsTestAccount(t, db, ctx, "test_restore_empty_mbox")

	// Source mailbox with one message, which we then expunge (its stats row exists, count back to 0).
	sourceID := createStatsTestMailbox(t, db, ctx, accountID, "Source")
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, sourceID, "Source", 10, nil)
	require.NoError(t, tx.Commit(ctx))

	var msgID int64
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT id FROM messages WHERE mailbox_id = $1 AND uid = 10", sourceID).Scan(&msgID))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, sourceID, imap.UID(10))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Target mailbox created with NO messages -> NO mailbox_stats row (the row is only created by the
	// INSERT-branch trigger when an active message lands).
	targetID := createStatsTestMailbox(t, db, ctx, accountID, "Target")
	var exists bool
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM mailbox_stats WHERE mailbox_id = $1)", targetID).Scan(&exists))
	require.False(t, exists, "precondition: target mailbox must have no mailbox_stats row")

	// Simulate the restore: un-expunge the message into the empty target mailbox. This is exactly the
	// statement db.RestoreMessages issues (db/restore.go) and is what fires the trigger UPDATE branch.
	_, err = db.GetWritePool().Exec(ctx, `
		UPDATE messages SET expunged_at = NULL, expunged_modseq = NULL, mailbox_id = $2, uid = 1, updated_at = now()
		WHERE id = $1
	`, msgID, targetID)
	require.NoError(t, err)

	// The cached message_count for the target must now equal the live count (1). Query the cache row
	// directly (not via GetMailboxMessageCountAndSizeSum, which is now computed live).
	var cachedCount int
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COALESCE((SELECT message_count FROM mailbox_stats WHERE mailbox_id = $1), 0)", targetID).Scan(&cachedCount)
	require.NoError(t, err)

	var liveCount int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", targetID).Scan(&liveCount))

	require.Equal(t, 1, liveCount, "sanity: one active message in target")
	assert.Equal(t, liveCount, cachedCount,
		"cached message_count must match live count after restore into an empty mailbox (UPSERT fix)")
}

func createStatsTestAccount(t *testing.T, db *Database, ctx context.Context, prefix string) (int64, string) {
	t.Helper()
	email := fmt.Sprintf("%s_%d@example.com", prefix, time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)
	return accountID, email
}

func createStatsTestMailbox(t *testing.T, db *Database, ctx context.Context, accountID int64, name string) int64 {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
	require.NoError(t, tx.Commit(ctx))

	mbox, err := db.GetMailboxByName(ctx, accountID, name)
	require.NoError(t, err)
	return mbox.ID
}
