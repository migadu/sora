//go:build integration

package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailboxDoesNotRewriteMessagesButRestoreFollowsIt pins the two halves of the
// rename fix together.
//
// RENAME must not touch messages at all: re-syncing the denormalized mailbox_path was a
// non-HOT update of every row in the subtree, propagating into all ~30 indexes on the
// table (37s / 2.2 GB of WAL for 105k messages), held under the mailboxes row lock that
// every delivery needs.
//
// The correctness that sync used to provide must survive anyway: an expunged message is
// restored into the mailbox it actually belongs to — under the mailbox's CURRENT name —
// rather than resurrecting a mailbox under the pre-rename name. RestoreMessages gets that
// from mailbox_id (see effectiveMailboxName), not from the stale string.
func TestRenameMailboxDoesNotRewriteMessagesButRestoreFollowsIt(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// Parent "Work" with a child "Work/Sub".
	parent, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Work")
	require.NoError(t, err)
	child, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Work/Sub")
	require.NoError(t, err)

	parentMsgID, parentUID := insertRenameFixture(t, rdb, accountID, parent, "aparent")
	childMsgID, childUID := insertRenameFixture(t, rdb, accountID, child, "bchild")

	// Expunge one message in each mailbox: these are the rows RestoreMessages reads.
	expungeRenameFixture(t, rdb, parent.ID, imap.UID(parentUID))
	expungeRenameFixture(t, rdb, child.ID, imap.UID(childUID))

	// Sanity: paths are the pre-rename names.
	assert.Equal(t, "Work", mailboxPathOf(t, rdb, parentMsgID))
	assert.Equal(t, "Work/Sub", mailboxPathOf(t, rdb, childMsgID))

	// Rename Work -> Business (cascades the child to Business/Sub).
	require.NoError(t, rdb.RenameMailboxWithRetry(ctx, parent.ID, accountID, "Business", nil))

	// The message rows are NOT rewritten: mailbox_path still holds the pre-rename name.
	// This is the hot-path guarantee — a rename costs O(mailboxes), never O(messages).
	assert.Equal(t, "Work", mailboxPathOf(t, rdb, parentMsgID),
		"RENAME must not rewrite messages rows; mailbox_path stays at the pre-rename name")
	assert.Equal(t, "Work/Sub", mailboxPathOf(t, rdb, childMsgID),
		"RENAME must not rewrite messages rows in child mailboxes either")

	// ...and the stale string must not mislead a restore: both messages come back into the
	// mailboxes they already belong to, now named Business and Business/Sub.
	restored, err := rdb.RestoreMessagesWithRetry(ctx, db.RestoreMessagesParams{
		Email:      account.Email,
		MessageIDs: []int64{parentMsgID, childMsgID},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), restored)

	assert.Equal(t, parent.ID, liveMailboxIDOf(t, rdb, parentMsgID),
		"restored message must land back in the renamed mailbox, not a resurrected 'Work'")
	assert.Equal(t, child.ID, liveMailboxIDOf(t, rdb, childMsgID),
		"restored child message must land back in the renamed child mailbox")

	_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "Work")
	assert.Error(t, err, "restore must not resurrect a mailbox under the pre-rename name")
}

// TestDeleteMailboxStampsPathOnAlreadyExpungedMessages covers the other end of the fix.
//
// Because RENAME no longer re-syncs mailbox_path, DeleteMailbox is the last chance to
// record where a message lived: after it runs, messages.mailbox_id is NULL (the FK is
// ON DELETE SET NULL) and the string is the only surviving record. It must therefore stamp
// rows that were ALREADY expunged before the delete, not just the live ones it expunges.
func TestDeleteMailboxStampsPathOnAlreadyExpungedMessages(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	mailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Archive")
	require.NoError(t, err)

	earlyID, earlyUID := insertRenameFixture(t, rdb, accountID, mailbox, "cearly")
	lateID, _ := insertRenameFixture(t, rdb, accountID, mailbox, "dlate")

	// "early" is expunged BEFORE the rename, so its stored path goes stale and nothing on
	// the rename path will ever refresh it. "late" is still live when the mailbox goes.
	expungeRenameFixture(t, rdb, mailbox.ID, imap.UID(earlyUID))

	require.NoError(t, rdb.RenameMailboxWithRetry(ctx, mailbox.ID, accountID, "Vault", nil))
	require.Equal(t, "Archive", mailboxPathOf(t, rdb, earlyID), "precondition: the tombstone's path is stale")

	// Hard-delete the mailbox (what the background purge does to a soft-deleted mailbox).
	require.NoError(t, rdb.DeleteMailboxWithRetry(ctx, mailbox.ID, accountID))

	assert.Equal(t, "Vault", mailboxPathOf(t, rdb, earlyID),
		"a message expunged before the rename must still be stamped with the mailbox's final name")
	assert.Equal(t, "Vault", mailboxPathOf(t, rdb, lateID),
		"a message live at delete time must be stamped with the mailbox's final name")

	// Both are orphans now, so the string is all restore has to go on.
	require.Nil(t, mailboxIDOf(t, rdb, earlyID), "mailbox_id must be NULL once the mailbox is gone")

	restored, err := rdb.RestoreMessagesWithRetry(ctx, db.RestoreMessagesParams{
		Email:      account.Email,
		MessageIDs: []int64{earlyID, lateID},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), restored)

	vault, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Vault")
	require.NoError(t, err, "restore recreates the mailbox under its final name")
	assert.Equal(t, vault.ID, liveMailboxIDOf(t, rdb, earlyID))
	assert.Equal(t, vault.ID, liveMailboxIDOf(t, rdb, lateID))

	_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "Archive")
	assert.Error(t, err, "the pre-rename name must not come back")
}

func insertRenameFixture(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, mb *db.DBMailbox, hashSeed string) (int64, int64) {
	t.Helper()
	hash := strings.Repeat(hashSeed[:1], 64) // deterministic, distinct 64-char hash
	opts := &db.InsertMessageOptions{
		AccountID:    accountID,
		MailboxID:    mb.ID,
		MailboxName:  mb.Name, // stored verbatim into messages.mailbox_path
		S3Domain:     "example.com",
		S3Localpart:  "user",
		ContentHash:  hash,
		MessageID:    fmt.Sprintf("<%s-%d@x>", hashSeed, time.Now().UnixNano()),
		InternalDate: time.Now(),
		SentDate:     time.Now(),
		Size:         100,
	}
	upload := db.PendingUpload{ContentHash: hash, InstanceID: "test", Size: 100, AccountID: accountID}
	id, uid, err := rdb.InsertMessageWithRetry(context.Background(), opts, upload)
	require.NoError(t, err)
	return id, uid
}

func expungeRenameFixture(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64, uid imap.UID) {
	t.Helper()
	ctx := context.Background()
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = rdb.GetDatabase().ExpungeMessageUIDs(ctx, tx, mailboxID, uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

func mailboxPathOf(t *testing.T, rdb *resilient.ResilientDatabase, messageID int64) string {
	t.Helper()
	var path *string
	err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT mailbox_path FROM messages WHERE id = $1`, messageID).Scan(&path)
	require.NoError(t, err)
	require.NotNil(t, path)
	return *path
}

func mailboxIDOf(t *testing.T, rdb *resilient.ResilientDatabase, messageID int64) *int64 {
	t.Helper()
	var id *int64
	err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT mailbox_id FROM messages WHERE id = $1`, messageID).Scan(&id)
	require.NoError(t, err)
	return id
}

func liveMailboxIDOf(t *testing.T, rdb *resilient.ResilientDatabase, messageID int64) int64 {
	t.Helper()
	var id *int64
	err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT mailbox_id FROM messages WHERE id = $1 AND expunged_at IS NULL`, messageID).Scan(&id)
	require.NoError(t, err, "message %d must be live after restore", messageID)
	require.NotNil(t, id)
	return *id
}
