//go:build integration

package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailboxSyncsMessagePath verifies that renaming a mailbox keeps the
// denormalized messages.mailbox_path column in sync with the new name — for the
// renamed mailbox itself, for its children, and for expunged rows (which are the
// ones RestoreMessages reads). Without the sync, a later restore would look up the
// stale pre-rename name and resurrect a mailbox under the old name.
func TestRenameMailboxSyncsMessagePath(t *testing.T) {
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

	insert := func(mb *db.DBMailbox, hashSeed string) (int64, int64) {
		t.Helper()
		hash := strings.Repeat(hashSeed[:1], 64) // deterministic, distinct 64-char hash
		opts := &db.InsertMessageOptions{
			AccountID:    accountID,
			MailboxID:    mb.ID,
			MailboxName:  mb.Name, // stored verbatim into messages.mailbox_path
			S3Domain:     "example.com",
			S3Localpart:  "user",
			ContentHash:  hash,
			MessageID:    fmt.Sprintf("<%s@x>", hashSeed),
			InternalDate: time.Now(),
			SentDate:     time.Now(),
			Size:         100,
		}
		upload := db.PendingUpload{ContentHash: hash, InstanceID: "test", Size: 100, AccountID: accountID}
		id, uid, err := rdb.InsertMessageWithRetry(ctx, opts, upload)
		require.NoError(t, err)
		return id, uid
	}

	parentMsgID, parentUID := insert(parent, "aparent")
	_, childUID := insert(child, "bchild")

	// Expunge the parent message: it remains restorable and MUST still get its
	// mailbox_path synced on rename.
	_, err = rdb.ExecWithRetry(ctx,
		`UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE id = $1`,
		parentMsgID)
	require.NoError(t, err)

	// Sanity: paths are the pre-rename names.
	assert.Equal(t, "Work", mailboxPathOf(t, rdb, parent.ID, parentUID))
	assert.Equal(t, "Work/Sub", mailboxPathOf(t, rdb, child.ID, childUID))

	// Rename Work -> Business (cascades the child to Business/Sub).
	require.NoError(t, rdb.RenameMailboxWithRetry(ctx, parent.ID, accountID, "Business", nil))

	// The expunged parent message and the live child message both follow the rename.
	assert.Equal(t, "Business", mailboxPathOf(t, rdb, parent.ID, parentUID),
		"expunged message in the renamed mailbox must have mailbox_path synced to the new name")
	assert.Equal(t, "Business/Sub", mailboxPathOf(t, rdb, child.ID, childUID),
		"message in the renamed child must have mailbox_path synced to the new child name")
}

func mailboxPathOf(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64, uid int64) string {
	t.Helper()
	var path string
	err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT mailbox_path FROM messages WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid).Scan(&path)
	require.NoError(t, err)
	return path
}
