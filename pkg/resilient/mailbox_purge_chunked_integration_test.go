//go:build integration

package resilient_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hard delete is driven step by step, each step its own transaction, so a mailbox of
// any size drains without a single transaction sized by the mailbox. Driving it with a
// batch size of 1 forces the multi-step path with a handful of messages.
func TestPurgeMailboxChunked_CompletesAcrossSteps(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	mailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "ChunkPurge")
	require.NoError(t, err)

	const total = 5
	for i := 0; i < total; i++ {
		hash := fmt.Sprintf("%064d", i)
		opts := &db.InsertMessageOptions{
			AccountID:    accountID,
			MailboxID:    mailbox.ID,
			MailboxName:  mailbox.Name,
			S3Domain:     "example.com",
			S3Localpart:  "user",
			ContentHash:  hash,
			MessageID:    fmt.Sprintf("<chunk-%d-%d@example.com>", i, time.Now().UnixNano()),
			InternalDate: time.Now(),
			SentDate:     time.Now(),
			Size:         100,
		}
		_, _, err := rdb.InsertMessageWithRetry(ctx, opts,
			db.PendingUpload{ContentHash: hash, InstanceID: "test", Size: 100, AccountID: accountID})
		require.NoError(t, err)
	}

	// Expunge one up front so the run also covers the tombstone-stamping step.
	msgs, err := rdb.ListMessagesWithRetry(ctx, mailbox.ID)
	require.NoError(t, err)
	require.NotEmpty(t, msgs)
	_, err = rdb.ExpungeMessageUIDsWithRetry(ctx, mailbox.ID, imap.UID(msgs[0].UID))
	require.NoError(t, err)

	require.NoError(t, rdb.PurgeMailboxChunkedForTest(ctx, mailbox.ID, accountID, 1))

	var mailboxRows, live, stamped int
	pool := rdb.GetDatabase().GetReadPool()
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM mailboxes WHERE id = $1", mailbox.ID).Scan(&mailboxRows))
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL", accountID).Scan(&live))
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_path = 'ChunkPurge'", accountID).Scan(&stamped))

	assert.Equal(t, 0, mailboxRows, "the mailbox row is removed by the final step")
	assert.Equal(t, 0, live, "every message is expunged before the mailbox goes")
	assert.Equal(t, total, stamped, "every message keeps the mailbox name restore routes by")

	// A second run finds nothing: the tombstone is gone, which is how the cleaner's
	// "already removed" branch is reached.
	err = rdb.PurgeMailboxChunkedForTest(ctx, mailbox.ID, accountID, 1)
	assert.ErrorIs(t, err, consts.ErrMailboxNotFound)
}
