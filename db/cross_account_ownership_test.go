//go:build integration

package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrossAccountMessageOwnership(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	// 1. Create two test accounts (User A and User B)
	accountA := common.CreateTestAccount(t, rdb)
	accountB := common.CreateTestAccount(t, rdb)

	accountID_A, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	require.NoError(t, err)
	accountID_B, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountB.Email)
	require.NoError(t, err)

	// User A creates a mailbox
	srcMailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID_A, "INBOX")
	require.NoError(t, err)

	// User B creates a shared mailbox
	destMailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID_B, "Shared")
	require.NoError(t, err)

	// 2. Insert a message into User A's mailbox (simulating upload)
	domainA := "example.com"
	localA := "user_a"
	contentHash := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

	opts := &db.InsertMessageOptions{
		AccountID:     accountID_A,
		MailboxID:     srcMailbox.ID,
		S3Domain:      domainA,
		S3Localpart:   localA,
		MailboxName:   srcMailbox.Name,
		ContentHash:   contentHash,
		MessageID:     "<test1@localhost>",
		InternalDate:  time.Now(),
		Size:          1024,
		Subject:       "Test Cross Account",
		PlaintextBody: "Hello",
		SentDate:      time.Now(),
	}

	// First insert pending upload
	upload := db.PendingUpload{
		ContentHash: contentHash,
		InstanceID:  "test",
		Size:        1024,
		AccountID:   accountID_A,
	}

	_, srcUID, err := rdb.InsertMessageWithRetry(ctx, opts, upload)
	require.NoError(t, err)

	// 3. User A copies the message to User B's shared mailbox
	domainB := "example.net"
	localB := "user_b"

	uids := []imap.UID{imap.UID(srcUID)}

	// Copy from A to B using resilient operations
	uidMap, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, srcMailbox.ID, destMailbox.ID, accountID_B, domainB, localB, "test-instance", map[imap.UID]string{imap.UID(srcUID): contentHash})
	require.NoError(t, err)
	require.Len(t, uidMap, 1)

	// Get the new message ID
	destUID := uidMap[imap.UID(srcUID)]

	// Verify the destination message is owned by User B and has correct S3 details
	var destAccountID int64
	var destDomain, destLocalpart string
	err = rdb.QueryRowWithRetry(ctx, `SELECT account_id, s3_domain, s3_localpart FROM messages WHERE mailbox_id = $1 AND uid = $2`, destMailbox.ID, destUID).Scan(&destAccountID, &destDomain, &destLocalpart)
	require.NoError(t, err)

	assert.Equal(t, accountID_B, destAccountID)
	assert.Equal(t, domainB, destDomain)
	assert.Equal(t, localB, destLocalpart)

	// The copied row is not yet uploaded, so CopyMessages must have re-staged a
	// pending_upload under the OWNER (User B) — otherwise the uploader would never
	// write the body under B's S3 path and the message would be lost. Without the
	// re-stage this count is 0 and the test fails.
	var ownerPending int
	err = rdb.QueryRowWithRetry(ctx, `SELECT COUNT(*) FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`, contentHash, accountID_B).Scan(&ownerPending)
	require.NoError(t, err)
	assert.Equal(t, 1, ownerPending, "cross-account COPY must re-stage a pending_upload under the owner")

	// 4. Move a message
	// The message is still in srcMailbox, so we can just move it.
	uids2 := []imap.UID{imap.UID(srcUID)}

	uidMap2, err := rdb.MoveMessagesWithRetry(ctx, &uids2, srcMailbox.ID, destMailbox.ID, accountID_B, domainB, localB, "test-instance", nil, nil)
	require.NoError(t, err)
	require.Len(t, uidMap2, 1)

	destUID2 := uidMap2[imap.UID(srcUID)]

	err = rdb.QueryRowWithRetry(ctx, `SELECT account_id, s3_domain, s3_localpart FROM messages WHERE mailbox_id = $1 AND uid = $2`, destMailbox.ID, destUID2).Scan(&destAccountID, &destDomain, &destLocalpart)
	require.NoError(t, err)

	assert.Equal(t, accountID_B, destAccountID)
	assert.Equal(t, domainB, destDomain)
	assert.Equal(t, localB, destLocalpart)
}

// TestCopyMessagesRefusesSourceRenamedSinceCaller pins CopyMessages' contract for a copy
// into another account (#761): a source row is copied only with the hash the caller made
// its body available for under the owner's key (sourceHashes). A row with any other hash,
// as one sora-admin import rekey renamed after the caller read it, or a row the caller gave
// no hash for, fails the whole copy before anything is written.
func TestCopyMessagesRefusesSourceRenamedSinceCaller(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	accountA := common.CreateTestAccount(t, rdb)
	accountB := common.CreateTestAccount(t, rdb)
	accountID_A, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	require.NoError(t, err)
	accountID_B, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountB.Email)
	require.NoError(t, err)
	srcMailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID_A, "INBOX")
	require.NoError(t, err)
	destMailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID_B, "Shared")
	require.NoError(t, err)

	hashes := map[imap.UID]string{}
	var uids []imap.UID
	for i, hash := range []string{
		"1111222233334444555566667777888899990000aaaabbbbccccddddeeee0761",
		"2222333344445555666677778888999900001111bbbbccccddddeeeeffff0761",
	} {
		_, uid, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID_A,
			MailboxID:     srcMailbox.ID,
			MailboxName:   srcMailbox.Name,
			S3Domain:      "example.com",
			S3Localpart:   "user_a",
			ContentHash:   hash,
			MessageID:     fmt.Sprintf("<renamed-source-%d@example.com>", i),
			InternalDate:  time.Now(),
			Size:          1024,
			Subject:       "Renamed source",
			PlaintextBody: "Hello",
			SentDate:      time.Now(),
		}, db.PendingUpload{ContentHash: hash, InstanceID: "test", Size: 1024, AccountID: accountID_A})
		require.NoError(t, err)
		hashes[imap.UID(uid)] = hash
		uids = append(uids, imap.UID(uid))
	}

	destState := func() (rows int, highestUID int64) {
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT (SELECT COUNT(*) FROM messages WHERE mailbox_id = $1), highest_uid
			FROM mailboxes WHERE id = $1`, destMailbox.ID).Scan(&rows, &highestUID))
		return rows, highestUID
	}
	_, highestBefore := destState()

	renamed := map[imap.UID]string{uids[0]: hashes[uids[0]], uids[1]: "0761" + hashes[uids[1]][4:]}
	missing := map[imap.UID]string{uids[0]: hashes[uids[0]]}
	for name, sourceHashes := range map[string]map[imap.UID]string{"renamed": renamed, "missing": missing} {
		_, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, srcMailbox.ID, destMailbox.ID, accountID_B, "example.net", "user_b", "test-instance", sourceHashes)
		require.ErrorIs(t, err, db.ErrCopySourceChanged, name)
		rows, highest := destState()
		assert.Zero(t, rows, "%s: a refused copy wrote rows", name)
		assert.Equal(t, highestBefore, highest, "%s: a refused copy allocated UIDs", name)
	}

	uidMap, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, srcMailbox.ID, destMailbox.ID, accountID_B, "example.net", "user_b", "test-instance", hashes)
	require.NoError(t, err)
	require.Len(t, uidMap, 2)
	for _, uid := range uids {
		var hash string
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT content_hash FROM messages WHERE mailbox_id = $1 AND uid = $2`,
			destMailbox.ID, uidMap[uid]).Scan(&hash))
		assert.Equal(t, hashes[uid], hash)
	}
}
