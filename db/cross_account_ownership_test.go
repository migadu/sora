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
	uidMap, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, srcMailbox.ID, destMailbox.ID, accountID_B, domainB, localB, "test-instance", nil)
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

	uidMap2, err := rdb.MoveMessagesWithRetry(ctx, &uids2, srcMailbox.ID, destMailbox.ID, accountID_B, domainB, localB, "test-instance")
	require.NoError(t, err)
	require.Len(t, uidMap2, 1)

	destUID2 := uidMap2[imap.UID(srcUID)]

	err = rdb.QueryRowWithRetry(ctx, `SELECT account_id, s3_domain, s3_localpart FROM messages WHERE mailbox_id = $1 AND uid = $2`, destMailbox.ID, destUID2).Scan(&destAccountID, &destDomain, &destLocalpart)
	require.NoError(t, err)

	assert.Equal(t, accountID_B, destAccountID)
	assert.Equal(t, domainB, destDomain)
	assert.Equal(t, localB, destLocalpart)
}

// TestCopyMessagesTakesOverHeldDestObjects checks the database half of a cross-account
// COPY's hand-over to the cleaner. The caller makes the destination objects exist while
// LockS3ObjectsShared holds their locks; CopyMessages takes the locks over in its own
// transaction, so the cleaner's try-lock keeps failing until the rows commit even after
// the caller's lock transaction is gone. A copy whose caller lost its locks before the
// take-over is refused. A re-keyed row is uploaded exactly when its object was held.
func TestCopyMessagesTakesOverHeldDestObjects(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	pool := rdb.GetDatabase().GetWritePool()

	accountA := common.CreateTestAccount(t, rdb)
	accountB := common.CreateTestAccount(t, rdb)
	idA, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	require.NoError(t, err)
	idB, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountB.Email)
	require.NoError(t, err)
	src, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, idA, "INBOX")
	require.NoError(t, err)
	dest, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, idB, "Shared")
	require.NoError(t, err)

	seed := time.Now().UnixNano()
	heldHash := fmt.Sprintf("%064x", seed)
	unheldHash := fmt.Sprintf("%064x", seed+1) // uploaded only after the caller looked
	insertUploaded := func(hash string) imap.UID {
		t.Helper()
		_, uid, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: idA, MailboxID: src.ID, MailboxName: src.Name,
			S3Domain: "example.com", S3Localpart: "user_a", ContentHash: hash,
			MessageID: "<" + hash[56:] + "@example.com>", InternalDate: time.Now(), Size: 10,
			Subject: "cross-account hand-over", SentDate: time.Now(),
		}, db.PendingUpload{ContentHash: hash, InstanceID: "test", Size: 10, AccountID: idA})
		require.NoError(t, err)
		// What the uploader's finalize does.
		_, err = pool.Exec(ctx, `UPDATE messages SET uploaded = TRUE WHERE account_id = $1 AND content_hash = $2`, idA, hash)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, idA, hash)
		require.NoError(t, err)
		return imap.UID(uid)
	}
	heldUID := insertUploaded(heldHash)
	unheldUID := insertUploaded(unheldHash)
	uids := []imap.UID{heldUID, unheldUID}
	copyRows := func(lock *db.AdvisoryLockTx) (map[imap.UID]imap.UID, error) {
		uidMap, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, src.ID, dest.ID, idB, "example.net", "user_b", "test-instance",
			&db.HeldDestObjects{Lock: lock, Hashes: map[string]bool{heldHash: true}})
		return uidMap, err
	}
	// cleanerCanLock is the cleaner's try-lock on B's object, in a statement of its own.
	cleanerCanLock := func() bool {
		t.Helper()
		var free bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, db.GetS3ObjectLockID(idB, heldHash)).Scan(&free))
		return free
	}
	destRows := func() int {
		t.Helper()
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM messages WHERE mailbox_id = $1`, dest.ID).Scan(&n))
		return n
	}

	// Locks lost before the copy took them over: refused, nothing copied.
	lost, err := rdb.LockS3ObjectsShared(ctx, idB, []string{heldHash})
	require.NoError(t, err)
	lost.Release()
	_, err = copyRows(lost)
	require.ErrorIs(t, err, db.ErrDBLockTimeout)
	require.Zero(t, destRows(), "a copy whose object locks were lost must not commit")

	lock, err := rdb.LockS3ObjectsShared(ctx, idB, []string{heldHash})
	require.NoError(t, err)
	defer lock.Release()
	require.False(t, cleanerCanLock(), "precondition: the caller's shared lock keeps the cleaner out")

	// Stop the copy at its UID allocation, after the take-over, before its commit.
	blocker, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer blocker.Rollback(ctx)
	var blockerPID int
	require.NoError(t, blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
	_, err = blocker.Exec(ctx, `SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE`, dest.ID)
	require.NoError(t, err)
	type copyResult struct {
		uidMap map[imap.UID]imap.UID
		err    error
	}
	done := make(chan copyResult, 1)
	go func() {
		uidMap, err := copyRows(lock)
		done <- copyResult{uidMap, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting))
		if waiting {
			break
		}
		require.True(t, time.Now().Before(deadline), "the copy never reached the destination mailbox row")
		time.Sleep(10 * time.Millisecond)
	}

	lock.Release() // the caller's lock transaction ends before the copy commits
	assert.False(t, cleanerCanLock(), "the copy's transaction must hold the object lock until its rows commit")

	require.NoError(t, blocker.Rollback(ctx))
	res := <-done
	require.NoError(t, res.err)
	require.Len(t, res.uidMap, 2)
	assert.True(t, cleanerCanLock(), "the commit releases the object lock")

	uploadedOf := func(uid imap.UID) bool {
		t.Helper()
		var uploaded bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT uploaded FROM messages WHERE mailbox_id = $1 AND uid = $2`, dest.ID, res.uidMap[uid]).Scan(&uploaded))
		return uploaded
	}
	assert.True(t, uploadedOf(heldUID), "the copy whose object was held is uploaded")
	assert.False(t, uploadedOf(unheldUID), "a copy whose object nobody made exist under the owner's key must not claim to be uploaded")
	var pending int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, idB, unheldHash).Scan(&pending))
	assert.Equal(t, 1, pending, "that copy is staged for an upload under the destination owner")
}
