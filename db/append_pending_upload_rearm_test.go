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

// insertDeliveredMessage delivers one message through db.InsertMessage, the path LMTP
// and IMAP APPEND use, with a pending upload owned by instanceID.
func insertDeliveredMessage(t *testing.T, db *Database, accountID, mailboxID int64, mailboxName, contentHash, instanceID string, uid uint32) {
	t.Helper()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 1024}
	now := time.Now()
	_, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   "rearm",
		ContentHash:   contentHash,
		MessageID:     fmt.Sprintf("<rearm_%s_%d@example.com>", contentHash, uid),
		InternalDate:  now,
		SentDate:      now,
		Size:          1024,
		Subject:       "Re-arm test",
		BodyStructure: &bs,
	}, PendingUpload{
		InstanceID:  instanceID,
		ContentHash: contentHash,
		Size:        1024,
		AccountID:   accountID,
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

// TestInsertMessageReArmsExhaustedPendingUpload proves that a fresh delivery revives an
// upload that an earlier copy gave up on.
//
// The uploader exhausts a pending upload (ExhaustUploadAttempts sets attempts =
// maxAttempts) when its spool file is gone AND S3 does not have the object. A later
// delivery of the same (content_hash, account_id) writes a brand-new spool file on this
// node, which is proof that the bytes are here again — but InsertMessage's
// ON CONFLICT (content_hash, account_id) DO NOTHING leaves attempts at maxAttempts, and
// AcquireAndLeasePendingUploads only ever leases rows with attempts < maxAttempts. The
// new message's body therefore never reaches S3, and the cleaner reaps the message once
// the grace period passes.
func TestInsertMessageReArmsExhaustedPendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()
	const maxAttempts = 5

	email := fmt.Sprintf("rearm_%d@example.com", ts)
	accountID := createTestAccount(t, db, email, "password")
	mailboxName := fmt.Sprintf("ReArmBox_%d", ts)
	mailboxID := createTestMailbox(t, db, accountID, mailboxName)

	contentHash := fmt.Sprintf("rearm_hash_%d", ts)
	instanceID := fmt.Sprintf("rearm_instance_%d", ts)

	// First delivery: creates the pending upload.
	insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, instanceID, 1)

	// The uploader finds the spool file missing and S3 without the object, so it gives
	// up on this upload for good.
	exhaustTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.ExhaustUploadAttempts(ctx, exhaustTx, contentHash, accountID, maxAttempts))
	require.NoError(t, exhaustTx.Commit(ctx))

	var attempts int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT attempts FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&attempts))
	require.Equal(t, maxAttempts, attempts, "precondition: the upload must be exhausted")

	// Second delivery of the same content: a fresh spool file exists on this node again.
	insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, instanceID, 2)

	var ownerInstance string
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT attempts, instance_id FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&attempts, &ownerInstance))

	assert.Equal(t, 0, attempts,
		"UPLOAD NEVER RETRIED: the pending upload is still exhausted (attempts = %d) after a fresh "+
			"delivery wrote a new spool file. AcquireAndLeasePendingUploads requires attempts < maxAttempts, "+
			"so nothing will ever upload this body and CleanupFailedUploads deletes the message once it is "+
			"older than the grace period.", attempts)
	assert.Equal(t, instanceID, ownerInstance,
		"the pending upload must belong to the instance holding the fresh spool file")

	// The functional consequence: the row must be leasable by this instance's worker.
	leaseTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer leaseTx.Rollback(ctx)
	leased, err := db.AcquireAndLeasePendingUploads(ctx, leaseTx, instanceID, 10, time.Minute, maxAttempts)
	require.NoError(t, err)
	require.NoError(t, leaseTx.Commit(ctx))

	var leasedHashes []string
	for _, u := range leased {
		leasedHashes = append(leasedHashes, u.ContentHash)
	}
	assert.Contains(t, leasedHashes, contentHash,
		"the re-delivered body was not picked up by the upload worker: %v", leasedHashes)
}

// TestInsertMessageReArmKeepsCleanupRulesIntact pins the reaping side of the re-arm: a
// re-armed row must protect its messages from CleanupFailedUploads exactly like any
// other live upload (owner alive, attempts left), and must not protect them once the
// owning instance is gone.
func TestInsertMessageReArmKeepsCleanupRulesIntact(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	const maxAttempts = 5
	const gracePeriod = 24 * time.Hour
	const liveness = time.Hour

	email := fmt.Sprintf("rearm_cleanup_%d@example.com", ts)
	accountID := createTestAccount(t, db, email, "password")
	mailboxName := fmt.Sprintf("ReArmCleanupBox_%d", ts)
	mailboxID := createTestMailbox(t, db, accountID, mailboxName)

	contentHash := fmt.Sprintf("rearm_cleanup_hash_%d", ts)
	instanceID := fmt.Sprintf("rearm_cleanup_instance_%d", ts)

	insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, instanceID, 1)

	exhaustTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.ExhaustUploadAttempts(ctx, exhaustTx, contentHash, accountID, maxAttempts))
	require.NoError(t, exhaustTx.Commit(ctx))

	insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, instanceID, 2)

	// Age both messages past the grace period; only the liveness of the owning instance
	// decides from here on.
	_, err = db.GetWritePool().Exec(ctx,
		`UPDATE messages SET created_at = now() - interval '25 hours' WHERE content_hash = $1`, contentHash)
	require.NoError(t, err)

	messageCount := func() int {
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE content_hash = $1`, contentHash).Scan(&n))
		return n
	}
	require.Equal(t, 2, messageCount(), "precondition: both deliveries are present and unuploaded")

	// Owner alive: the re-armed row must hold the messages back.
	_, err = db.GetWritePool().Exec(ctx,
		`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now())
		 ON CONFLICT (instance_id) DO UPDATE SET last_seen = now()`, instanceID)
	require.NoError(t, err)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CleanupFailedUploads(ctx, tx, gracePeriod, maxAttempts, liveness)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, 2, messageCount(),
		"a re-armed upload owned by a live instance must keep its messages: the bytes are on that node's disk")

	// Owner gone: the re-arm must not make the row immortal.
	_, err = db.GetWritePool().Exec(ctx,
		`UPDATE instance_heartbeats SET last_seen = now() - interval '2 hours' WHERE instance_id = $1`, instanceID)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CleanupFailedUploads(ctx, tx, gracePeriod, maxAttempts, liveness)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, 0, messageCount(),
		"once the owning instance is provably gone, the re-armed row must no longer shield the messages")

	var pending int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM pending_uploads WHERE content_hash = $1`, contentHash).Scan(&pending))
	assert.Equal(t, 0, pending, "the pending_uploads row must be reaped with its messages")
}
