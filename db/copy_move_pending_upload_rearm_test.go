package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copyOrMove runs a COPY or MOVE of uids from srcMailboxID into destMailboxID, owned by
// destAccountID, in its own transaction, as this node (instanceID) does for IMAP.
func copyOrMove(t *testing.T, db *Database, op string, uids []imap.UID, srcMailboxID, destMailboxID, destAccountID int64, instanceID string, sourceHashes map[imap.UID]string) {
	t.Helper()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	switch op {
	case "copy":
		_, _, err = db.CopyMessages(ctx, tx, &uids, srcMailboxID, destMailboxID, destAccountID, "example.org", "owner", instanceID, sourceHashes, nil)
	case "move":
		_, err = db.MoveMessages(ctx, tx, &uids, srcMailboxID, destMailboxID, destAccountID, "example.org", "owner", instanceID, sourceHashes, nil)
	default:
		t.Fatalf("unknown op %q", op)
	}
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

func mailboxUIDs(t *testing.T, db *Database, mailboxID int64) []imap.UID {
	t.Helper()
	rows, err := db.GetReadPool().Query(context.Background(),
		`SELECT uid FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL ORDER BY uid`, mailboxID)
	require.NoError(t, err)
	defer rows.Close()
	var uids []imap.UID
	for rows.Next() {
		var uid int64
		require.NoError(t, rows.Scan(&uid))
		uids = append(uids, imap.UID(uid))
	}
	require.NoError(t, rows.Err())
	return uids
}

type pendingUploadState struct {
	attempts    int
	instanceID  string
	lastAttempt *time.Time
}

func readPendingUpload(t *testing.T, db *Database, contentHash string, accountID int64) pendingUploadState {
	t.Helper()
	var s pendingUploadState
	require.NoError(t, db.GetReadPool().QueryRow(context.Background(),
		`SELECT attempts, instance_id, last_attempt FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&s.attempts, &s.instanceID, &s.lastAttempt))
	return s
}

// TestCrossAccountCopyMoveReArmsOwnersPendingUpload covers #1209: a COPY or MOVE into
// another account's mailbox of a body still staged on this node links the staging file to
// the owner's path here and re-stages the owner's upload. When the owner already had a
// pending upload for that body which no uploader will lease any more (its attempts used
// up, or its instance gone), the re-stage must take it over for this node, whose spool now
// holds the owner's body, as a fresh delivery does (TestInsertMessageReArmsExhaustedPendingUpload).
// Left alone, nothing uploads the copy and CleanupFailedUploads reaps it.
//
// The source holds the body twice, so both copies re-stage the same owner row in one
// statement.
func TestCrossAccountCopyMoveReArmsOwnersPendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	const maxAttempts = 5

	for _, op := range []string{"copy", "move"} {
		for _, owner := range []struct {
			name     string
			attempts int
			gone     bool
		}{
			{name: "exhausted", attempts: maxAttempts},
			{name: "gone instance", gone: true},
		} {
			t.Run(op+"/"+owner.name, func(t *testing.T) {
				ctx := context.Background()
				ts := time.Now().UnixNano()
				here := fmt.Sprintf("rearm_xacct_here_%d", ts)
				contentHash := fmt.Sprintf("rearm_xacct_hash_%d", ts)

				accountA := createTestAccount(t, db, fmt.Sprintf("rearm_xacct_src_%d@example.com", ts), "password")
				accountB := createTestAccount(t, db, fmt.Sprintf("rearm_xacct_owner_%d@example.com", ts), "password")
				srcName := fmt.Sprintf("Src_%d", ts)
				ownerName := fmt.Sprintf("Owner_%d", ts)
				srcBox := createTestMailbox(t, db, accountA, srcName)
				ownerBox := createTestMailbox(t, db, accountB, ownerName)
				sharedBox := createTestMailbox(t, db, accountB, fmt.Sprintf("Shared_%d", ts))

				// The owner's older message of the body, whose upload nobody leases any more.
				ownerInstance := here
				if owner.gone {
					ownerInstance = fmt.Sprintf("rearm_xacct_gone_%d", ts)
					_, err := db.GetWritePool().Exec(ctx,
						`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now() - interval '2 hours')`,
						ownerInstance)
					require.NoError(t, err)
				}
				insertDeliveredMessage(t, db, accountB, ownerBox, ownerName, contentHash, ownerInstance, 1)
				_, err := db.GetWritePool().Exec(ctx,
					`UPDATE pending_uploads SET attempts = $3, last_attempt = now() WHERE content_hash = $1 AND account_id = $2`,
					contentHash, accountB, owner.attempts)
				require.NoError(t, err)

				// The source account holds the same body, staged on this node.
				insertDeliveredMessage(t, db, accountA, srcBox, srcName, contentHash, here, 1)
				insertDeliveredMessage(t, db, accountA, srcBox, srcName, contentHash, here, 2)
				uids := mailboxUIDs(t, db, srcBox)
				require.Len(t, uids, 2)
				sourceHashes := map[imap.UID]string{uids[0]: contentHash, uids[1]: contentHash}

				copyOrMove(t, db, op, uids, srcBox, sharedBox, accountB, here, sourceHashes)

				got := readPendingUpload(t, db, contentHash, accountB)
				assert.Equal(t, 0, got.attempts, "the owner's re-staged upload must have its attempts back")
				assert.Equal(t, here, got.instanceID,
					"the owner's re-staged upload must belong to the node whose spool now holds the owner's body")
				assert.Nil(t, got.lastAttempt, "the owner's re-staged upload must be leasable on the next tick")

				// The functional consequence: this node's uploader leases it.
				leaseTx, err := db.GetWritePool().Begin(ctx)
				require.NoError(t, err)
				defer leaseTx.Rollback(ctx)
				leased, err := db.AcquireAndLeasePendingUploads(ctx, leaseTx, here, 10, time.Minute, maxAttempts)
				require.NoError(t, err)
				found := false
				for _, u := range leased {
					found = found || (u.ContentHash == contentHash && u.AccountID == accountB)
				}
				assert.True(t, found, "this node's uploader does not lease the owner's upload of the %s: %+v", op, leased)
			})
		}
	}
}

// TestSameAccountCopyMoveLeavesPendingUploadAlone pins the other side of #1209: a COPY or
// MOVE within one account stages nothing on this node. Its body is wherever the source was
// delivered, possibly another node, so the re-stage must not take that upload over.
func TestSameAccountCopyMoveLeavesPendingUploadAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	for _, op := range []string{"copy", "move"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			ts := time.Now().UnixNano()
			here := fmt.Sprintf("rearm_same_here_%d", ts)
			elsewhere := fmt.Sprintf("rearm_same_elsewhere_%d", ts)
			contentHash := fmt.Sprintf("rearm_same_hash_%d", ts)

			account := createTestAccount(t, db, fmt.Sprintf("rearm_same_%d@example.com", ts), "password")
			srcName := fmt.Sprintf("Src_%d", ts)
			srcBox := createTestMailbox(t, db, account, srcName)
			destBox := createTestMailbox(t, db, account, fmt.Sprintf("Dest_%d", ts))

			insertDeliveredMessage(t, db, account, srcBox, srcName, contentHash, elsewhere, 1)
			_, err := db.GetWritePool().Exec(ctx,
				`UPDATE pending_uploads SET attempts = 2, last_attempt = now() WHERE content_hash = $1 AND account_id = $2`,
				contentHash, account)
			require.NoError(t, err)
			before := readPendingUpload(t, db, contentHash, account)

			copyOrMove(t, db, op, mailboxUIDs(t, db, srcBox), srcBox, destBox, account, here, nil)

			got := readPendingUpload(t, db, contentHash, account)
			assert.Equal(t, elsewhere, got.instanceID, "a same-account %s took over the source's upload", op)
			assert.Equal(t, before.attempts, got.attempts, "a same-account %s reset the source's upload", op)
			assert.NotNil(t, got.lastAttempt, "a same-account %s reset the source's upload", op)
		})
	}
}
