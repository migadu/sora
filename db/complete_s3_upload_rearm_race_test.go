package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompleteS3UploadSparesAPendingUploadReArmedMidStatement is the finalize side of the
// race TestCleanupFailedUploadsSparesAPendingUploadReArmedMidStatement covers for the
// cleaner.
//
// CompleteS3Upload (sora-admin uploader resolve, S3 import) marks the pair's rows uploaded
// and then deletes the pending row when no unuploaded row is left. A delivery of the same
// body that re-arms the pending row while it runs holds the row's lock until it commits,
// together with the message it staged. The DELETE waits for that lock and, under READ
// COMMITTED, re-checks the row itself but judges "no unuploaded row left" from its own
// snapshot, which lacks the new message. The re-armed row is deleted, and the delivery is
// left uploaded = FALSE with no pending upload: nothing uploads or marks it, and
// CleanupFailedUploads deletes it after the grace period.
//
// The uploader's leased finalize (CompleteLeasedS3Upload) locks the row, ending its lease,
// before it decides, so that decision already sees the delivery; it is covered so that it
// stays that way.
func TestCompleteS3UploadSparesAPendingUploadReArmedMidStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	for _, leased := range []bool{false, true} {
		name := "unleased"
		if leased {
			name = "leased"
		}
		t.Run(name, func(t *testing.T) {
			db := setupTestDatabase(t)
			defer db.Close()

			ctx := context.Background()
			ts := time.Now().UnixNano()

			accountID := createTestAccount(t, db, fmt.Sprintf("complete_rearm_%d@example.com", ts), "password")
			mailboxName := fmt.Sprintf("CompleteReArmBox_%d", ts)
			mailboxID := createTestMailbox(t, db, accountID, mailboxName)
			contentHash := fmt.Sprintf("complete_rearm_hash_%d", ts)
			instance := fmt.Sprintf("complete_rearm_instance_%d", ts)
			const owner = "complete_rearm_uploader"
			// insertDeliveredMessage keys its rows under example.com/rearm.
			key := "example.com/rearm/" + contentHash

			// First delivery: its pending row is what the finalize completes.
			insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, instance, 1)
			var pendingID int64
			require.NoError(t, db.GetReadPool().QueryRow(ctx,
				`SELECT id FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
				contentHash, accountID).Scan(&pendingID))
			if leased {
				_, err := db.GetWritePool().Exec(ctx,
					`UPDATE pending_uploads SET lease_until = now() + interval '1 minute', lease_owner = $2 WHERE id = $1`,
					pendingID, owner)
				require.NoError(t, err)
			}

			// Second delivery of the same body: its dedup check finds nothing uploaded yet,
			// so it re-arms the pending row, and holds the row's lock.
			deliveryTx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer deliveryTx.Rollback(context.Background())
			var deliveryPID int
			require.NoError(t, deliveryTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&deliveryPID))
			insertDeliveredMessageTx(t, db, deliveryTx, accountID, mailboxID, mailboxName, contentHash, instance, 2)

			// The object for the first delivery has been written; finalize it.
			done := make(chan error, 1)
			go func() {
				tx, err := db.GetWritePool().Begin(context.Background())
				if err != nil {
					done <- err
					return
				}
				defer tx.Rollback(context.Background())
				if leased {
					err = db.CompleteLeasedS3Upload(context.Background(), tx, pendingID, owner, contentHash, accountID, []string{key})
				} else {
					err = db.CompleteS3Upload(context.Background(), tx, contentHash, accountID, []string{key})
				}
				if err != nil {
					done <- err
					return
				}
				done <- tx.Commit(context.Background())
			}()

			waitForBlockedOn(t, db, deliveryPID)
			require.NoError(t, deliveryTx.Commit(ctx))
			require.NoError(t, <-done)

			rows, err := db.GetReadPool().Query(ctx,
				`SELECT uid, uploaded FROM messages WHERE content_hash = $1 AND account_id = $2`,
				contentHash, accountID)
			require.NoError(t, err)
			uploaded := map[int64]bool{}
			for rows.Next() {
				var uid int64
				var up bool
				require.NoError(t, rows.Scan(&uid, &up))
				uploaded[uid] = up
			}
			require.NoError(t, rows.Err())
			require.Equal(t, map[int64]bool{1: true, 2: false}, uploaded,
				"precondition: the finalize marks the first delivery, and cannot see the second")

			var attempts int
			err = db.GetReadPool().QueryRow(ctx,
				`SELECT attempts FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
				contentHash, accountID).Scan(&attempts)
			require.NoError(t, err,
				"RE-ARMED UPLOAD DELETED: the finalize deleted the pending upload that the second delivery "+
					"re-armed while it ran. That delivery is left uploaded = FALSE with no pending upload, so "+
					"nothing marks it and CleanupFailedUploads deletes the message.")
			assert.Equal(t, 0, attempts, "the pending upload must stay re-armed")
		})
	}
}
