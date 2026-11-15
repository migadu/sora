package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCleanupFailedUploadsSparesAPendingUploadReArmedMidStatement covers the window
// between the two halves of CleanupFailedUploads' statement.
//
// deleted_messages judges a pending upload dead from the statement's snapshot, and
// deleted_pending then deletes every pending row with that (content_hash, account_id).
// A delivery that re-arms the row (InsertMessage: attempts = 0, instance_id = its own,
// last_attempt = NULL) while the cleaner runs holds the row's lock; the cleaner's DELETE
// waits for it and, under READ COMMITTED, re-checks only its own WHERE clause on the
// re-armed version. The key is unchanged, so without a liveness re-check the re-armed
// row is deleted, the new delivery is left with no pending upload at all, and a later
// run reaps it although its body is staged on a live node.
func TestCleanupFailedUploadsSparesAPendingUploadReArmedMidStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	const maxAttempts = 5
	const gracePeriod = 24 * time.Hour
	const liveness = time.Hour

	// Each case makes the first delivery's pending row one that nothing will upload, as
	// of the cleaner's snapshot.
	cases := []struct {
		name               string
		exhaust            bool // the row has used up its attempts
		goneOwner          bool // the row belongs to an instance that stopped beating
		heartbeatCatchesUp bool // the heartbeat commits after the cleaner takes its snapshot
	}{
		{name: "attempts exhausted", exhaust: true},
		// The re-arm also moves the row to another instance, so the re-check has to look
		// up the heartbeat of the instance on the re-armed version.
		{name: "owner instance gone", goneOwner: true},
		{name: "heartbeat catches up while waiting", exhaust: true, heartbeatCatchesUp: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDatabase(t)
			defer db.Close()

			ctx := context.Background()
			ts := time.Now().UnixNano()

			accountID := createTestAccount(t, db, fmt.Sprintf("rearm_race_%d@example.com", ts), "password")
			mailboxName := fmt.Sprintf("ReArmRaceBox_%d", ts)
			mailboxID := createTestMailbox(t, db, accountID, mailboxName)
			contentHash := fmt.Sprintf("rearm_race_hash_%d", ts)

			liveInstance := fmt.Sprintf("rearm_race_live_%d", ts)
			goneInstance := fmt.Sprintf("rearm_race_gone_%d", ts)
			liveSeen := time.Now()
			if tc.heartbeatCatchesUp {
				liveSeen = liveSeen.Add(-2 * time.Hour)
			}
			_, err := db.GetWritePool().Exec(ctx, `
				INSERT INTO instance_heartbeats (instance_id, last_seen)
				VALUES ($1, $3), ($2, now() - interval '2 hours')`, liveInstance, goneInstance, liveSeen)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = db.GetWritePool().Exec(context.Background(),
					`DELETE FROM instance_heartbeats WHERE instance_id IN ($1, $2)`, liveInstance, goneInstance)
			})

			// First delivery: its pending row becomes dead and the message ages past the
			// grace period, so the cleaner reaps both.
			firstOwner := liveInstance
			if tc.goneOwner {
				firstOwner = goneInstance
			}
			insertDeliveredMessage(t, db, accountID, mailboxID, mailboxName, contentHash, firstOwner, 1)
			if tc.exhaust {
				tx, err := db.GetWritePool().Begin(ctx)
				require.NoError(t, err)
				for i := 0; i < maxAttempts; i++ {
					require.NoError(t, db.MarkUploadAttempt(ctx, tx, contentHash, accountID))
				}
				require.NoError(t, tx.Commit(ctx))
			}
			_, err = db.GetWritePool().Exec(ctx,
				`UPDATE messages SET created_at = now() - interval '25 hours' WHERE content_hash = $1`, contentHash)
			require.NoError(t, err)

			// Second delivery on the live node re-arms the row and holds its lock.
			deliveryTx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer deliveryTx.Rollback(context.Background())
			var deliveryPID int
			require.NoError(t, deliveryTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&deliveryPID))
			insertDeliveredMessageTx(t, db, deliveryTx, accountID, mailboxID, mailboxName, contentHash, liveInstance, 2)

			// The cleaner starts while the delivery is open, so its snapshot still holds
			// the dead row.
			type result struct {
				cleaned int64
				err     error
			}
			done := make(chan result, 1)
			go func() {
				tx, err := db.GetWritePool().Begin(context.Background())
				if err != nil {
					done <- result{err: err}
					return
				}
				defer tx.Rollback(context.Background())
				cleaned, err := db.CleanupFailedUploads(context.Background(), tx, gracePeriod, maxAttempts, liveness)
				if err == nil {
					err = tx.Commit(context.Background())
				}
				done <- result{cleaned, err}
			}()

			waitForBlockedOn(t, db, deliveryPID)
			if tc.heartbeatCatchesUp {
				// The pending-row recheck sees the delivery's new version, but
				// its heartbeat subquery still reads the cleaner's old snapshot.
				hbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				_, err := db.GetWritePool().Exec(hbCtx,
					`UPDATE instance_heartbeats SET last_seen = now() WHERE instance_id = $1`, liveInstance)
				require.NoError(t, err)
			}
			require.NoError(t, deliveryTx.Commit(ctx))

			res := <-done
			require.NoError(t, res.err)
			require.Equal(t, int64(1), res.cleaned,
				"precondition: the cleaner reaps the first delivery, judged dead from its snapshot")

			var uploaded bool
			require.NoError(t, db.GetReadPool().QueryRow(ctx,
				`SELECT uploaded FROM messages WHERE content_hash = $1 AND account_id = $2`,
				contentHash, accountID).Scan(&uploaded))
			require.False(t, uploaded, "the second delivery is staged on the live node, not uploaded yet")

			var attempts int
			var owner string
			err = db.GetReadPool().QueryRow(ctx,
				`SELECT attempts, instance_id FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
				contentHash, accountID).Scan(&attempts, &owner)
			require.NoError(t, err,
				"RE-ARMED UPLOAD DELETED: the cleaner deleted the pending upload that the second delivery "+
					"re-armed while the cleaner ran. That delivery is left uploaded = FALSE with no pending "+
					"upload, so nothing uploads its body and a later cleaner run deletes the message.")
			assert.Equal(t, 0, attempts, "the pending upload must stay re-armed")
			assert.Equal(t, liveInstance, owner, "the pending upload must stay with the node holding the body")
		})
	}
}
