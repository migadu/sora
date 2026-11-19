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

// unuploadedRowsWithoutPendingUpload counts the live rows of (accountID, hash) that are
// not uploaded and have no pending upload: nothing will ever upload them, and
// CleanupFailedUploads deletes them once they are past its grace period.
func unuploadedRowsWithoutPendingUpload(t *testing.T, ctx context.Context, db *Database, accountID int64, hash string) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `
		SELECT count(*) FROM messages m
		WHERE m.account_id = $1 AND m.content_hash = $2 AND m.expunged_at IS NULL AND NOT m.uploaded
		  AND NOT EXISTS (SELECT 1 FROM pending_uploads pu WHERE pu.account_id = m.account_id AND pu.content_hash = m.content_hash)`,
		accountID, hash).Scan(&n))
	return n
}

// insertUnuploadedFixture inserts a live, not yet uploaded message with its pending upload.
func insertUnuploadedFixture(t *testing.T, ctx context.Context, db *Database, accountID, mailboxID, uid int64, hash string, attempts int) {
	t.Helper()
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, mailboxID, uid, hash, false)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `INSERT INTO pending_uploads (account_id, instance_id, content_hash, size, attempts) VALUES ($1, 'other-instance', $2, 100, $3)`, accountID, hash, attempts)
	require.NoError(t, err)
}

// openCopyOrMove runs a same-account COPY or MOVE of uid from inboxID to archiveID and
// leaves its transaction open. It returns the backend pid of that transaction.
func openCopyOrMove(t *testing.T, ctx context.Context, db *Database, command string, accountID, inboxID, archiveID, uid int64) (commit func(), pid int) {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { tx.Rollback(context.Background()) })
	pid = int(tx.Conn().PgConn().PID())
	uids := []imap.UID{imap.UID(uid)}
	if command == "COPY" {
		_, _, err = db.CopyMessages(ctx, tx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	} else {
		_, err = db.MoveMessages(ctx, tx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	}
	require.NoError(t, err)
	return func() { require.NoError(t, tx.Commit(ctx)) }, pid
}

// requireBlockedBy fails the test unless some backend waits for a lock that blockerPID
// holds before done yields. A worker that finishes without waiting for the open command
// decided without seeing the command's new row: the race these tests are about.
func requireBlockedBy(t *testing.T, ctx context.Context, db *Database, blockerPID int, done <-chan error, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var blocked bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`,
			blockerPID).Scan(&blocked))
		if blocked {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("%s finished without waiting for the open command (err: %v)", what, err)
		default:
		}
		require.False(t, time.Now().After(deadline), "%s never waited for the open command", what)
		time.Sleep(5 * time.Millisecond)
	}
}

// A same-account COPY or MOVE of a message that is not uploaded yet relies on the
// source's pending upload: its new row is not uploaded either, and restagePendingUploads
// leaves an existing pending row alone. Whatever deletes that row while the command is
// open cannot see the new row, and must not leave it behind without one: nothing would
// ever mark it uploaded, and CleanupFailedUploads would delete the message (#2126).
//
// Here the upload finishes while the command is open. The command holds the source row
// (COPY FOR SHARE, MOVE FOR UPDATE), so marking it uploaded waits for the commit; the
// finalize then sees the new row and keeps the pending upload for it. Had it decided
// first, it would drop the pending row with the body in S3 and the new row unmarked.
func TestUploadFinishingDuringSameAccountCopyOrMoveKeepsThePendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	for _, command := range []string{"COPY", "MOVE"} {
		for _, finalize := range []string{"unleased", "leased"} {
			t.Run(command+"/"+finalize, func(t *testing.T) {
				db, _, accountID, inboxID := setupCleanerTestDatabase(t)
				t.Cleanup(db.Close) // after openCopyOrMove's rollback: Close waits for the open transaction

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
				hash := fmt.Sprintf("upload_finishes_%s_%s_%d", command, finalize, time.Now().UnixNano())
				key := "domain/part/" + hash
				const uid, owner = 9901, "worker-1"
				insertUnuploadedFixture(t, ctx, db, accountID, inboxID, uid, hash, 0)
				var pendingID int64
				if finalize == "leased" {
					// The uploader's path: it finalizes under the lease it wrote with.
					require.NoError(t, db.GetWritePool().QueryRow(ctx, `
						UPDATE pending_uploads SET lease_owner = $3, lease_until = now() + interval '10 minutes'
						WHERE account_id = $1 AND content_hash = $2 RETURNING id`, accountID, hash, owner).Scan(&pendingID))
				}

				commit, commandPID := openCopyOrMove(t, ctx, db, command, accountID, inboxID, archiveID, uid)

				finalizeDone := make(chan error, 1)
				go func() {
					tx, err := db.GetWritePool().Begin(ctx)
					if err != nil {
						finalizeDone <- err
						return
					}
					defer tx.Rollback(context.Background())
					if finalize == "leased" {
						err = db.CompleteLeasedS3Upload(ctx, tx, pendingID, owner, hash, accountID, []string{key})
					} else {
						err = db.CompleteS3Upload(ctx, tx, hash, accountID, []string{key})
					}
					if err != nil {
						finalizeDone <- err
						return
					}
					finalizeDone <- tx.Commit(ctx)
				}()
				// The command holds the source row, so the finalize must wait for it and
				// decide only after the new row is visible.
				requireBlockedBy(t, ctx, db, commandPID, finalizeDone, "the upload finalize")
				commit()
				require.NoError(t, <-finalizeDone)

				assert.Zero(t, unuploadedRowsWithoutPendingUpload(t, ctx, db, accountID, hash),
					"the new row is not uploaded and has no pending upload, although its body is in S3")

				if command != "COPY" {
					return
				}
				// The pending row that was kept gets the copy marked: the next lease finds
				// nothing left to write and finalizes from the source row, which proves the
				// object.
				tx, err := db.GetWritePool().Begin(ctx)
				require.NoError(t, err)
				defer tx.Rollback(context.Background())
				require.NoError(t, db.CompleteS3Upload(ctx, tx, hash, accountID, nil))
				require.NoError(t, tx.Commit(ctx))
				var live, uploaded, pending int
				require.NoError(t, db.GetWritePool().QueryRow(ctx, `
					SELECT count(*), count(*) FILTER (WHERE uploaded),
					       (SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2)
					FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL`,
					accountID, hash).Scan(&live, &uploaded, &pending))
				assert.Equal(t, 2, live)
				assert.Equal(t, 2, uploaded, "the copy was not marked uploaded")
				assert.Zero(t, pending, "the pending upload outlived its last unuploaded row")
			})
		}
	}
}

// Here the admin tool deletes a parked upload while the command is open. It waits for the
// command at the account guard (lockAccountAgainstCopies) before it picks the mailboxes
// and rows to delete, so it takes the new row with the rest instead of leaving it
// behind without a pending upload.
func TestDeleteFailedUploadDuringSameAccountCopyOrMoveLeavesNoRowBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			db, _, accountID, inboxID := setupCleanerTestDatabase(t)
			t.Cleanup(db.Close) // after openCopyOrMove's rollback: Close waits for the open transaction

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			archiveID := createRestageMailbox(t, ctx, db, accountID, "Archive")
			hash := fmt.Sprintf("delete_failed_%s_%d", command, time.Now().UnixNano())
			const uid, maxAttempts = 9911, 5
			insertUnuploadedFixture(t, ctx, db, accountID, inboxID, uid, hash, maxAttempts)

			commit, commandPID := openCopyOrMove(t, ctx, db, command, accountID, inboxID, archiveID, uid)

			deleteDone := make(chan error, 1)
			go func() {
				tx, err := db.GetWritePool().Begin(ctx)
				if err != nil {
					deleteDone <- err
					return
				}
				defer tx.Rollback(context.Background())
				if _, err := db.DeleteFailedUpload(ctx, tx, hash, accountID, maxAttempts); err != nil {
					deleteDone <- err
					return
				}
				deleteDone <- tx.Commit(ctx)
			}()
			requireBlockedBy(t, ctx, db, commandPID, deleteDone, "DeleteFailedUpload")
			commit()
			require.NoError(t, <-deleteDone)

			assert.Zero(t, unuploadedRowsWithoutPendingUpload(t, ctx, db, accountID, hash),
				"the new row is not uploaded and has no pending upload")
			// The tool waited for the command and took the new row with the rest.
			var rows, pending int
			require.NoError(t, db.GetWritePool().QueryRow(ctx, `
				SELECT (SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2),
				       (SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2)`,
				accountID, hash).Scan(&rows, &pending))
			assert.Zero(t, rows, "message rows of the lost body are left")
			assert.Zero(t, pending, "the pending upload of the lost body is left")
		})
	}
}
