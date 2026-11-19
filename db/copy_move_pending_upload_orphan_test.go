package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
func insertUnuploadedFixture(t *testing.T, ctx context.Context, db *Database, accountID, mailboxID, uid int64, hash string, attempts int) PendingUpload {
	t.Helper()
	insertRestageFixture(t, ctx, db.GetWritePool(), accountID, mailboxID, uid, hash, false)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid)
	require.NoError(t, err)
	// A dedicated staging instance lets the next pass acquire only this fixture's upload.
	upload := PendingUpload{AccountID: accountID, ContentHash: hash, InstanceID: fmt.Sprintf("move-test-%d", accountID)}
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `
		INSERT INTO pending_uploads (account_id, instance_id, content_hash, size, attempts)
		VALUES ($1, $2, $3, 100, $4) RETURNING id`, accountID, upload.InstanceID, hash, attempts).Scan(&upload.ID))
	return upload
}

// openCopyOrMove runs a same-account COPY or MOVE of uid from inboxID to archiveID and
// leaves its transaction open. It returns the commit function, backend PID, and destination UID.
func openCopyOrMove(t *testing.T, ctx context.Context, db *Database, command string, accountID, inboxID, archiveID, uid int64) (commit func(), pid int, destUID imap.UID) {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { tx.Rollback(context.Background()) })
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	uids := []imap.UID{imap.UID(uid)}
	var uidMap map[imap.UID]imap.UID
	if command == "COPY" {
		uidMap, _, err = db.CopyMessages(ctx, tx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	} else {
		uidMap, err = db.MoveMessages(ctx, tx, &uids, inboxID, archiveID, accountID, "domain", "part", "test-instance", nil, nil)
	}
	require.NoError(t, err)
	destUID = uidMap[imap.UID(uid)]
	require.NotZero(t, destUID, "%s did not return a destination UID for %d", command, uid)
	return func() { require.NoError(t, tx.Commit(ctx)) }, pid, destUID
}

// startUploadWorker returns the PID of the transaction running work and its commit result.
func startUploadWorker(t *testing.T, ctx context.Context, db *Database, work func(pgx.Tx) error) (int, <-chan error) {
	t.Helper()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		tx.Rollback(context.Background())
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer tx.Rollback(context.Background())
		if err := work(tx); err != nil {
			done <- err
			return
		}
		done <- tx.Commit(ctx)
	}()
	return pid, done
}

// requireBlockedBy waits for the worker to block on the open command.
func requireBlockedBy(t *testing.T, ctx context.Context, db *Database, workerPID, commandPID int, done <-chan error, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var blocked bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT $2 = ANY(pg_blocking_pids($1))`,
			workerPID, commandPID).Scan(&blocked))
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
				upload := insertUnuploadedFixture(t, ctx, db, accountID, inboxID, uid, hash, 0)
				if finalize == "leased" {
					leaseRow(t, db, upload.ID, accountID, hash, owner)
				}

				commit, commandPID, destUID := openCopyOrMove(t, ctx, db, command, accountID, inboxID, archiveID, uid)

				workerPID, finalizeDone := startUploadWorker(t, ctx, db, func(tx pgx.Tx) error {
					if finalize == "leased" {
						return db.CompleteLeasedS3Upload(ctx, tx, upload.ID, owner, hash, accountID, []string{key})
					}
					return db.CompleteS3Upload(ctx, tx, hash, accountID, []string{key})
				})
				// The command holds the source row, so the finalize must wait for it and
				// decide only after the new row is visible.
				requireBlockedBy(t, ctx, db, workerPID, commandPID, finalizeDone, "the upload finalize")
				commit()
				require.NoError(t, <-finalizeDone)

				assert.Zero(t, unuploadedRowsWithoutPendingUpload(t, ctx, db, accountID, hash),
					"the new row is not uploaded and has no pending upload, although its body is in S3")

				if command == "MOVE" {
					checkNextMoveUpload(t, ctx, db, upload, archiveID, destUID, key)
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

// MOVE expunged the source, so the next pass needs storage confirmation for the
// destination's key. The first pass already stored the object under storedKey.
func checkNextMoveUpload(t *testing.T, ctx context.Context, db *Database, original PendingUpload, archiveID int64, destUID imap.UID, storedKey string) {
	t.Helper()
	destinationUploaded := func() bool {
		t.Helper()
		var uploaded bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT uploaded FROM messages WHERE mailbox_id = $1 AND uid = $2 AND account_id = $3
			  AND content_hash = $4 AND expunged_at IS NULL`,
			archiveID, int64(destUID), original.AccountID, original.ContentHash).Scan(&uploaded),
			"MOVE destination UID %d is missing from the archive", destUID)
		return uploaded
	}
	require.False(t, destinationUploaded(), "expected the moved message to need a second upload pass")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	queue, err := db.AcquireAndLeasePendingUploads(ctx, tx, original.InstanceID, 1, time.Second, 5)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Len(t, queue, 1, "the next upload pass must find the retained pending row")
	upload := queue[0]
	require.Equal(t, original.ID, upload.ID)

	keys, err := db.PendingUploadKeys(ctx, upload.ContentHash, upload.AccountID)
	require.NoError(t, err)
	require.Equal(t, []string{storedKey}, keys, "the worker must verify the moved message's object in storage")
	const nextOwner = "worker-2"
	leaseRow(t, db, upload.ID, upload.AccountID, upload.ContentHash, nextOwner)
	require.NoError(t, pgx.BeginFunc(ctx, db.GetWritePool(), func(tx pgx.Tx) error {
		return db.CompleteLeasedS3Upload(ctx, tx, upload.ID, nextOwner, upload.ContentHash, upload.AccountID, keys)
	}))

	assert.True(t, destinationUploaded(), "the second upload pass must mark the moved message uploaded")
	pending, err := db.PendingUploadExists(ctx, original.ContentHash, original.AccountID)
	require.NoError(t, err)
	assert.False(t, pending, "the second upload pass must clear the pending row")
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

			commit, commandPID, _ := openCopyOrMove(t, ctx, db, command, accountID, inboxID, archiveID, uid)

			workerPID, deleteDone := startUploadWorker(t, ctx, db, func(tx pgx.Tx) error {
				_, err := db.DeleteFailedUpload(ctx, tx, hash, accountID, maxAttempts)
				return err
			})
			requireBlockedBy(t, ctx, db, workerPID, commandPID, deleteDone, "DeleteFailedUpload")
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
