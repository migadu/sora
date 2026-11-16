package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

// The rekey transaction holds both its new body's shared lock and the account
// rekey lock. A queued deleter wins the new-body lock on commit; restore must read
// the new hash after the account guard and wait for that body before admitting it.
func TestRestoreBodyAdmissionReadsHashAfterRekeyGuard(t *testing.T) {
	d, email, account, inbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	oldHash := helpers.HashContent([]byte(fmt.Sprintf("old-%d", time.Now().UnixNano())))
	newHash := helpers.HashContent([]byte(oldHash + "new"))
	insertKeyedMessage(t, d, account, inbox, 1, oldHash, "restore-rekey", true, time.Now().Add(-48*time.Hour))
	_, err := d.GetWritePool().Exec(ctx, `UPDATE mailboxes SET highest_uid=1 WHERE id=$1`, inbox)
	require.NoError(t, err)
	var id int64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT id FROM messages WHERE account_id=$1 AND content_hash=$2`, account, oldHash).Scan(&id))
	rekey, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer rekey.Rollback(context.Background())
	var rekeyPID int
	require.NoError(t, rekey.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&rekeyPID))
	_, err = d.RekeyContentHash(ctx, rekey, account, ContentObject{ContentHash: oldHash, S3Domain: "example.com", S3Localpart: "restore-rekey"}, newHash)
	require.NoError(t, err)
	deletion, err := d.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer deletion.Release()
	locked := make(chan error, 1)
	go func() { locked <- deletion.Lock(ctx, GetS3ObjectLockID(account, newHash)) }()
	require.Eventually(t, func() bool {
		var n int
		err := d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, rekeyPID).Scan(&n)
		return err == nil && n > 0
	}, time.Second, 5*time.Millisecond, "deleter did not queue behind actual rekey body's shared lock")
	restore, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer restore.Rollback(context.Background())
	var restorePID int
	require.NoError(t, restore.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&restorePID))
	done := make(chan error, 1)
	go func() {
		_, e := d.RestoreMessages(ctx, restore, RestoreMessagesParams{Email: email, MessageIDs: []int64{id}})
		if e == nil {
			e = restore.Commit(ctx)
		}
		done <- e
	}()
	require.Eventually(t, func() bool {
		var blocked bool
		err := d.GetWritePool().QueryRow(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, rekeyPID, restorePID).Scan(&blocked)
		return err == nil && blocked
	}, time.Second, 5*time.Millisecond, "restore did not wait on the still-uncommitted rekey")
	require.NoError(t, rekey.Commit(ctx))
	require.NoError(t, <-locked)
	var finishErr error
	finished := false
	waitingNewHash := false
	lockID := uint64(GetS3ObjectLockID(account, newHash))
	deadline := time.After(time.Second)
observe:
	for {
		select {
		case finishErr = <-done:
			finished = true
			break observe
		case <-deadline:
			break observe
		default:
		}
		require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted AND mode='ShareLock' AND classid=$2::bigint::oid AND objid=$3::bigint::oid AND objsubid=1)`, restorePID, int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&waitingNewHash))
		if waitingNewHash {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	deletion.Release()
	if !finished {
		select {
		case finishErr = <-done:
		case <-ctx.Done():
			t.Fatal("restore did not finish after deleter released new hash")
		}
	}
	require.NoError(t, finishErr)
	require.True(t, waitingNewHash, "restore admitted the rekeyed body under a stale old-hash lock")
	var restoredHash string
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT content_hash FROM messages WHERE account_id=$1 AND expunged_at IS NULL`, account).Scan(&restoredHash))
	require.Equal(t, newHash, restoredHash)
}
