package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Pipelining must not reuse the snapshot taken before a blocking body lock.
// A deleter's durable intent committed while finalization waits must be seen
// before either completion API marks messages uploaded or retires pending work.
func TestUploadFinalizeBatchSeesIntentCommittedWhileWaiting(t *testing.T) {
	d, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer d.Close()
	for index, leased := range []bool{false, true} {
		t.Run(fmt.Sprintf("leased=%t", leased), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			hash := fmt.Sprintf("finalize-snapshot-%d-%d", time.Now().UnixNano(), index)
			insertKeyedMessage(t, d, accountID, mailboxID, 9900+index, hash, "snapshot", false, time.Time{})
			pending := createPendingUpload(t, d, accountID, "snapshot", hash, 0, time.Time{}, 100)
			if leased {
				leaseRow(t, d, pending, accountID, hash, gateTestOwner)
			}
			holder, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer holder.Rollback(context.Background())
			_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, GetS3ObjectLockID(accountID, hash))
			require.NoError(t, err)
			writer, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer writer.Rollback(context.Background())
			var pid int
			require.NoError(t, writer.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			done := make(chan error, 1)
			go func() {
				keys := []string{"example.com/snapshot/" + hash}
				if leased {
					done <- d.CompleteLeasedS3Upload(ctx, writer, pending, gateTestOwner, hash, accountID, keys)
				} else {
					done <- d.CompleteS3Upload(ctx, writer, hash, accountID, keys)
				}
			}()
			require.Eventually(t, func() bool {
				var waiting bool
				err := d.GetWritePool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting)
				return err == nil && waiting
			}, 3*time.Second, 10*time.Millisecond)
			_, err = holder.Exec(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2::uuid,$3,'[]'::jsonb)`, hash, uuid.NewString(), []string{"example.com/snapshot/" + hash})
			require.NoError(t, err)
			require.NoError(t, holder.Commit(ctx))
			require.ErrorIs(t, <-done, ErrS3BodyQuarantined)
			require.NoError(t, writer.Rollback(ctx))
			var uploaded bool
			require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE mailbox_id=$1 AND content_hash=$2`, mailboxID, hash).Scan(&uploaded))
			require.False(t, uploaded)
			var count int
			require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE id=$1`, pending).Scan(&count))
			require.Equal(t, 1, count)
			_, err = d.GetWritePool().Exec(ctx, `DELETE FROM s3_body_delete_intents WHERE content_hash=$1`, hash)
			require.NoError(t, err)
		})
	}
}
