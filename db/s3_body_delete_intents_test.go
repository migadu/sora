package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestS3BodyIntentBlocksClaimAndFinalization(t *testing.T) {
	d, _, account, mailbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("intent-claims-%d", time.Now().UnixNano())
	insertKeyedMessage(t, d, account, mailbox, 1, hash, "intent", false, time.Time{})
	pending := createPendingUpload(t, d, account, "intent-claim", hash, 0, time.Time{}, 100)
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot,created_at) VALUES($1,$2,ARRAY[$3], '[]',now()-interval '100 years')`, hash, uuid.NewString(), "example.com/intent/"+hash)
	require.NoError(t, err)
	gate, err := d.PassS3WriteGate(ctx, pending, account, hash, "claim", time.Minute)
	require.NoError(t, err)
	require.Equal(t, S3WriteBusy, gate)
	for _, mode := range []string{"copy-move", "legacy-finalize", "leased-finalize"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			switch mode {
			case "copy-move":
				err = LockS3ObjectsSharedInTx(ctx, tx, account, []string{hash})
			case "legacy-finalize":
				err = d.CompleteS3Upload(ctx, tx, hash, account, []string{"example.com/intent/" + hash})
			case "leased-finalize":
				err = d.CompleteLeasedS3Upload(ctx, tx, pending, "claim", hash, account, []string{"example.com/intent/" + hash})
			}
			require.ErrorIs(t, err, ErrS3BodyQuarantined)
		})
	}
	var uploaded bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE account_id=$1 AND content_hash=$2`, account, hash).Scan(&uploaded))
	require.False(t, uploaded)
	lock, err := d.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer lock.Release()
	require.NoError(t, lock.Lock(ctx, GetS3ObjectLockID(0, hash)))
	require.ErrorIs(t, lock.CheckS3BodyClaims(ctx, []string{hash}), ErrS3BodyQuarantined)
}

func TestS3BodyClaimRejectsPinnedRepeatableReadSnapshot(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	tx, err := d.GetWritePool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT 1`)
	require.NoError(t, err)
	require.ErrorIs(t, LockS3ObjectsSharedInTx(ctx, tx, 1, []string{fmt.Sprintf("rr-%d", time.Now().UnixNano())}), ErrS3BodyQuarantined)
}

func TestS3BodyReconcileExactIntentAndReferenceLifecycle(t *testing.T) {
	d, _, account, mailbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("reconcile-%d", time.Now().UnixNano())
	key := "example.com/reconcile/" + hash
	insertKeyedMessage(t, d, account, mailbox, 1, hash, "reconcile", true, time.Now().Add(-48*time.Hour))
	objects := []UserScopedObjectForCleanup{{AccountID: account, ContentHash: hash, S3Domain: "example.com", S3Localpart: "reconcile"}}
	failure := errors.New("accepted request outcome unknown")
	_, err := d.ExecuteWithS3BodyCleanup(ctx, objects, time.Hour, func(context.Context, []UserScopedObjectForCleanup) (S3BodyCleanupResult, error) {
		return S3BodyCleanupResult{}, failure
	})
	require.ErrorIs(t, err, failure)
	intents, err := d.ListS3BodyDeleteIntents(ctx)
	require.NoError(t, err)
	var intent S3BodyDeleteIntent
	for _, i := range intents {
		if i.ContentHash == hash {
			intent = i
		}
	}
	require.NotEmpty(t, intent.OperationID)
	require.Len(t, intent.RetireSnapshot, 1)
	calls := 0
	callback := func(context.Context, S3BodyDeleteIntent, map[string]bool) error { calls++; return nil }
	require.Error(t, d.ReconcileS3BodyDeleteIntent(ctx, hash, intent.OperationID, false, callback))
	require.Zero(t, calls)
	require.Error(t, d.ReconcileS3BodyDeleteIntent(ctx, hash, uuid.NewString(), true, callback))
	require.Zero(t, calls)
	// The old eligible expunge alone does not turn an orphan-only key into a
	// protected reference. A later lifecycle, including a live copy, does.
	err = d.ReconcileS3BodyDeleteIntent(ctx, hash, intent.OperationID, true, func(_ context.Context, _ S3BodyDeleteIntent, required map[string]bool) error {
		require.False(t, required[key])
		return failure
	})
	require.ErrorIs(t, err, failure)
	insertKeyedMessage(t, d, account, mailbox, 2, hash, "reconcile", true, time.Time{})
	err = d.ReconcileS3BodyDeleteIntent(ctx, hash, intent.OperationID, true, func(_ context.Context, _ S3BodyDeleteIntent, required map[string]bool) error {
		require.True(t, required[key])
		return failure
	})
	require.ErrorIs(t, err, failure)
	var count int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&count))
	require.Equal(t, 1, count)
	// This is where the CLI's storage verifier checks/restores the protected bytes.
	require.NoError(t, d.ReconcileS3BodyDeleteIntent(ctx, hash, intent.OperationID, true, func(_ context.Context, _ S3BodyDeleteIntent, required map[string]bool) error {
		require.True(t, required[key])
		return nil
	}))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&count))
	require.Zero(t, count)
}

func TestS3BodyIntentMigrationRefusesUnknownOutcomeDowngrade(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("down-intent-%d", time.Now().UnixNano())
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2,ARRAY[$3],'[]')`, hash, uuid.NewString(), "example.com/down/"+hash)
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000072_s3_body_delete_intents.down.sql")
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, string(down))
	require.ErrorContains(t, err, "reconcile")
	var count int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&count))
	require.Equal(t, 1, count)
}

func TestS3BodyIntentBlocksRestore(t *testing.T) {
	d, email, account, mailbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("intent-restore-%d", time.Now().UnixNano())
	insertKeyedMessage(t, d, account, mailbox, 1, hash, "restore", true, time.Now().Add(-48*time.Hour))
	var message int64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT id FROM messages WHERE account_id=$1 AND content_hash=$2`, account, hash).Scan(&message))
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2,ARRAY[$3],'[]')`, hash, uuid.NewString(), "example.com/restore/"+hash)
	require.NoError(t, err)
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = d.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: email, MessageIDs: []int64{message}})
	require.ErrorIs(t, err, ErrS3BodyQuarantined)
}
