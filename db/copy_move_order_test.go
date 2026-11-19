package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

func TestCopyLocksSourcesAtInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, inboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	copyDest := createRestageMailbox(t, ctx, db, accountID, "Copy")
	moveDest := createRestageMailbox(t, ctx, db, accountID, "Move")
	stamp := time.Now().UnixNano()
	pendingHash := fmt.Sprintf("copy_move_pending_%d", stamp)
	uploadedHash := fmt.Sprintf("copy_move_uploaded_%d", stamp)
	const pendingUID, uploadedUID = 1, 2
	pool := db.GetWritePool()
	insertRestageFixture(t, ctx, pool, accountID, inboxID, pendingUID, pendingHash, false)
	insertRestageFixture(t, ctx, pool, accountID, inboxID, uploadedUID, uploadedHash, false)
	_, err := pool.Exec(ctx, `UPDATE messages SET uploaded = FALSE WHERE mailbox_id = $1 AND uid = $2`, inboxID, pendingUID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id)
		VALUES ($1, $2, 100, 'staging-instance')
	`, accountID, pendingHash)
	require.NoError(t, err)

	copyTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer copyTx.Rollback(context.Background())
	paused := newPauseTx(copyTx, "WITH src_data")
	copyDone := make(chan error, 1)
	var copied map[imap.UID]imap.UID
	go func() {
		defer close(copyDone)
		copyUIDs := []imap.UID{pendingUID, uploadedUID}
		var err error
		copied, _, err = db.CopyMessages(ctx, paused, &copyUIDs, inboxID, copyDest, accountID, "domain", "part", "copy-instance", nil, nil)
		copyDone <- err
	}()
	defer func() {
		cancel()
		<-copyDone
	}()
	select {
	case <-paused.reached:
	case err := <-copyDone:
		t.Fatalf("COPY returned before its insert: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	upload, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer upload.Rollback(context.Background())
	require.NoError(t, db.CompleteS3Upload(ctx, upload, pendingHash, accountID, []string{"domain/part/" + pendingHash}))
	require.NoError(t, upload.Commit(ctx))

	// COPY is paused before inserting and must leave both sources available to MOVE.
	// Roll back MOVE so the same rows are still there when COPY resumes.
	moveTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer moveTx.Rollback(context.Background())
	_, err = moveTx.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`)
	require.NoError(t, err)
	moveUIDs := []imap.UID{pendingUID, uploadedUID}
	moved, err := db.MoveMessages(ctx, moveTx, &moveUIDs, inboxID, moveDest, accountID, "domain", "part", "move-instance", nil, nil)
	require.NoError(t, err, "COPY held a source row before inserting")
	require.Len(t, moved, 2)
	require.NoError(t, moveTx.Rollback(ctx))

	close(paused.resume)
	require.NoError(t, <-copyDone)
	require.Len(t, copied, 2)
	require.NoError(t, copyTx.Commit(ctx))

	var hashes []string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT array_agg(content_hash) FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL AND uploaded
	`, copyDest).Scan(&hashes))
	require.ElementsMatch(t, []string{pendingHash, uploadedHash}, hashes)
	require.Equal(t, []imap.UID{pendingUID, uploadedUID}, mailboxUIDs(t, db, inboxID))
	require.Empty(t, mailboxUIDs(t, db, moveDest))
	pending, err := db.PendingUploadExists(ctx, pendingHash, accountID)
	require.NoError(t, err)
	require.False(t, pending)
}
