//go:build integration
// +build integration

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

// TestCleanupFailedUploadsSkipsBusyMailbox runs the failed-upload reaper while a \Seen
// STORE holds Archive, one of the two mailboxes with a reapable message. The reaper must
// not wait for the STORE: while it waited it held INBOX, the mailbox before Archive, and
// deliveries and flag changes there queued behind the cleaner. It reaps the INBOX message
// at once and leaves the Archive one live for the next cycle, which reaps it once Archive
// is free. The cached counts stay right throughout.
func TestCleanupFailedUploadsSkipsBusyMailbox(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	f := setupHardDeleteFixture(t, db, "INBOX", "Archive")
	_, err := db.GetWritePool().Exec(ctx,
		`UPDATE messages SET created_at = now() - interval '2 hours' WHERE account_id = $1 AND content_hash = $2`,
		f.accountID, f.hash)
	require.NoError(t, err)

	// lostIn reports whether mbox still has a row for the lost body, and whether it is live.
	lostIn := func(mbox *DBMailbox) (exists, live bool) {
		t.Helper()
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT count(*) > 0, COALESCE(bool_or(expunged_at IS NULL), false)
			FROM messages WHERE account_id = $1 AND content_hash = $2 AND mailbox_id = $3
		`, f.accountID, f.hash, mbox.ID).Scan(&exists, &live))
		return exists, live
	}

	// tx1: mark the Archive message \Seen and hold the transaction open, as a STORE in
	// flight does.
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)
	_, _, err = db.AddMessageFlags(ctx, tx1, f.uids[1], f.archive.ID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	var pid2 int
	require.NoError(t, tx2.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid2))

	done := make(chan error, 1)
	go func() {
		_, err := db.CleanupFailedUploads(ctx, tx2, time.Hour, hardDeleteMaxAttempts, time.Hour)
		done <- err
	}()

	// The reaper must finish without ever waiting on a lock. If it does wait, end the STORE
	// so that it can finish before the test fails.
	waited := false
	deadline := time.Now().Add(30 * time.Second)
	for finished := false; !finished; {
		select {
		case err := <-done:
			require.NoError(t, err)
			finished = true
			continue
		default:
		}
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) FROM pg_stat_activity WHERE pid = $1`,
			pid2).Scan(&waited))
		if waited {
			require.NoError(t, tx1.Rollback(ctx))
			<-done
			break
		}
		require.False(t, time.Now().After(deadline), "CleanupFailedUploads did not finish")
		time.Sleep(5 * time.Millisecond)
	}
	require.False(t, waited, "CleanupFailedUploads waited on the mailbox a concurrent STORE holds")
	require.NoError(t, tx2.Commit(ctx))
	require.NoError(t, tx1.Commit(ctx))

	exists, _ := lostIn(f.inbox)
	require.False(t, exists, "the INBOX message is reaped in the first cycle")
	exists, live := lostIn(f.archive)
	require.True(t, exists && live, "the message in the busy Archive stays live for the next cycle")
	requireHardDeleteStats(t, db, f)

	inTx(t, db, func(tx pgx.Tx) {
		_, err := db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
		require.NoError(t, err)
	})
	exists, _ = lostIn(f.archive)
	require.False(t, exists, "the next cycle reaps the Archive message")
	requireHardDeleteStats(t, db, f)
}

// TestCleanupFailedUploadsPreservesSharedPendingUploadForRemainingMessage checks that
// reaping one copy of an unuploaded body does not delete the account's shared
// pending_uploads row while another unuploaded copy of the same body was skipped (for
// example in a busy mailbox).
//
// Otherwise, if the offline storage node holding the staged file comes back online before
// the next cleanup cycle, its pending_uploads row is already gone: the uploader will not
// upload the body, cleanupOrphanedFiles will delete the staged file, and the next cleanup
// cycle will permanently delete the remaining live message even though its owner node is
// healthy again.
func TestCleanupFailedUploadsPreservesSharedPendingUploadForRemainingMessage(t *testing.T) {
	t.Run("owner comes back online before next cycle", func(t *testing.T) {
		db := setupTestDatabase(t)
		defer db.Close()
		ctx := context.Background()
		f := setupHardDeleteFixture(t, db, "INBOX", "Archive")

		instanceID := fmt.Sprintf("busy_shared_recover_%d", time.Now().UnixNano())
		_, err := db.GetWritePool().Exec(ctx,
			`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now() - interval '2 hours')`,
			instanceID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = db.GetWritePool().Exec(context.Background(),
				`DELETE FROM instance_heartbeats WHERE instance_id = $1`, instanceID)
		})

		_, err = db.GetWritePool().Exec(ctx,
			`UPDATE pending_uploads SET attempts = 0, instance_id = $3, last_attempt = NULL WHERE account_id = $1 AND content_hash = $2`,
			f.accountID, f.hash, instanceID)
		require.NoError(t, err)
		_, err = db.GetWritePool().Exec(ctx,
			`UPDATE messages SET created_at = now() - interval '2 hours' WHERE account_id = $1 AND content_hash = $2`,
			f.accountID, f.hash)
		require.NoError(t, err)

		msgState := func(mbox *DBMailbox) (exists, live bool) {
			t.Helper()
			require.NoError(t, db.GetWritePool().QueryRow(ctx, `
				SELECT count(*) > 0, COALESCE(bool_or(expunged_at IS NULL), false)
				FROM messages WHERE account_id = $1 AND content_hash = $2 AND mailbox_id = $3
			`, f.accountID, f.hash, mbox.ID).Scan(&exists, &live))
			return exists, live
		}
		pendingCount := func() (n int) {
			t.Helper()
			require.NoError(t, db.GetWritePool().QueryRow(ctx, `
				SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2
			`, f.accountID, f.hash).Scan(&n))
			return n
		}

		// Hold Archive open while cycle 1 runs: INBOX is reaped, Archive stays live.
		tx1, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx1.Rollback(ctx)
		_, _, err = db.AddMessageFlags(ctx, tx1, f.uids[1], f.archive.ID, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err)

		var reaped1 int64
		inTx(t, db, func(tx pgx.Tx) {
			reaped1, err = db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
			require.NoError(t, err)
		})
		require.Equal(t, int64(1), reaped1, "cycle 1 reaps only the INBOX copy")

		exists, _ := msgState(f.inbox)
		require.False(t, exists, "the INBOX copy is reaped in cycle 1")
		exists, live := msgState(f.archive)
		require.True(t, exists && live, "the Archive copy stays live while Archive is busy")
		assert.Equal(t, 1, pendingCount(), "shared pending_uploads row must remain while the Archive copy is still unuploaded")

		// The offline node comes back online with its local staging directory intact and
		// refreshes its heartbeat before cycle 2 runs.
		_, err = db.GetWritePool().Exec(ctx,
			`UPDATE instance_heartbeats SET last_seen = now() WHERE instance_id = $1`,
			instanceID)
		require.NoError(t, err)
		require.NoError(t, tx1.Commit(ctx))
		requireHardDeleteStats(t, db, f)

		var reaped2 int64
		inTx(t, db, func(tx pgx.Tx) {
			reaped2, err = db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
			require.NoError(t, err)
		})
		assert.Equal(t, int64(0), reaped2, "cycle 2 must spare the Archive copy once its owner node is alive again")
		exists, live = msgState(f.archive)
		assert.True(t, exists && live, "the Archive copy must stay live so the recovered node can upload its body")
		assert.Equal(t, 1, pendingCount(), "pending_uploads row must stay queued for the recovered node")
		requireHardDeleteStats(t, db, f)
	})

	t.Run("owner stays gone on next cycle", func(t *testing.T) {
		db := setupTestDatabase(t)
		defer db.Close()
		ctx := context.Background()
		f := setupHardDeleteFixture(t, db, "INBOX", "Archive")

		instanceID := fmt.Sprintf("busy_shared_gone_%d", time.Now().UnixNano())
		_, err := db.GetWritePool().Exec(ctx,
			`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now() - interval '2 hours')`,
			instanceID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = db.GetWritePool().Exec(context.Background(),
				`DELETE FROM instance_heartbeats WHERE instance_id = $1`, instanceID)
		})

		_, err = db.GetWritePool().Exec(ctx,
			`UPDATE pending_uploads SET attempts = 0, instance_id = $3, last_attempt = NULL WHERE account_id = $1 AND content_hash = $2`,
			f.accountID, f.hash, instanceID)
		require.NoError(t, err)
		_, err = db.GetWritePool().Exec(ctx,
			`UPDATE messages SET created_at = now() - interval '2 hours' WHERE account_id = $1 AND content_hash = $2`,
			f.accountID, f.hash)
		require.NoError(t, err)

		msgState := func(mbox *DBMailbox) (exists, live bool) {
			t.Helper()
			require.NoError(t, db.GetWritePool().QueryRow(ctx, `
				SELECT count(*) > 0, COALESCE(bool_or(expunged_at IS NULL), false)
				FROM messages WHERE account_id = $1 AND content_hash = $2 AND mailbox_id = $3
			`, f.accountID, f.hash, mbox.ID).Scan(&exists, &live))
			return exists, live
		}
		pendingCount := func() (n int) {
			t.Helper()
			require.NoError(t, db.GetWritePool().QueryRow(ctx, `
				SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2
			`, f.accountID, f.hash).Scan(&n))
			return n
		}

		tx1, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx1.Rollback(ctx)
		_, _, err = db.AddMessageFlags(ctx, tx1, f.uids[1], f.archive.ID, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err)

		var reaped1 int64
		inTx(t, db, func(tx pgx.Tx) {
			reaped1, err = db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
			require.NoError(t, err)
		})
		require.Equal(t, int64(1), reaped1, "cycle 1 reaps only the INBOX copy")
		assert.Equal(t, 1, pendingCount(), "shared pending_uploads row must remain until the Archive copy is also reaped")

		require.NoError(t, tx1.Commit(ctx))
		requireHardDeleteStats(t, db, f)

		var reaped2 int64
		inTx(t, db, func(tx pgx.Tx) {
			reaped2, err = db.CleanupFailedUploads(ctx, tx, time.Hour, hardDeleteMaxAttempts, time.Hour)
			require.NoError(t, err)
		})
		require.Equal(t, int64(1), reaped2, "cycle 2 reaps the Archive copy once Archive is free and the owner stays gone")
		exists, _ := msgState(f.archive)
		require.False(t, exists, "the Archive copy is reaped in cycle 2")
		require.Equal(t, 0, pendingCount(), "shared pending_uploads row is deleted once the last unuploaded copy is reaped")
		requireHardDeleteStats(t, db, f)
	})
}
