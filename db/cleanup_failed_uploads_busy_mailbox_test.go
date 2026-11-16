//go:build integration
// +build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
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
