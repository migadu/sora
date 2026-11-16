package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

func TestMailboxHierarchyNonCanonicalPathIsReportOnly(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	for _, prefix := range []string{"_______________%", "ABCDEF0000000000"} {
		t.Run(prefix, func(t *testing.T) {
			id := createTestAccount(t, db, fmt.Sprintf("repair-hex-%d@example.com", time.Now().UnixNano()), "password123")
			require.NoError(t, db.CreateMailboxForUser(ctx, id, "Broken"))
			m, err := db.GetMailboxByName(ctx, id, "Broken")
			require.NoError(t, err)
			bad := prefix + helpers.FormatMailboxID(m.ID)
			_, err = db.GetWritePool().Exec(ctx, "UPDATE mailboxes SET path=$2 WHERE id=$1", m.ID, bad)
			require.NoError(t, err)
			for _, apply := range []bool{false, true} {
				results, err := db.RepairMailboxHierarchy(ctx, id, apply)
				require.NoError(t, err)
				require.Len(t, results, 1)
				require.Equal(t, HierarchyBadPath, results[0].Problem)
				require.Equal(t, HierarchyActionReport, results[0].Action)
				var path string
				require.NoError(t, db.GetWritePool().QueryRow(ctx, "SELECT path FROM mailboxes WHERE id=$1", m.ID).Scan(&path))
				require.Equal(t, bad, path)
			}
		})
	}
}

func TestMailboxHierarchyLocksLateLoadedParent(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()
	id := createTestAccount(t, db, fmt.Sprintf("review1716-late-%d@example.com", time.Now().UnixNano()), "password123")
	require.NoError(t, db.CreateMailboxForUser(ctx, id, "Placeholder"))
	m, err := db.GetMailboxByName(ctx, id, "Placeholder")
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "UPDATE mailboxes SET name='Dest/Child' WHERE id=$1", m.ID)
	require.NoError(t, err)
	blocker, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer blocker.Rollback(ctx)
	blockPID := backendPID(t, blocker)
	_, err = blocker.Exec(ctx, "SELECT id FROM mailboxes WHERE id=$1 FOR UPDATE", m.ID)
	require.NoError(t, err)
	gate, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer gate.Rollback(ctx)
	gatePID := backendPID(t, gate)
	key := time.Now().UnixNano()
	_, err = gate.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", key)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, fmt.Sprintf(`
CREATE FUNCTION mailbox_hierarchy_commit_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.id=%d AND NEW.path IS DISTINCT FROM OLD.path THEN
PERFORM pg_advisory_xact_lock(%d::bigint); END IF; RETURN NEW; END $$;
CREATE CONSTRAINT TRIGGER mailbox_hierarchy_commit_gate AFTER UPDATE ON mailboxes
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mailbox_hierarchy_commit_gate();`, m.ID, key))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.GetWritePool().Exec(ctx, "DROP TRIGGER mailbox_hierarchy_commit_gate ON mailboxes; DROP FUNCTION mailbox_hierarchy_commit_gate()")
	})
	repaired := make(chan error, 1)
	go func() { _, err := db.RepairMailboxHierarchy(ctx, id, true); repaired <- err }()
	finished, early := blockedOrDone(t, db, blockPID, repaired)
	require.False(t, finished, "repair did not wait for its initial row lock: %v", early)
	// This root is committed after the initial locking statement's snapshot.
	require.NoError(t, db.CreateMailboxForUser(ctx, id, "Dest"))
	dest, err := db.GetMailboxByName(ctx, id, "Dest")
	require.NoError(t, err)
	require.NoError(t, blocker.Commit(ctx))
	finished, early = blockedOrDone(t, db, gatePID, repaired)
	require.False(t, finished, "repair did not reach its deferred commit gate: %v", early)
	var repairPID int
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&repairPID))
	renamed := make(chan error, 1)
	go func() {
		tx, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			renamed <- err
			return
		}
		defer tx.Rollback(ctx)
		if err = db.RenameMailbox(ctx, tx, dest.ID, id, "Other", nil); err == nil {
			err = tx.Commit(ctx)
		}
		renamed <- err
	}()
	finished, renameErr := blockedOrDone(t, db, repairPID, renamed)
	require.NoError(t, gate.Commit(ctx))
	require.NoError(t, <-repaired)
	if !finished {
		renameErr = <-renamed
	}
	require.NoError(t, renameErr)
	rows, err := db.GetWritePool().Query(ctx, "SELECT name FROM mailboxes WHERE account_id=$1 AND deleted_at IS NULL", id)
	require.NoError(t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"Other", "Other/Child"}, names, "late parent rename must wait and carry the repaired child")
	assertMailboxTreeConsistent(t, db, id)
}
