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

func TestMailboxHierarchyBadPathIsolationAndDryRunParity(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()
	pool := db.GetWritePool()

	placeMailbox := func(t *testing.T, accountID int64, seq *int, name, path string) int64 {
		t.Helper()
		*seq++
		placeholder := fmt.Sprintf("placeholder-%d", *seq)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, placeholder))
		m, err := db.GetMailboxByName(ctx, accountID, placeholder)
		require.NoError(t, err)
		if path == "" {
			path = helpers.FormatMailboxID(m.ID)
		}
		_, err = pool.Exec(ctx, "UPDATE mailboxes SET name = $2, path = $3 WHERE id = $1", m.ID, name, path)
		require.NoError(t, err)
		return m.ID
	}

	t.Run("bad_path colliding with parent path does not poison join or abort apply", func(t *testing.T) {
		accountID := createTestAccount(t, db, fmt.Sprintf("repair-bad-join-%d@example.com", time.Now().UnixNano()), "password123")
		var seq int
		alphaID := placeMailbox(t, accountID, &seq, "Alpha", "")
		alphaPath := helpers.FormatMailboxID(alphaID)
		alphaBetaID := placeMailbox(t, accountID, &seq, "Alpha/Beta", "")
		_, err := pool.Exec(ctx, "UPDATE mailboxes SET path = $2 WHERE id = $1", alphaBetaID, alphaPath+helpers.FormatMailboxID(alphaBetaID))
		require.NoError(t, err)
		ghostKidID := placeMailbox(t, accountID, &seq, "Ghost/Kid", "")
		brokenLiveID := placeMailbox(t, accountID, &seq, "BrokenLive", alphaPath)
		brokenDeletedID := placeMailbox(t, accountID, &seq, "BrokenDeleted", alphaPath)
		_, err = pool.Exec(ctx, "UPDATE mailboxes SET deleted_at = now() WHERE id = $1", brokenDeletedID)
		require.NoError(t, err)

		problems, err := detectMailboxHierarchyProblems(ctx, pool, []int64{accountID})
		require.NoError(t, err)
		var problemNames []string
		for _, p := range problems {
			problemNames = append(problemNames, p.Problem+":"+p.Name)
		}
		require.ElementsMatch(t, []string{
			"bad_path:BrokenLive",
			"root_with_delimiter:Ghost/Kid",
		}, problemNames)

		repairs, err := db.RepairMailboxHierarchy(ctx, accountID, true)
		require.NoError(t, err)
		require.Len(t, repairs, 2)

		var ghostKidPath, brokenLivePath string
		require.NoError(t, pool.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1", ghostKidID).Scan(&ghostKidPath))
		ghost, err := db.GetMailboxByName(ctx, accountID, "Ghost")
		require.NoError(t, err)
		require.Equal(t, ghost.Path+helpers.FormatMailboxID(ghostKidID), ghostKidPath)
		require.NoError(t, pool.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1", brokenLiveID).Scan(&brokenLivePath))
		require.Equal(t, alphaPath, brokenLivePath)
	})

	t.Run("child under bad_path parent is detected as manual", func(t *testing.T) {
		accountID := createTestAccount(t, db, fmt.Sprintf("repair-bad-parent-%d@example.com", time.Now().UnixNano()), "password123")
		var seq int
		const bogusParentPath = "7fffffffffff00ff"
		_ = placeMailbox(t, accountID, &seq, "Alpha", bogusParentPath)
		betaID := placeMailbox(t, accountID, &seq, "Alpha/Beta", "")
		_, err := pool.Exec(ctx, "UPDATE mailboxes SET path = $2 WHERE id = $1", betaID, bogusParentPath+helpers.FormatMailboxID(betaID))
		require.NoError(t, err)

		for _, apply := range []bool{false, true} {
			repairs, err := db.RepairMailboxHierarchy(ctx, accountID, apply)
			require.NoError(t, err)
			got := map[string]string{}
			for _, r := range repairs {
				got[r.Name] = r.Action + ":" + r.Problem + ":" + r.Reason
			}
			require.Equal(t, map[string]string{
				"Alpha":      fmt.Sprintf("report:bad_path:path %q is malformed", bogusParentPath),
				"Alpha/Beta": `manual:parent_missing:its parent "Alpha" has a malformed path`,
			}, got)
		}
	})

	t.Run("reparent preserves bad_path rows sharing oldPath prefix and moves soft-deleted valid child", func(t *testing.T) {
		accountID := createTestAccount(t, db, fmt.Sprintf("repair-reparent-bad-%d@example.com", time.Now().UnixNano()), "password123")
		var seq int
		parentID := placeMailbox(t, accountID, &seq, "Parent", "")
		parentPath := helpers.FormatMailboxID(parentID)
		childID := placeMailbox(t, accountID, &seq, "Parent/Child", "")
		childOldPath := helpers.FormatMailboxID(childID)
		deletedSubID := placeMailbox(t, accountID, &seq, "Parent/Child/DeletedSub", "")
		_, err := pool.Exec(ctx, "UPDATE mailboxes SET path = $2, deleted_at = now() WHERE id = $1",
			deletedSubID, childOldPath+helpers.FormatMailboxID(deletedSubID))
		require.NoError(t, err)
		leafOnlyID := placeMailbox(t, accountID, &seq, "Parent/LeafOnly", "")
		leafOldPath := helpers.FormatMailboxID(leafOnlyID)

		sentinel := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
		badSuffixID := placeMailbox(t, accountID, &seq, "BrokenSuffix", childOldPath+"xyz")
		badDupID := placeMailbox(t, accountID, &seq, "BrokenDup", leafOldPath)
		_, err = pool.Exec(ctx, "UPDATE mailboxes SET updated_at = $2 WHERE id = ANY($1::bigint[])",
			[]int64{badSuffixID, badDupID}, sentinel)
		require.NoError(t, err)

		_, err = db.RepairMailboxHierarchy(ctx, accountID, true)
		require.NoError(t, err)

		var deletedSubPath string
		require.NoError(t, pool.QueryRow(ctx, "SELECT path FROM mailboxes WHERE id = $1", deletedSubID).Scan(&deletedSubPath))
		require.Equal(t, parentPath+childOldPath+helpers.FormatMailboxID(deletedSubID), deletedSubPath)

		for _, tc := range []struct {
			id   int64
			path string
		}{
			{badSuffixID, childOldPath + "xyz"},
			{badDupID, leafOldPath},
		} {
			var gotPath string
			var gotUpdated time.Time
			require.NoError(t, pool.QueryRow(ctx, "SELECT path, updated_at FROM mailboxes WHERE id = $1", tc.id).Scan(&gotPath, &gotUpdated))
			require.Equal(t, tc.path, gotPath)
			require.True(t, gotUpdated.Equal(sentinel))
		}
	})

	t.Run("dry run matches apply for missing INBOX and nested virtual parent", func(t *testing.T) {
		accountID := createTestAccount(t, db, fmt.Sprintf("repair-dryrun-inbox-%d@example.com", time.Now().UnixNano()), "password123")
		var seq int
		_ = placeMailbox(t, accountID, &seq, "inbox/Child", "")
		_ = placeMailbox(t, accountID, &seq, "Nested/Sub", "")
		_ = placeMailbox(t, accountID, &seq, "Nested/Sub/Leaf", "")

		dry, err := db.RepairMailboxHierarchy(ctx, accountID, false)
		require.NoError(t, err)
		applied, err := db.RepairMailboxHierarchy(ctx, accountID, true)
		require.NoError(t, err)
		require.Equal(t, dry, applied)
	})
}
