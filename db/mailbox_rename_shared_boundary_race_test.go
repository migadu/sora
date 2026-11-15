package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_SharedBoundaryConcurrentCreate: a mailbox created inside the
// subtree while the rename runs is renamed with it when its insert is committed
// before the rename's child UPDATE starts. The boundary check has to cover what
// that UPDATE renames, not a set of rows read before it (issue #1229).
//
// "Shared" and "Shared/Old" are personal, from before sharing was enabled, so the
// rename of "Shared" to "Other" takes both out of the namespace as it may. A
// concurrent CREATE of the shared "Shared/Old/New" holds "Shared/Old" FOR KEY
// SHARE until it commits: a rename that waits for it there, and then renames
// "Shared/Old/New" too, carries a shared mailbox out of the namespace.
func TestRenameMailbox_SharedBoundaryConcurrentCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	shared := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true}
	ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{SharedMailboxes: shared})
	accountID := createTestAccount(t, db, fmt.Sprintf("rename-boundary-race-%d@example.com", time.Now().UnixNano()), "password123")

	require.NoError(t, db.CreateMailboxForUser(context.Background(), accountID, "Shared/Old"))
	root, err := db.GetMailboxByName(ctx, accountID, "Shared")
	require.NoError(t, err)
	old, err := db.GetMailboxByName(ctx, accountID, "Shared/Old")
	require.NoError(t, err)

	// The CREATE: inserted and holding its parent, not committed yet.
	txCreate, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txCreate.Rollback(context.Background())
	require.NoError(t, db.CreateMailbox(ctx, txCreate, accountID, "Shared/Old/New", &old.ID))

	// The RENAME, in a transaction of its own.
	txRename, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txRename.Rollback(context.Background())
	var renamePID int
	require.NoError(t, txRename.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&renamePID))
	done := make(chan error, 1)
	go func() {
		err := db.RenameMailbox(ctx, txRename, root.ID, accountID, "Other", nil)
		if err == nil {
			err = txRename.Commit(ctx)
		}
		done <- err
	}()

	// Commit the CREATE once the rename waits for one of its locks, or has finished
	// without waiting.
	var renameErr error
	finished := false
	require.Eventually(t, func() bool {
		select {
		case renameErr = <-done:
			finished = true
			return true
		default:
		}
		var waiting bool
		err := db.GetWritePool().QueryRow(ctx,
			`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), FALSE) FROM pg_stat_activity WHERE pid = $1`,
			renamePID).Scan(&waiting)
		return err == nil && waiting
	}, 10*time.Second, 5*time.Millisecond)
	require.NoError(t, txCreate.Commit(ctx))
	if !finished {
		renameErr = <-done
	}
	// The rename waits for the CREATE, on its lock of "Shared/Old" (issue #1298), and
	// then renames "Shared/Old/New" with the rest of the subtree, which would carry a
	// shared mailbox out of the namespace: it is refused, and nothing is renamed.
	require.ErrorIs(t, renameErr, consts.ErrMailboxSharedBoundary)
	require.NoError(t, txRename.Rollback(ctx))
	rows, err := db.GetWritePool().Query(ctx,
		`SELECT name, COALESCE(is_shared, FALSE) FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`, accountID)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (string, error) {
		var name string
		var isShared bool
		err := row.Scan(&name, &isShared)
		return fmt.Sprintf("%s shared=%t", name, isShared), err
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"Shared shared=false", "Shared/Old shared=false", "Shared/Old/New shared=true"}, got)
}
