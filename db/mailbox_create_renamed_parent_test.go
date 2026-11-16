package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertMailboxTreeConsistent fails when a live mailbox of the account sits below a
// parent (by path) whose name is not the parent part of its own name, or below no
// live parent at all.
func assertMailboxTreeConsistent(t *testing.T, db *Database, accountID int64) {
	t.Helper()
	rows, err := db.GetWritePool().Query(context.Background(),
		`SELECT name, path FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`, accountID)
	require.NoError(t, err)
	byPath, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]string, error) {
		var name, path string
		err := row.Scan(&name, &path)
		return [2]string{path, name}, err
	})
	require.NoError(t, err)
	names := make(map[string]string, len(byPath))
	for _, r := range byPath {
		names[r[0]] = r[1]
	}
	for path, name := range names {
		parentPart := ""
		if i := strings.LastIndex(name, string(consts.MailboxDelimiter)); i >= 0 {
			parentPart = name[:i]
		}
		if len(path) <= helpers.HexIDLength {
			assert.Empty(t, parentPart, "%q is at the top level", name)
			continue
		}
		parentName, ok := names[path[:len(path)-helpers.HexIDLength]]
		if assert.True(t, ok, "%q has no live parent", name) {
			assert.Equal(t, strings.ToLower(parentPart), strings.ToLower(parentName), "%q is below %q", name, parentName)
		}
	}
}

// blockedOrDone waits until a backend waits for a lock held by the backend blocker,
// or done delivers, and reports whether done delivered and what.
func blockedOrDone(t *testing.T, db *Database, blocker int, done <-chan error) (bool, error) {
	t.Helper()
	var result error
	finished := false
	require.Eventually(t, func() bool {
		select {
		case result = <-done:
			finished = true
			return true
		default:
		}
		var waiting bool
		err := db.GetWritePool().QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting)
		return err == nil && waiting
	}, 10*time.Second, 5*time.Millisecond)
	return finished, result
}

func backendPID(t *testing.T, tx pgx.Tx) int {
	t.Helper()
	var pid int
	require.NoError(t, tx.QueryRow(context.Background(), "SELECT pg_backend_pid()").Scan(&pid))
	return pid
}

// TestCreateMailbox_ParentRenamedSinceLookup: a caller that resolved the parent's ID
// by name in an earlier transaction (ResolveOrCreateMailboxPathWithRetry) must not
// link the child below that mailbox once a rename has given it another name
// (issue #1298).
func TestCreateMailbox_ParentRenamedSinceLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("create-renamed-parent-%d@example.com", time.Now().UnixNano()), "password123")

	require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Alpha"))
	alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
	require.NoError(t, err)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.RenameMailbox(ctx, tx, alpha.ID, accountID, "Gam", nil))
	require.NoError(t, tx.Commit(ctx))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	err = db.CreateMailbox(ctx, tx, accountID, "Alpha/Beta", &alpha.ID)
	require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	require.NoError(t, tx.Commit(ctx))

	_, err = db.GetMailboxByName(ctx, accountID, "Alpha/Beta")
	require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	assertMailboxTreeConsistent(t, db, accountID)

	// The parent's name is compared case-insensitively, as mailbox names are.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "gam/Beta", &alpha.ID))
	require.NoError(t, tx.Commit(ctx))
	assertMailboxTreeConsistent(t, db, accountID)
}

// TestCreateMailbox_ParentRenamedConcurrently: the create resolves its parent by name
// while a rename of the parent, or of an ancestor of it, is in flight. When the rename
// commits, the create must not link the child below the renamed parent under the old
// name (issue #1298).
func TestCreateMailbox_ParentRenamedConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()

	for _, tc := range []struct {
		name     string
		existing string // created first
		create   string // created while "Alpha" is renamed
	}{
		{name: "parent", existing: "Alpha", create: "Alpha/Beta"},
		{name: "ancestor", existing: "Alpha/Beta", create: "Alpha/Beta/Delta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			accountID := createTestAccount(t, db, fmt.Sprintf("create-rename-race-%s-%d@example.com", tc.name, time.Now().UnixNano()), "password123")
			require.NoError(t, db.CreateMailboxForUser(ctx, accountID, tc.existing))
			alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
			require.NoError(t, err)

			// The rename, done but not committed.
			txRename, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer txRename.Rollback(context.Background())
			renamePID := backendPID(t, txRename)
			require.NoError(t, db.RenameMailbox(ctx, txRename, alpha.ID, accountID, "Gam", nil))

			// The create resolves its parents by the names committed so far.
			done := make(chan error, 1)
			go func() { done <- db.CreateMailboxForUser(ctx, accountID, tc.create) }()
			finished, createErr := blockedOrDone(t, db, renamePID, done)

			require.NoError(t, txRename.Commit(ctx))
			if !finished {
				createErr = <-done
			}
			if createErr != nil {
				require.ErrorIs(t, createErr, consts.ErrMailboxNotFound)
			}
			assertMailboxTreeConsistent(t, db, accountID)
		})
	}
}

// TestRenameMailbox_ConcurrentCreatesInSubtree: a create that holds a descendant of the
// renamed mailbox as its parent when the rename starts has its child renamed with the
// rest of the subtree, and a create below that child, resolved by the child's old
// name before the rename commits, is not linked below the renamed child (issue #1298).
func TestRenameMailbox_ConcurrentCreatesInSubtree(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("rename-subtree-creates-%d@example.com", time.Now().UnixNano()), "password123")

	require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Alpha/Beta"))
	alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
	require.NoError(t, err)
	beta, err := db.GetMailboxByName(ctx, accountID, "Alpha/Beta")
	require.NoError(t, err)

	// A create below "Alpha/Beta": inserted and holding its parent, not committed yet.
	txCreate, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txCreate.Rollback(context.Background())
	createPID := backendPID(t, txCreate)
	require.NoError(t, db.CreateMailbox(ctx, txCreate, accountID, "Alpha/Beta/Delta", &beta.ID))

	// The rename of "Alpha", in a transaction of its own that it does not commit.
	txRename, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txRename.Rollback(context.Background())
	renamePID := backendPID(t, txRename)
	renamed := make(chan error, 1)
	go func() { renamed <- db.RenameMailbox(ctx, txRename, alpha.ID, accountID, "Gam", nil) }()

	finished, renameErr := blockedOrDone(t, db, createPID, renamed)
	require.NoError(t, txCreate.Commit(ctx))
	if !finished {
		renameErr = <-renamed
	}
	require.NoError(t, renameErr)

	// A create below the new child, which still has its old name for everyone but
	// the rename.
	done := make(chan error, 1)
	go func() { done <- db.CreateMailboxForUser(ctx, accountID, "Alpha/Beta/Delta/Eps") }()
	finished, createErr := blockedOrDone(t, db, renamePID, done)

	require.NoError(t, txRename.Commit(ctx))
	if !finished {
		createErr = <-done
	}
	if createErr != nil {
		require.ErrorIs(t, createErr, consts.ErrMailboxNotFound)
	}
	assertMailboxTreeConsistent(t, db, accountID)
	_, err = db.GetMailboxByName(ctx, accountID, "Gam/Beta/Delta")
	require.NoError(t, err, "the child created before the rename committed is renamed with its parent")
}

// TestRenameMailbox_NewParentRenamedSinceLookup: RENAME resolves the new parent's ID
// by the parent part of the new name, in an earlier transaction (IMAP RENAME,
// sora-admin mailbox rename). A rename of that parent committed since must not leave
// the renamed mailbox below it under the parent's old name (issue #1298).
func TestRenameMailbox_NewParentRenamedSinceLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("rename-renamed-parent-%d@example.com", time.Now().UnixNano()), "password123")

	require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Alpha"))
	require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Box"))
	alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
	require.NoError(t, err)
	box, err := db.GetMailboxByName(ctx, accountID, "Box")
	require.NoError(t, err)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.RenameMailbox(ctx, tx, alpha.ID, accountID, "Gam", nil))
	require.NoError(t, tx.Commit(ctx))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	err = db.RenameMailbox(ctx, tx, box.ID, accountID, "Alpha/Box", &alpha.ID)
	require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	require.NoError(t, tx.Rollback(ctx))

	_, err = db.GetMailboxByName(ctx, accountID, "Box")
	require.NoError(t, err, "a refused rename leaves the mailbox as it was")
	assertMailboxTreeConsistent(t, db, accountID)

	// The parent's name is compared case-insensitively, as mailbox names are.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.RenameMailbox(ctx, tx, box.ID, accountID, "gam/Box", &alpha.ID))
	require.NoError(t, tx.Commit(ctx))
	assertMailboxTreeConsistent(t, db, accountID)
}

// TestRenameMailbox_NewParentRenamedConcurrently: a RENAME into a parent, or into a
// mailbox below an ancestor, that another RENAME is renaming must not link the
// mailbox below the renamed parent under its old name (issue #1298).
func TestRenameMailbox_NewParentRenamedConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()

	for _, tc := range []struct {
		name     string
		existing string // the new parent, created first with "Box"
		newName  string // what "Box" is renamed to while "Alpha" is renamed
	}{
		{name: "parent", existing: "Alpha", newName: "Alpha/Box"},
		{name: "ancestor", existing: "Alpha/Beta", newName: "Alpha/Beta/Box"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			accountID := createTestAccount(t, db, fmt.Sprintf("rename-parent-race-%s-%d@example.com", tc.name, time.Now().UnixNano()), "password123")
			require.NoError(t, db.CreateMailboxForUser(ctx, accountID, tc.existing))
			require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Box"))
			alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
			require.NoError(t, err)
			box, err := db.GetMailboxByName(ctx, accountID, "Box")
			require.NoError(t, err)
			// Resolved by name before the rename of "Alpha" commits.
			parent, err := db.GetMailboxByName(ctx, accountID, tc.existing)
			require.NoError(t, err)

			// The rename of "Alpha", done but not committed.
			txRename, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer txRename.Rollback(context.Background())
			renamePID := backendPID(t, txRename)
			require.NoError(t, db.RenameMailbox(ctx, txRename, alpha.ID, accountID, "Gam", nil))

			done := make(chan error, 1)
			go func() {
				tx, err := db.GetWritePool().Begin(ctx)
				if err != nil {
					done <- err
					return
				}
				defer tx.Rollback(context.Background())
				if err := db.RenameMailbox(ctx, tx, box.ID, accountID, tc.newName, &parent.ID); err != nil {
					done <- err
					return
				}
				done <- tx.Commit(ctx)
			}()
			finished, moveErr := blockedOrDone(t, db, renamePID, done)

			require.NoError(t, txRename.Commit(ctx))
			if !finished {
				moveErr = <-done
			}
			if moveErr != nil {
				require.ErrorIs(t, moveErr, consts.ErrMailboxNotFound)
			}
			assertMailboxTreeConsistent(t, db, accountID)
		})
	}
}
