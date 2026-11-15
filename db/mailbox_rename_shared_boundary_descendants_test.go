package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_SharedBoundaryDescendants: a rename carries the mailbox's
// descendants with it, so RenameMailbox refuses it when any of them, not only the
// renamed mailbox, would land on the other side of the shared namespace boundary
// from its is_shared (issue #1229).
func TestRenameMailbox_SharedBoundaryDescendants(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	sharedCtx := func(prefix string) context.Context {
		return context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
			SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: prefix, AllowUserCreate: true},
		})
	}
	newAccount := func(t *testing.T) int64 {
		t.Helper()
		return createTestAccount(t, db, fmt.Sprintf("rename-boundary-%d@example.com", time.Now().UnixNano()), "password123")
	}
	rename := func(t *testing.T, ctx context.Context, accountID int64, oldName, newName string) error {
		t.Helper()
		mbox, err := db.GetMailboxByName(ctx, accountID, oldName)
		require.NoError(t, err)
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := db.RenameMailbox(ctx, tx, mbox.ID, accountID, newName, nil); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	// requireMailboxes asserts each name exists with the given is_shared.
	requireMailboxes := func(t *testing.T, ctx context.Context, accountID int64, want map[string]bool) {
		t.Helper()
		for name, shared := range want {
			mbox, err := db.GetMailboxByName(ctx, accountID, name)
			require.NoError(t, err, "mailbox %q", name)
			isShared, err := db.IsMailboxShared(ctx, mbox.ID)
			require.NoError(t, err)
			require.Equal(t, shared, isShared, "is_shared of %q", name)
		}
	}

	t.Run("personal children into a multi-level namespace", func(t *testing.T) {
		ctx, accountID := sharedCtx("Team/Shared/"), newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Foo/Shared/X"))
		requireMailboxes(t, ctx, accountID, map[string]bool{"Foo": false, "Foo/Shared": false, "Foo/Shared/X": false})

		// "Team" is outside the namespace, but "Foo/Shared" would become its root.
		require.ErrorIs(t, rename(t, ctx, accountID, "Foo", "Team"), consts.ErrMailboxSharedBoundary)
		requireMailboxes(t, ctx, accountID, map[string]bool{"Foo": false, "Foo/Shared": false, "Foo/Shared/X": false})

		// A rename that keeps the whole subtree outside the namespace is unaffected.
		require.NoError(t, rename(t, ctx, accountID, "Foo", "Bar"))
		requireMailboxes(t, ctx, accountID, map[string]bool{"Bar": false, "Bar/Shared": false, "Bar/Shared/X": false})
	})

	t.Run("shared children out of a multi-level namespace", func(t *testing.T) {
		ctx, accountID := sharedCtx("Team/Shared/"), newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Team/Shared/X/Y"))
		requireMailboxes(t, ctx, accountID, map[string]bool{"Team": false, "Team/Shared": true, "Team/Shared/X": true, "Team/Shared/X/Y": true})

		// "Team" is personal and "Other" outside the namespace, but its shared
		// children would leave it with their grants.
		require.ErrorIs(t, rename(t, ctx, accountID, "Team", "Other"), consts.ErrMailboxSharedBoundary)
		requireMailboxes(t, ctx, accountID, map[string]bool{"Team": false, "Team/Shared": true, "Team/Shared/X": true, "Team/Shared/X/Y": true})

		// A shared mailbox with shared children renamed within the namespace is unaffected.
		require.NoError(t, rename(t, ctx, accountID, "Team/Shared/X", "Team/Shared/Z"))
		requireMailboxes(t, ctx, accountID, map[string]bool{"Team/Shared/Z": true, "Team/Shared/Z/Y": true})
	})

	t.Run("shared children below a personal namespace root", func(t *testing.T) {
		ctx, accountID := sharedCtx("Shared/"), newAccount(t)
		// A personal "Shared" from before sharing was enabled.
		require.NoError(t, db.CreateMailboxForUser(context.Background(), accountID, "Shared"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Shared/X"))
		requireMailboxes(t, ctx, accountID, map[string]bool{"Shared": false, "Shared/X": true})

		// A personal mailbox under the prefix may be renamed out of it, but its
		// shared child may not.
		require.ErrorIs(t, rename(t, ctx, accountID, "Shared", "Other"), consts.ErrMailboxSharedBoundary)
		requireMailboxes(t, ctx, accountID, map[string]bool{"Shared": false, "Shared/X": true})
	})
}
