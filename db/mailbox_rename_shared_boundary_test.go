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

// TestRenameMailbox_SharedNamespaceBoundary: RenameMailbox refuses a rename to the
// other side of the shared namespace boundary from what the mailbox's stored
// is_shared says, for every caller that gives it the shared mailbox config (IMAP,
// sora-admin), not only IMAP's own name check (issue #160).
func TestRenameMailbox_SharedNamespaceBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	})
	ts := time.Now().UnixNano()
	shared, personal := fmt.Sprintf("Shared/Team-%d", ts), fmt.Sprintf("Projects-%d", ts)

	create := func(name string) *DBMailbox {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
		require.NoError(t, tx.Commit(ctx))
		mbox, err := db.GetMailboxByName(ctx, accountID, name)
		require.NoError(t, err)
		return mbox
	}
	rename := func(mbox *DBMailbox, newName string) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := db.RenameMailbox(ctx, tx, mbox.ID, accountID, newName, nil); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	sharedMbox, personalMbox := create(shared), create(personal)
	require.ErrorIs(t, rename(sharedMbox, fmt.Sprintf("Team-%d", ts)), consts.ErrMailboxSharedBoundary)
	require.ErrorIs(t, rename(personalMbox, fmt.Sprintf("Shared/Projects-%d", ts)), consts.ErrMailboxSharedBoundary)

	// Renames that stay on one side are unaffected.
	require.NoError(t, rename(sharedMbox, fmt.Sprintf("Shared/Renamed-%d", ts)))
	require.NoError(t, rename(personalMbox, fmt.Sprintf("Renamed-%d", ts)))
}
