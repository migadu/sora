//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestMailboxFixUTF7KeepsHierarchy covers issue #882: fix-utf7 renamed every mailbox
// to the top level, so a nested mailbox kept its hierarchical name but was no longer
// linked under its parent. A decode fixes one level's characters in place; the
// mailbox stays where it is in the tree, with its subtree below it.
func TestMailboxFixUTF7KeepsHierarchy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)

	for _, name := range []string{
		"Parent/R&AOk-pertoire/Sub", // only the middle level is encoded
		"A&AOk-/B&AOk-",             // both levels are encoded
		"C&AOk-/D&AOk-",             // the parent cannot be renamed: "Cé" exists
		"Tom&-Jerry/R&AOk-sum&AOk-", // the parent is no Modified UTF-7 candidate
	} {
		_, err := rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, name)
		require.NoError(t, err, "create %q", name)
	}
	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "Cé", nil))

	previousConfig, previousArgs := globalConfig, os.Args
	t.Cleanup(func() { globalConfig, os.Args = previousConfig, previousArgs })
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = []string{"sora-admin", "mailbox", "fix-utf7", "--email", account.Email}
	handleMailboxFixUTF7(ctx)

	path := func(t *testing.T, name string) string {
		t.Helper()
		mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, name)
		require.NoError(t, err, "mailbox %q must exist after fix-utf7", name)
		return mbox.Path
	}
	requireChildOf := func(t *testing.T, child, parent string) {
		t.Helper()
		parentPath := path(t, parent)
		require.True(t, helpers.IsDirectChildOf(path(t, child), parentPath),
			"%q must stay linked under %q", child, parent)
		hasChildren, err := rdb.HasLiveDescendantsWithRetry(ctx, accountID, parentPath)
		require.NoError(t, err)
		require.True(t, hasChildren, "%q must keep \\HasChildren", parent)
	}

	t.Run("encoded level under a plain parent", func(t *testing.T) {
		requireChildOf(t, "Parent/Répertoire", "Parent")
		requireChildOf(t, "Parent/Répertoire/Sub", "Parent/Répertoire")
	})
	t.Run("every level encoded", func(t *testing.T) {
		require.Len(t, path(t, "Aé"), helpers.HexIDLength, "a top-level mailbox stays top-level")
		requireChildOf(t, "Aé/Bé", "Aé")
	})
	// A level that is not renamed keeps its name, and its children stay below it
	// under that name: only their own level is decoded.
	t.Run("parent rename refused", func(t *testing.T) {
		requireChildOf(t, "C&AOk-/Dé", "C&AOk-")
		hasChildren, err := rdb.HasLiveDescendantsWithRetry(ctx, accountID, path(t, "Cé"))
		require.NoError(t, err)
		require.False(t, hasChildren, "the existing \"Cé\" must not receive \"C&AOk-\"'s children")
	})
	t.Run("parent not a candidate", func(t *testing.T) {
		requireChildOf(t, "Tom&-Jerry/Résumé", "Tom&-Jerry")
	})
}
