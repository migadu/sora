//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestMailboxRenameCommandPreservesHierarchy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	for _, name := range []string{"Parent", "Leaf"} {
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, name, nil))
	}
	previousConfig, previousArgs := globalConfig, os.Args
	t.Cleanup(func() { globalConfig, os.Args = previousConfig, previousArgs })
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	for _, destination := range []string{"Parent/Leaf", "Parent/Sub/Deep/Leaf"} {
		os.Args = []string{"sora-admin", "mailbox", "rename", "--email", account.Email, "--old-name", "Leaf", "--new-name", destination}
		handleMailboxRename(ctx)
		parentName := "Parent"
		if destination == "Parent/Sub/Deep/Leaf" {
			parentName = "Parent/Sub/Deep"
			_, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Parent/Sub")
			require.NoError(t, err, "all intermediate ancestors must exist")
		}
		parent, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, parentName)
		require.NoError(t, err)
		leaf, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, destination)
		require.NoError(t, err)
		require.Contains(t, leaf.Path, parent.Path, "renamed leaf must be linked under its destination parent")
		root, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Parent")
		require.NoError(t, err)
		require.NoError(t, rdb.RenameMailboxWithRetry(ctx, root.ID, accountID, "RenamedParent", nil))
		_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "Renamed"+destination)
		require.NoError(t, err, "renaming parent must cascade to the command's nested destination")
		// Restore names for the second move, which must create missing parents.
		os.Args = []string{"sora-admin", "mailbox", "rename", "--email", account.Email, "--old-name", "Renamed" + destination, "--new-name", "Leaf"}
		handleMailboxRename(ctx)
		require.NoError(t, rdb.RenameMailboxWithRetry(ctx, root.ID, accountID, "Parent", nil))
	}
}
