//go:build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

const renameHelperEnv = "SORA_ADMIN_RENAME_HELPER_EMAIL"

func renameTestSharedConfig() config.SharedMailboxesConfig {
	return config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"}
}

// TestMailboxRenameCommandHelper is not a test: it is `sora-admin mailbox rename`,
// run by runMailboxRename in a process of its own because the command exits.
func TestMailboxRenameCommandHelper(t *testing.T) {
	email := os.Getenv(renameHelperEnv)
	if email == "" {
		t.Skip("helper process for runMailboxRename")
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	globalConfig.SharedMailboxes = renameTestSharedConfig()
	os.Args = []string{"sora-admin", "mailbox", "rename", "--email", email,
		"--old-name", os.Getenv("SORA_ADMIN_RENAME_HELPER_OLD"), "--new-name", os.Getenv("SORA_ADMIN_RENAME_HELPER_NEW")}
	handleMailboxRename(context.Background())
}

// runMailboxRename runs the rename command and reports whether it succeeded.
func runMailboxRename(t *testing.T, email, oldName, newName string) (string, bool) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMailboxRenameCommandHelper$")
	cmd.Env = append(os.Environ(), renameHelperEnv+"="+email,
		"SORA_ADMIN_RENAME_HELPER_OLD="+oldName, "SORA_ADMIN_RENAME_HELPER_NEW="+newName)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestMailboxRenameCommandRefusals covers issue #231 item 2 for sora-admin: a rename
// that is refused must not leave the parents of the new name behind, and a personal
// mailbox under the shared prefix must be renameable out of it.
func TestMailboxRenameCommandRefusals(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)

	shared := renameTestSharedConfig()
	shared.AllowUserCreate = true
	sharedCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: shared})
	require.NoError(t, rdb.CreateMailboxForUserWithRetry(sharedCtx, accountID, "Shared/Team"))
	// A personal mailbox under the shared prefix, as the User API creates them.
	require.NoError(t, rdb.CreateMailboxForUserWithRetry(ctx, accountID, "Shared/Planted"))
	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "CycleBox", nil))

	exists := func(name string) bool {
		_, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, name)
		if err != nil {
			require.ErrorIs(t, err, consts.ErrMailboxNotFound)
		}
		return err == nil
	}

	t.Run("personal into shared", func(t *testing.T) {
		out, ok := runMailboxRename(t, account.Email, "Shared/Planted", "Shared/Team/LeakedParent/Planted")
		require.False(t, ok, "a personal mailbox cannot become a shared one: %s", out)
		require.True(t, exists("Shared/Planted"))
		require.False(t, exists("Shared/Team/LeakedParent"), "a refused rename left the parent it created behind: %s", out)
	})
	t.Run("below itself", func(t *testing.T) {
		out, ok := runMailboxRename(t, account.Email, "CycleBox", "CycleBox/Sub1/Sub2/CycleBox")
		require.False(t, ok, "a mailbox cannot be moved below itself: %s", out)
		require.True(t, exists("CycleBox"))
		require.False(t, exists("CycleBox/Sub1"), "a refused rename left the parent it created behind: %s", out)
	})
	t.Run("personal out of the shared prefix", func(t *testing.T) {
		out, ok := runMailboxRename(t, account.Email, "Shared/Planted", "PersonalPlanted")
		require.True(t, ok, "a personal mailbox under the shared prefix can be renamed out of it: %s", out)
		require.True(t, exists("PersonalPlanted"))
		require.False(t, exists("Shared/Planted"))
	})
}
