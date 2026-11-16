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
	// Issue #566: the new name is checked as IMAP RENAME checks it. A name with an
	// empty level is refused before any parent is created, and a trailing delimiter
	// is no part of the name.
	t.Run("empty hierarchy level", func(t *testing.T) {
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "LevelBox", nil))
		for _, newName := range []string{"r//s", "/lead", "p//q/"} {
			out, ok := runMailboxRename(t, account.Email, "LevelBox", newName)
			require.False(t, ok, "rename to %q: a name with an empty level is refused: %s", newName, out)
			require.True(t, exists("LevelBox"))
		}
		for _, parent := range []string{"r", "r/", "", "p", "p/"} {
			require.False(t, exists(parent), "a refused rename left the parent %q behind", parent)
		}
	})
	t.Run("trailing delimiter", func(t *testing.T) {
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "TrailSource", nil))
		before, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "TrailSource")
		require.NoError(t, err)
		out, ok := runMailboxRename(t, account.Email, "TrailSource", "TrailBox/")
		require.True(t, ok, "a trailing delimiter is dropped: %s", out)
		after, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "TrailBox")
		require.NoError(t, err)
		require.Equal(t, before.ID, after.ID, `"TrailBox/" names TrailBox, not a mailbox below a new parent TrailBox`)
		require.False(t, exists("TrailBox/"))
	})
	// Issue #1229: the children the rename carries along must stay on their side of
	// the boundary too, and that refusal also comes before any parent is created.
	t.Run("shared child out of the shared prefix", func(t *testing.T) {
		require.NoError(t, rdb.CreateMailboxForUserWithRetry(ctx, accountID, "Shared/Namesake"))
		require.NoError(t, rdb.CreateMailboxForUserWithRetry(sharedCtx, accountID, "Shared/Namesake/Kid"))
		out, ok := runMailboxRename(t, account.Email, "Shared/Namesake", "NewParent/Namesake")
		require.False(t, ok, "a shared child cannot be moved out of the shared namespace: %s", out)
		require.True(t, exists("Shared/Namesake/Kid"))
		require.False(t, exists("NewParent"), "a refused rename left the parent it created behind: %s", out)
	})
	t.Run("personal out of the shared prefix", func(t *testing.T) {
		out, ok := runMailboxRename(t, account.Email, "Shared/Planted", "PersonalPlanted")
		require.True(t, ok, "a personal mailbox under the shared prefix can be renamed out of it: %s", out)
		require.True(t, exists("PersonalPlanted"))
		require.False(t, exists("Shared/Planted"))
	})
}

// TestMailboxRenameCommandBelowItselfAsTheDatabaseNames: the rename refuses a new
// name below the mailbox itself before it creates the missing levels of that name.
// Which level is the mailbox is the database's call, LOWER(name) under its
// collation, as for IMAP RENAME (issue #1622). The test asks the database, so it
// holds under any collation. Under ICU strings.ToLower refused "ix" -> "İx/z/y",
// and let "ΑΣ" -> "ας/z/y" create "ας/z" below the mailbox before the rename failed.
func TestMailboxRenameCommandBelowItselfAsTheDatabaseNames(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)

	sameName := func(a, b string) bool {
		var same bool
		require.NoError(t, rdb.GetDatabase().GetWritePool().QueryRow(ctx,
			`SELECT LOWER($1::text) = LOWER($2::text)`, a, b).Scan(&same))
		return same
	}
	exists := func(name string) bool {
		_, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, name)
		if err != nil {
			require.ErrorIs(t, err, consts.ErrMailboxNotFound)
		}
		return err == nil
	}

	for _, tc := range []struct{ mailbox, top string }{
		{"ix", "İx"},
		{"ΑΣ", "ας"},
		{"sx", "ſx"},
	} {
		t.Run(tc.mailbox+"->"+tc.top, func(t *testing.T) {
			require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, tc.mailbox, nil))
			target := tc.top + "/z/y"
			out, ok := runMailboxRename(t, account.Email, tc.mailbox, target)
			if sameName(tc.mailbox, tc.top) {
				require.False(t, ok, "rename %q to %q: the database takes %q for the mailbox itself: %s", tc.mailbox, target, tc.top, out)
				require.True(t, exists(tc.mailbox))
				require.False(t, exists(tc.top+"/z"), "the refused rename left the parent it created behind: %s", out)
			} else {
				require.True(t, ok, "rename %q to %q: %q is not %q to the database: %s", tc.mailbox, target, tc.top, tc.mailbox, out)
				require.True(t, exists(target))
			}
		})
	}
}
