//go:build integration

package main

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
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

	runMailboxFixUTF7(t, ctx, account.Email)

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

// TestMailboxFixUTF7DryRunMatchesRun: --dry-run lists the renames the run makes. It
// writes nothing, so it has to carry each rename down to the children itself, as the
// rename does in the database: a child is renamed under its parent's new name, a child
// whose own level needs no decoding just moves with its parent, and a parent that is
// no candidate keeps its name.
func TestMailboxFixUTF7DryRunMatchesRun(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)

	for _, name := range []string{
		"A&AOk-/B&AOk-/C",           // B is renamed under A's new name, C moves with B
		"Parent/R&AOk-pertoire/Sub", // Sub moves with its parent
		"Tom&-Jerry/R&AOk-sum&AOk-", // the parent is no candidate and keeps its name
	} {
		_, err := rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, name)
		require.NoError(t, err, "create %q", name)
	}

	line := regexp.MustCompile(`(?m)^\s+(?:WOULD RENAME|OK)\s+account_id=\d+\s+(".*")\s+->\s+(".*")$`)
	renames := func(out string) []string {
		var got []string
		for _, m := range line.FindAllStringSubmatch(out, -1) {
			got = append(got, m[1]+" -> "+m[2])
		}
		sort.Strings(got)
		return got
	}
	predicted := renames(runMailboxFixUTF7(t, ctx, account.Email, "--dry-run"))
	made := renames(runMailboxFixUTF7(t, ctx, account.Email))

	require.Equal(t, []string{
		`"A&AOk-" -> "Aé"`,
		`"Aé/B&AOk-" -> "Aé/Bé"`,
		`"Parent/R&AOk-pertoire" -> "Parent/Répertoire"`,
		`"Tom&-Jerry/R&AOk-sum&AOk-" -> "Tom&-Jerry/Résumé"`,
	}, made)
	require.Equal(t, made, predicted, "the dry run must list the renames the run makes")
}

// runMailboxFixUTF7 runs "sora-admin mailbox fix-utf7" for one account against the
// test database and returns what it printed.
func runMailboxFixUTF7(t *testing.T, ctx context.Context, email string, flags ...string) string {
	t.Helper()
	previousConfig, previousArgs := globalConfig, os.Args
	t.Cleanup(func() { globalConfig, os.Args = previousConfig, previousArgs })
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = append([]string{"sora-admin", "mailbox", "fix-utf7", "--email", email}, flags...)
	out := captureStdout(t, func() error {
		handleMailboxFixUTF7(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
