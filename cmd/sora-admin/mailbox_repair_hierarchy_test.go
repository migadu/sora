//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// repairHierarchyLineRe matches one mailbox line of "mailbox repair-hierarchy":
// action, problem, quoted name and what is (or would be) done about it.
var repairHierarchyLineRe = regexp.MustCompile(`(?m)^\s+(WOULD REPAIR|REPAIRED|MANUAL|REPORT)\s+(\w+)\s+("(?:[^"\\]|\\.)*")\s+(.*)$`)

// parseRepairHierarchy maps each listed mailbox name to "ACTION problem detail".
func parseRepairHierarchy(t *testing.T, out string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, m := range repairHierarchyLineRe.FindAllStringSubmatch(out, -1) {
		name := strings.Trim(m[3], `"`)
		require.NotContains(t, got, name, "mailbox listed twice:\n%s", out)
		got[name] = m[1] + " " + m[2] + " " + strings.TrimSpace(m[4])
	}
	return got
}

type hierarchyRow struct {
	ID          int64
	Name        string
	Path        string
	UIDValidity int64
	Deleted     bool
}

// TestMailboxRepairHierarchy covers every problem the detection reports (the categories
// of the read-only detached-mailboxes query): a name with a delimiter at the top level, a
// mailbox below a parent that does not have its name's parent part (the #1298
// CREATE-vs-RENAME race), a parent that is deleted or missing, and a malformed path. A
// dry run changes nothing and lists what --apply then does; --apply links each mailbox
// under the mailbox its name names, creating missing ancestors as CREATE does, keeps its
// id and UIDVALIDITY and carries its subtree along. A mailbox whose name's parent part
// names no mailbox while its path gives it another name (as the race left it, or a later
// RENAME mangled it) is left alone: only the user knows which name is right.
func TestMailboxRepairHierarchy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	pool := rdb.GetOperationalDatabase().WritePool

	exec := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	get := func(t *testing.T, name string) hierarchyRow {
		t.Helper()
		var r hierarchyRow
		err := pool.QueryRow(ctx, `
			SELECT id, name, path, uid_validity, deleted_at IS NOT NULL FROM mailboxes
			WHERE account_id = $1 AND name = $2 AND deleted_at IS NULL`, accountID, name).
			Scan(&r.ID, &r.Name, &r.Path, &r.UIDValidity, &r.Deleted)
		require.NoError(t, err, "live mailbox %q", name)
		return r
	}
	snapshot := func(t *testing.T) []hierarchyRow {
		t.Helper()
		rows, err := pool.Query(ctx, `
			SELECT id, name, path, uid_validity, deleted_at IS NOT NULL FROM mailboxes
			WHERE account_id = $1 ORDER BY id`, accountID)
		require.NoError(t, err)
		defer rows.Close()
		var all []hierarchyRow
		for rows.Next() {
			var r hierarchyRow
			require.NoError(t, rows.Scan(&r.ID, &r.Name, &r.Path, &r.UIDValidity, &r.Deleted))
			all = append(all, r)
		}
		require.NoError(t, rows.Err())
		return all
	}
	create := func(t *testing.T, name string) hierarchyRow {
		t.Helper()
		_, err := rdb.ResolveOrCreateMailboxPathWithRetry(ctx, accountID, name)
		require.NoError(t, err, "create %q", name)
		return get(t, name)
	}
	// place makes a mailbox called name whose path puts it below parentPath ("" is the
	// top level), whatever its name says: the state the bugs left behind.
	placed := 0
	place := func(t *testing.T, name, parentPath string) hierarchyRow {
		t.Helper()
		placed++
		placeholder := fmt.Sprintf("placeholder-%d", placed)
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, placeholder, nil))
		m := get(t, placeholder)
		exec(t, `UPDATE mailboxes SET name = $2, path = $3 WHERE id = $1`,
			m.ID, name, parentPath+helpers.FormatMailboxID(m.ID))
		return get(t, name)
	}

	// root_with_delimiter: "Parent/Child" at the top level with "Leaf" below it.
	parent := create(t, "Parent")
	child := place(t, "Parent/Child", "")
	leaf := place(t, "Parent/Child/Leaf", child.Path)
	// root_with_delimiter whose parent does not exist.
	kid := place(t, "Ghost/Kid", "")
	// detached: below "Gamma" (the parent renamed under the create), with "Alpha" there.
	create(t, "Alpha")
	gamma := create(t, "Gamma")
	beta := place(t, "Alpha/Beta", gamma.Path)
	sub := place(t, "Alpha/Beta/Sub", beta.Path)
	// detached top-level name.
	loose := place(t, "Loose", gamma.Path)
	// detached and mangled by a later RENAME: "X/a" does not exist, the path says "X/Beta".
	x := create(t, "X")
	mangled := place(t, "X/a/Beta", x.Path)
	// detached as the race left it: "Delta" was renamed to "Epsilon" and does not exist.
	epsilon := create(t, "Epsilon")
	raced := place(t, "Delta/Beta", epsilon.Path)
	// parent_deleted: "Old" is soft-deleted under its live child.
	old := create(t, "Old")
	oldChild := create(t, "Old/Child")
	exec(t, `UPDATE mailboxes SET deleted_at = now() WHERE id = $1`, old.ID)
	// parent_missing: the path names a mailbox that does not exist.
	gone := place(t, "Gone/Child", "7fffffffffff0000")
	// bad_path.
	broken := place(t, "Broken", "")
	exec(t, `UPDATE mailboxes SET path = 'abc' WHERE id = $1`, broken.ID)

	before := snapshot(t)

	listed := map[string]string{
		"Parent/Child": `root_with_delimiter -> under "Parent"`,
		"Ghost/Kid":    `root_with_delimiter -> under "Ghost" (creating "Ghost")`,
		"Alpha/Beta":   `detached -> under "Alpha"`,
		"Loose":        `detached -> to the top level`,
		"Old/Child":    `parent_deleted -> under "Old" (creating "Old")`,
		"Gone/Child":   `parent_missing -> under "Gone" (creating "Gone")`,
	}
	left := map[string]string{
		"X/a/Beta":   `MANUAL detached no mailbox "X/a"; its path places it at "X/Beta"`,
		"Delta/Beta": `MANUAL detached no mailbox "Delta"; its path places it at "Epsilon/Beta"`,
		"Broken":     `REPORT bad_path path "abc" is malformed`,
	}
	want := func(action string) map[string]string {
		m := map[string]string{}
		for name, line := range left {
			m[name] = line
		}
		for name, detail := range listed {
			m[name] = action + " " + detail
		}
		return m
	}

	t.Run("dry run changes nothing", func(t *testing.T) {
		out := runMailboxRepairHierarchy(t, ctx, account.Email)
		require.Equal(t, want("WOULD REPAIR"), parseRepairHierarchy(t, out))
		require.Equal(t, before, snapshot(t), "a dry run must not change any mailbox")
	})

	t.Run("apply repairs what the dry run listed", func(t *testing.T) {
		out := runMailboxRepairHierarchy(t, ctx, account.Email, "--apply")
		require.Equal(t, want("REPAIRED"), parseRepairHierarchy(t, out))
	})

	requireChildOf := func(t *testing.T, c hierarchyRow, parentName string) {
		t.Helper()
		now := get(t, c.Name)
		require.Equal(t, c.ID, now.ID, "%q keeps its id", c.Name)
		require.Equal(t, c.UIDValidity, now.UIDValidity, "%q keeps its UIDVALIDITY", c.Name)
		if parentName == "" {
			require.Equal(t, helpers.FormatMailboxID(c.ID), now.Path, "%q must be at the top level", c.Name)
			return
		}
		require.Equal(t, get(t, parentName).Path+helpers.FormatMailboxID(c.ID), now.Path,
			"%q must be linked below %q", c.Name, parentName)
	}

	t.Run("root_with_delimiter", func(t *testing.T) {
		requireChildOf(t, child, "Parent")
		requireChildOf(t, leaf, "Parent/Child")
		require.Equal(t, parent.Path, get(t, "Parent").Path)
		requireChildOf(t, get(t, "Ghost"), "")
		requireChildOf(t, kid, "Ghost")
	})
	t.Run("detached", func(t *testing.T) {
		requireChildOf(t, beta, "Alpha")
		requireChildOf(t, sub, "Alpha/Beta")
		requireChildOf(t, loose, "")
		hasChildren, err := rdb.HasLiveDescendantsWithRetry(ctx, accountID, gamma.Path)
		require.NoError(t, err)
		require.False(t, hasChildren, "Gamma must keep no children")
	})
	t.Run("parent_deleted", func(t *testing.T) {
		newOld := get(t, "Old")
		require.NotEqual(t, old.ID, newOld.ID, "the deleted parent stays deleted")
		requireChildOf(t, newOld, "")
		requireChildOf(t, oldChild, "Old")
	})
	t.Run("parent_missing", func(t *testing.T) {
		requireChildOf(t, get(t, "Gone"), "")
		requireChildOf(t, gone, "Gone")
	})
	t.Run("mangled and bad_path untouched", func(t *testing.T) {
		require.Equal(t, mangled, get(t, "X/a/Beta"))
		require.Equal(t, raced, get(t, "Delta/Beta"))
		_, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Delta")
		require.Error(t, err, "no parent is created for a mailbox left alone")
		require.Equal(t, broken.ID, get(t, "Broken").ID)
		require.Equal(t, "abc", get(t, "Broken").Path)
	})

	t.Run("nothing left to repair", func(t *testing.T) {
		out := runMailboxRepairHierarchy(t, ctx, account.Email)
		require.Equal(t, left, parseRepairHierarchy(t, out))
	})
}

// TestMailboxRepairHierarchyAllAccounts: without --email the dry run walks every account
// in pages and finds the problem of this one.
func TestMailboxRepairHierarchyAllAccounts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	pool := rdb.GetOperationalDatabase().WritePool

	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, "AllAccounts", nil))
	var id int64
	require.NoError(t, pool.QueryRow(ctx, `
		UPDATE mailboxes SET name = 'AllAccounts/Lost'
		WHERE account_id = $1 AND name = 'AllAccounts' RETURNING id`, accountID).Scan(&id))

	out := runMailboxRepairHierarchy(t, ctx, "", "--batch-size", "50")
	require.Regexp(t, fmt.Sprintf(`(?m)^account_id=%d .*\n(?:\s+.*\n)*?\s+WOULD REPAIR\s+root_with_delimiter\s+"AllAccounts/Lost"\s+-> under "AllAccounts" \(creating "AllAccounts"\)$`, accountID), out)

	var path string
	require.NoError(t, pool.QueryRow(ctx, `SELECT path FROM mailboxes WHERE id = $1`, id).Scan(&path))
	require.Equal(t, helpers.FormatMailboxID(id), path, "a dry run must not change any mailbox")
}

// runMailboxRepairHierarchy runs "sora-admin mailbox repair-hierarchy" against the test
// database, for one account unless email is empty, and returns what it printed.
func runMailboxRepairHierarchy(t *testing.T, ctx context.Context, email string, flags ...string) string {
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
	os.Args = []string{"sora-admin", "mailbox", "repair-hierarchy"}
	if email != "" {
		os.Args = append(os.Args, "--email", email)
	}
	os.Args = append(os.Args, flags...)
	out := captureStdout(t, func() error {
		handleMailboxRepairHierarchy(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
