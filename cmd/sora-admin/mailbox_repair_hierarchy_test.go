//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

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

const repairHierarchyHelperEnv = "SORA_ADMIN_REPAIR_HIERARCHY_HELPER_ARGS"

// TestMailboxRepairHierarchyCommandHelper executes handleMailboxRepairHierarchy in a
// subprocess so an account failure (os.Exit(1)) surfaces as a normal test failure.
func TestMailboxRepairHierarchyCommandHelper(t *testing.T) {
	raw, ok := os.LookupEnv(repairHierarchyHelperEnv)
	if !ok {
		t.Skip("helper process for runMailboxRepairHierarchyCmd")
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	args := []string{"sora-admin", "mailbox", "repair-hierarchy"}
	if raw != "" {
		args = append(args, strings.Split(raw, "\n")...)
	}
	os.Args = args
	handleMailboxRepairHierarchy(context.Background())
}

func runMailboxRepairHierarchyCmd(t *testing.T, email string, flags ...string) (string, bool) {
	t.Helper()
	var args []string
	if email != "" {
		args = append(args, "--email", email)
	}
	args = append(args, flags...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMailboxRepairHierarchyCommandHelper$")
	cmd.Env = append(os.Environ(), repairHierarchyHelperEnv+"="+strings.Join(args, "\n"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	t.Logf("repair-hierarchy %s (ok=%v, err=%v)\n%s", strings.Join(args, " "), err == nil, err, stdout.String())
	return stdout.String(), err == nil
}

// TestMailboxRepairHierarchyBadPathIsolationAndDryRunParity verifies that:
//  1. A bad_path row whose corrupt path collides with another mailbox's path does not
//     poison the parent LEFT JOIN (no false-positive problem on healthy children, no
//     duplicate problem rows, and no --apply rollback of valid repairs in the account),
//     nor hide a child whose path points at a bad_path parent instead of a real ID.
//  2. Reparenting a mailbox moves its valid live and soft-deleted subtree while leaving
//     any bad_path rows whose corrupt path happens to share that prefix untouched.
//  3. Dry-run and --apply agree when auto-creating a missing INBOX from a lowercase
//     "inbox/..." child (canonical "INBOX") and when repairing deeper mailboxes below
//     an ancestor that also moves under a newly created parent.
func TestMailboxRepairHierarchyBadPathIsolationAndDryRunParity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	pool := rdb.GetOperationalDatabase().WritePool

	newFixture := func(t *testing.T) (common.TestAccount, int64,
		func(*testing.T, string, ...any),
		func(*testing.T, string) hierarchyRow,
		func(*testing.T) []hierarchyRow,
		func(*testing.T, string) hierarchyRow,
		func(*testing.T, string, string) hierarchyRow,
	) {
		t.Helper()
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
		require.NoError(t, err)

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
		return account, accountID, exec, get, snapshot, create, place
	}

	t.Run("bad_path colliding with parent path does not poison healthy or repairable mailboxes", func(t *testing.T) {
		account, _, exec, get, snapshot, create, place := newFixture(t)

		alpha := create(t, "Alpha")
		alphaBeta := create(t, "Alpha/Beta")
		other := create(t, "Other")
		otherDetached := place(t, "Other/Detached", alpha.Path)
		ghostKid := place(t, "Ghost/Kid", "")

		brokenLive := place(t, "BrokenLive", "")
		exec(t, `UPDATE mailboxes SET path = $2 WHERE id = $1`, brokenLive.ID, alpha.Path)

		brokenDeleted := place(t, "BrokenDeleted", "")
		exec(t, `UPDATE mailboxes SET path = $2, deleted_at = now() WHERE id = $1`, brokenDeleted.ID, alpha.Path)

		before := snapshot(t)
		want := func(action string) map[string]string {
			return map[string]string{
				"Ghost/Kid":      action + ` root_with_delimiter -> under "Ghost" (creating "Ghost")`,
				"Other/Detached": action + ` detached -> under "Other"`,
				"BrokenLive":     fmt.Sprintf(`REPORT bad_path path %q is malformed`, alpha.Path),
			}
		}

		t.Run("dry run", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email)
			require.True(t, ok, "dry run failed:\n%s", out)
			require.Equal(t, want("WOULD REPAIR"), parseRepairHierarchy(t, out))
			require.Equal(t, before, snapshot(t))
		})

		t.Run("apply", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email, "--apply")
			require.True(t, ok, "apply failed:\n%s", out)
			require.Equal(t, want("REPAIRED"), parseRepairHierarchy(t, out))

			require.Equal(t, alpha.Path+helpers.FormatMailboxID(alphaBeta.ID), get(t, "Alpha/Beta").Path)
			require.Equal(t, other.Path+helpers.FormatMailboxID(otherDetached.ID), get(t, "Other/Detached").Path)
			require.Equal(t, get(t, "Ghost").Path+helpers.FormatMailboxID(ghostKid.ID), get(t, "Ghost/Kid").Path)
			require.Equal(t, alpha.Path, get(t, "BrokenLive").Path)

			afterOut, afterOK := runMailboxRepairHierarchyCmd(t, account.Email)
			require.True(t, afterOK, "follow-up dry run failed:\n%s", afterOut)
			require.Equal(t, map[string]string{
				"BrokenLive": fmt.Sprintf(`REPORT bad_path path %q is malformed`, alpha.Path),
			}, parseRepairHierarchy(t, afterOut))
		})
	})

	t.Run("child under bad_path parent is reported as manual instead of missed", func(t *testing.T) {
		account, _, exec, get, snapshot, create, place := newFixture(t)

		const bogusParentPath = "7fffffffffff00ff"
		alpha := create(t, "Alpha")
		exec(t, `UPDATE mailboxes SET path = $2 WHERE id = $1`, alpha.ID, bogusParentPath)
		beta := place(t, "Alpha/Beta", bogusParentPath)
		ghostKid := place(t, "Ghost/Kid", "")

		before := snapshot(t)
		want := func(action string) map[string]string {
			return map[string]string{
				"Alpha":      fmt.Sprintf(`REPORT bad_path path %q is malformed`, bogusParentPath),
				"Alpha/Beta": `MANUAL parent_missing its parent "Alpha" has a malformed path`,
				"Ghost/Kid":  action + ` root_with_delimiter -> under "Ghost" (creating "Ghost")`,
			}
		}

		t.Run("dry run", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email)
			require.True(t, ok, "dry run failed:\n%s", out)
			require.Equal(t, want("WOULD REPAIR"), parseRepairHierarchy(t, out))
			require.Equal(t, before, snapshot(t))
		})

		t.Run("apply", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email, "--apply")
			require.True(t, ok, "apply failed:\n%s", out)
			require.Equal(t, want("REPAIRED"), parseRepairHierarchy(t, out))

			require.Equal(t, bogusParentPath, get(t, "Alpha").Path)
			require.Equal(t, beta.Path, get(t, "Alpha/Beta").Path)
			require.Equal(t, get(t, "Ghost").Path+helpers.FormatMailboxID(ghostKid.ID), get(t, "Ghost/Kid").Path)
		})
	})

	t.Run("reparent leaves bad_path rows with matching prefix untouched while moving valid subtree", func(t *testing.T) {
		account, _, exec, get, snapshot, create, place := newFixture(t)

		parent := create(t, "Parent")
		child := place(t, "Parent/Child", "")
		liveSub := place(t, "Parent/Child/LiveSub", child.Path)
		deletedSub := place(t, "Parent/Child/DeletedSub", child.Path)
		exec(t, `UPDATE mailboxes SET deleted_at = now() WHERE id = $1`, deletedSub.ID)
		leafOnly := place(t, "Parent/LeafOnly", "")

		sentinel := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

		brokenSuffix := place(t, "BrokenSuffix", "")
		badSuffixPath := child.Path + "xyz"
		exec(t, `UPDATE mailboxes SET path = $2, updated_at = $3 WHERE id = $1`, brokenSuffix.ID, badSuffixPath, sentinel)

		brokenUpper := place(t, "BrokenUpper", "")
		badUpperPath := child.Path + "ABCDEF0000000000" + helpers.FormatMailboxID(brokenUpper.ID)
		exec(t, `UPDATE mailboxes SET path = $2, updated_at = $3 WHERE id = $1`, brokenUpper.ID, badUpperPath, sentinel)

		brokenDup := place(t, "BrokenDup", "")
		badDupPath := leafOnly.Path
		exec(t, `UPDATE mailboxes SET path = $2, updated_at = $3 WHERE id = $1`, brokenDup.ID, badDupPath, sentinel)

		brokenDeletedWrongID := place(t, "BrokenDeletedWrongID", "")
		badDeletedPath := child.Path + "7fffffffffff00ff"
		exec(t, `UPDATE mailboxes SET path = $2, updated_at = $3, deleted_at = now() WHERE id = $1`,
			brokenDeletedWrongID.ID, badDeletedPath, sentinel)

		before := snapshot(t)
		want := func(action string) map[string]string {
			return map[string]string{
				"Parent/Child":    action + ` root_with_delimiter -> under "Parent"`,
				"Parent/LeafOnly": action + ` root_with_delimiter -> under "Parent"`,
				"BrokenSuffix":    fmt.Sprintf(`REPORT bad_path path %q is malformed`, badSuffixPath),
				"BrokenUpper":     fmt.Sprintf(`REPORT bad_path path %q is malformed`, badUpperPath),
				"BrokenDup":       fmt.Sprintf(`REPORT bad_path path %q is malformed`, badDupPath),
			}
		}

		t.Run("dry run", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email)
			require.True(t, ok, "dry run failed:\n%s", out)
			require.Equal(t, want("WOULD REPAIR"), parseRepairHierarchy(t, out))
			require.Equal(t, before, snapshot(t))
		})

		t.Run("apply", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email, "--apply")
			require.True(t, ok, "apply failed:\n%s", out)
			require.Equal(t, want("REPAIRED"), parseRepairHierarchy(t, out))

			newChildPath := parent.Path + helpers.FormatMailboxID(child.ID)
			require.Equal(t, newChildPath, get(t, "Parent/Child").Path)
			require.Equal(t, newChildPath+helpers.FormatMailboxID(liveSub.ID), get(t, "Parent/Child/LiveSub").Path)
			require.Equal(t, parent.Path+helpers.FormatMailboxID(leafOnly.ID), get(t, "Parent/LeafOnly").Path)

			var deletedSubPath string
			require.NoError(t, pool.QueryRow(ctx, `SELECT path FROM mailboxes WHERE id = $1`, deletedSub.ID).Scan(&deletedSubPath))
			require.Equal(t, newChildPath+helpers.FormatMailboxID(deletedSub.ID), deletedSubPath,
				"soft-deleted valid descendant must still move with its subtree")

			for _, tc := range []struct {
				label string
				id    int64
				path  string
			}{
				{"BrokenSuffix", brokenSuffix.ID, badSuffixPath},
				{"BrokenUpper", brokenUpper.ID, badUpperPath},
				{"BrokenDup", brokenDup.ID, badDupPath},
				{"BrokenDeletedWrongID", brokenDeletedWrongID.ID, badDeletedPath},
			} {
				var gotPath string
				var gotUpdated time.Time
				require.NoError(t, pool.QueryRow(ctx,
					`SELECT path, updated_at FROM mailboxes WHERE id = $1`, tc.id).Scan(&gotPath, &gotUpdated))
				require.Equal(t, tc.path, gotPath, "%s path must remain untouched", tc.label)
				require.True(t, gotUpdated.Equal(sentinel), "%s updated_at must remain untouched (got %v, want %v)",
					tc.label, gotUpdated, sentinel)
			}
		})
	})

	t.Run("dry run matches apply when creating missing INBOX and nested ancestors", func(t *testing.T) {
		account, accountID, exec, get, snapshot, _, place := newFixture(t)

		exec(t, `DELETE FROM mailboxes WHERE account_id = $1 AND LOWER(name) = 'inbox'`, accountID)
		inboxChild := place(t, "inbox/Child", "")
		nestedSub := place(t, "Nested/Sub", "")
		nestedLeaf := place(t, "Nested/Sub/Leaf", "")

		before := snapshot(t)
		want := func(action string) map[string]string {
			return map[string]string{
				"inbox/Child":     action + ` root_with_delimiter -> under "INBOX" (creating "INBOX")`,
				"Nested/Sub":      action + ` root_with_delimiter -> under "Nested" (creating "Nested")`,
				"Nested/Sub/Leaf": action + ` root_with_delimiter -> under "Nested/Sub"`,
			}
		}

		t.Run("dry run", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email)
			require.True(t, ok, "dry run failed:\n%s", out)
			require.Equal(t, want("WOULD REPAIR"), parseRepairHierarchy(t, out))
			require.Equal(t, before, snapshot(t))
		})

		t.Run("apply", func(t *testing.T) {
			out, ok := runMailboxRepairHierarchyCmd(t, account.Email, "--apply")
			require.True(t, ok, "apply failed:\n%s", out)
			require.Equal(t, want("REPAIRED"), parseRepairHierarchy(t, out))

			inbox := get(t, "INBOX")
			require.Equal(t, helpers.FormatMailboxID(inbox.ID), inbox.Path)
			require.Equal(t, inbox.Path+helpers.FormatMailboxID(inboxChild.ID), get(t, "inbox/Child").Path)

			nested := get(t, "Nested")
			require.Equal(t, helpers.FormatMailboxID(nested.ID), nested.Path)
			require.Equal(t, nested.Path+helpers.FormatMailboxID(nestedSub.ID), get(t, "Nested/Sub").Path)
			require.Equal(t, get(t, "Nested/Sub").Path+helpers.FormatMailboxID(nestedLeaf.ID), get(t, "Nested/Sub/Leaf").Path)
		})
	})
}
