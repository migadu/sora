package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A symbolic link that belongs to the user running sora-admin, when that user is not
// root, says only that this user made it, not who gave it the name the path reaches:
// another user who can rename entries in the directory holding it, or in a directory
// above it, can move such a link there, or (where users may hard-link a file they do
// not own) keep a second name of it that has a single name again once the operator
// removes the first. The link is followed only from a directory no user but root and
// the operator can rename entries in, as renamableParent checks for the maildir cache
// (#1868). Import, --sieve, export and the export's dry run share the walk.

// operatorLinkUses are the four ways a path reaches the walk, each with the
// preparation of the directory the link leads to.
var operatorLinkUses = []struct {
	name    string
	prepare func(t *testing.T, target string)
	open    func(path string) error
}{
	{"import maildir", func(t *testing.T, target string) {
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.Mkdir(filepath.Join(target, sub), 0755))
		}
	}, func(path string) error {
		root, err := openImportRoot(path)
		if root != nil {
			root.Close()
		}
		return err
	}},
	{"import sieve", func(t *testing.T, target string) {
		require.NoError(t, os.WriteFile(filepath.Join(target, "managesieve.sieve"), []byte("keep;\n"), 0644))
	}, func(path string) error {
		_, err := readSieveFile(filepath.Join(path, "managesieve.sieve"))
		return err
	}},
	{"export maildir", func(t *testing.T, target string) {}, func(path string) error {
		root, err := openExportRoot(path)
		if root != nil {
			root.Close()
		}
		return err
	}},
	{"export maildir dry run", func(t *testing.T, target string) {}, func(path string) error {
		root, err := openExportPreviewRoot(path)
		if root != nil {
			root.Close()
		}
		return err
	}},
}

// directoryOwnedBy makes the directory at path appear to renamableParent to belong to
// uid, which only root can arrange for real.
func directoryOwnedBy(t *testing.T, uid int, path string) {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	previous := directoryOwnerAndMode
	t.Cleanup(func() { directoryOwnerAndMode = previous })
	directoryOwnerAndMode = func(dir string) (int, uint32, error) {
		owner, mode, err := previous(dir)
		if dir == resolved {
			owner = uid
		}
		return owner, mode, err
	}
}

// requireTrustedTempDir skips the test when a directory above the test's temporary
// directories is one another user could rename an entry in: there no link of the
// operator's can be followed, and the cases that expect one to be are meaningless.
func requireTrustedTempDir(t *testing.T) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	if parent, _, _, err := renamableParent(filepath.Join(dir, "x"), geteuid()); err != nil || parent != "" {
		t.Skipf("the temporary directory is below %s, which other users can rename entries in (%v)", parent, err)
	}
}

func TestLinkWalkFollowsTheOperatorsLinkOnlyWhereNoOtherUserCanRenameIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the links the test makes would be root's")
	}
	requireTrustedTempDir(t)
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name string
		// layout makes the directory that holds the link, and returns the directory
		// the refusal must name, "" when the link is followed.
		layout func(t *testing.T, base string) (stage, renamable string)
	}{
		{"the operator's directory", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			return stage, ""
		}},
		// As /tmp: others may create entries but rename only their own.
		{"a sticky directory others may write", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			require.NoError(t, os.Chmod(stage, 0o777|os.ModeSticky))
			return stage, ""
		}},
		{"another user's directory", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			directoryOwnedBy(t, int(alice), stage)
			return stage, stage
		}},
		// The sticky bit does not keep a directory's owner from renaming entries.
		{"another user's sticky directory", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			require.NoError(t, os.Chmod(stage, 0o777|os.ModeSticky))
			directoryOwnedBy(t, int(alice), stage)
			return stage, stage
		}},
		{"a directory others may write without the sticky bit", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			require.NoError(t, os.Chmod(stage, 0o777))
			return stage, stage
		}},
		{"a directory its group may write", func(t *testing.T, base string) (string, string) {
			stage := filepath.Join(base, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			require.NoError(t, os.Chmod(stage, 0o775))
			return stage, stage
		}},
		// Another user who can rename the directory above can put a directory of
		// their own at the stage's name.
		{"a directory above it others may write", func(t *testing.T, base string) (string, string) {
			outer := filepath.Join(base, "shared")
			require.NoError(t, os.Mkdir(outer, 0755))
			require.NoError(t, os.Chmod(outer, 0o777))
			stage := filepath.Join(outer, "stage")
			require.NoError(t, os.Mkdir(stage, 0755))
			return stage, outer
		}},
	} {
		for _, use := range operatorLinkUses {
			t.Run(tc.name+"/"+use.name, func(t *testing.T) {
				target := t.TempDir()
				use.prepare(t, target)
				ownedByUID(t, bob, target) // vmail's: only the operator's own link leads there
				stage, renamable := tc.layout(t, t.TempDir())
				link := filepath.Join(stage, "alice")
				require.NoError(t, os.Symlink(target, link))

				err := use.open(link)
				if renamable == "" {
					require.NoError(t, err, "the operator's link was refused where no other user can rename it")
					return
				}
				if assert.Error(t, err, "the operator's link was followed where another user can rename it") {
					assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
					resolvedRenamable, evalErr := filepath.EvalSymlinks(renamable)
					require.NoError(t, evalErr)
					assert.Contains(t, err.Error(), resolvedRenamable, "the refusal does not name the directory others can rename entries in")
				}
			})
		}
	}
}

// The rules for links of root, which a run as root also takes its own links for, and
// for links of a third user, do not depend on the directory that holds the link.
func TestLinkWalkKeepsTheRulesForLinksOfRootAndOfAThirdUser(t *testing.T) {
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name        string
		asRoot      bool
		linkOwner   uint32
		targetOwner uint32
		refused     bool
	}{
		{"running as root, root's link", true, 0, bob, false},
		{"root's link", false, 0, bob, false},
		{"a third user's link to their own directory", false, alice, alice, false},
		{"a third user's link to another user's directory", false, alice, bob, true},
	} {
		for _, use := range operatorLinkUses {
			t.Run(tc.name+"/"+use.name, func(t *testing.T) {
				if tc.asRoot {
					realGeteuid := geteuid
					t.Cleanup(func() { geteuid = realGeteuid })
					geteuid = func() int { return 0 }
				}
				target := t.TempDir()
				use.prepare(t, target)
				stage := filepath.Join(t.TempDir(), "stage")
				require.NoError(t, os.Mkdir(stage, 0755))
				require.NoError(t, os.Chmod(stage, 0o777))
				link := filepath.Join(stage, "alice")
				require.NoError(t, os.Symlink(target, link))
				ownedByUID(t, tc.linkOwner, link)
				ownedByUID(t, tc.targetOwner, target)

				err := use.open(link)
				if !tc.refused {
					require.NoError(t, err)
					return
				}
				if assert.Error(t, err, "a third user's link to another user's directory was followed") {
					assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
				}
			})
		}
	}
}
