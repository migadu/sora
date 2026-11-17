package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This schedules an attacker-owned holding directory being renamed out of a sticky
// parent after its link was read, then replaced by an operator-owned directory.
// UID ownership is modeled with the existing seams; filesystem renames are real.
func TestOperatorLinkParentReplacementCannotVouchForPinnedFD(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root operator")
	}
	requireTrustedTempDir(t)
	alice, bob := rootLinkUIDs()
	for _, level := range []string{"containing directory", "ancestor directory"} {
		for _, use := range operatorLinkUses {
			t.Run(level+"/"+use.name, func(t *testing.T) {
				base, err := filepath.EvalSymlinks(t.TempDir())
				require.NoError(t, err)
				public := filepath.Join(base, "public")
				require.NoError(t, os.Mkdir(public, 0755))
				require.NoError(t, os.Chmod(public, 0777|os.ModeSticky))
				stage := filepath.Join(public, "stage")
				require.NoError(t, os.Mkdir(stage, 0777))
				require.NoError(t, os.Chmod(stage, 0777))
				stageInfo, err := os.Lstat(stage)
				require.NoError(t, err)
				ownedByUID(t, alice, stage)
				drop := filepath.Join(base, "drop")
				require.NoError(t, os.Mkdir(drop, 0777))
				require.NoError(t, os.Chmod(drop, 0777))
				replacement := filepath.Join(drop, "safe")
				require.NoError(t, os.Mkdir(replacement, 0755))
				target := filepath.Join(base, "target")
				require.NoError(t, os.Mkdir(target, 0755))
				use.prepare(t, target)
				ownedByUID(t, bob, target)
				holding := stage
				if level == "ancestor directory" {
					holding = filepath.Join(stage, "inner")
					require.NoError(t, os.Mkdir(holding, 0755))
					require.NoError(t, os.Mkdir(filepath.Join(replacement, "inner"), 0755))
				}
				link := filepath.Join(holding, "alice")
				require.NoError(t, os.Symlink(target, link))
				moved := filepath.Join(public, "old-stage")
				previous := directoryOwnerAndMode
				t.Cleanup(func() { directoryOwnerAndMode = previous })
				swapped := false
				directoryOwnerAndMode = func(dir string) (int, uint32, error) {
					if dir == stage && !swapped {
						require.NoError(t, os.Rename(stage, moved))
						require.NoError(t, os.Rename(replacement, stage))
						swapped = true
					}
					owner, mode, err := previous(dir)
					if info, serr := os.Lstat(dir); serr == nil && sameFileID(stageInfo, info) {
						owner = int(alice)
					}
					return owner, mode, err
				}
				err = use.open(link)
				require.True(t, swapped, "did not reach the operator-link directory check")
				assert.Error(t, err, "a safe replacement pathname vouched for the link read from the old directory FD")
			})
		}
	}
}

func TestOperatorLinkDirectoryRuleIndependentOfHardLinkProtection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root operator")
	}
	requireTrustedTempDir(t)
	_, bob := rootLinkUIDs()
	for _, tc := range []struct {
		name              string
		protected, sticky bool
	}{
		{"protected sticky", true, true}, {"protected nonsticky", true, false},
		{"unprotected sticky", false, true}, {"unprotected nonsticky", false, false},
	} {
		for _, use := range operatorLinkUses {
			t.Run(tc.name+"/"+use.name, func(t *testing.T) {
				previous := hardLinksProtected
				t.Cleanup(func() { hardLinksProtected = previous })
				hardLinksProtected = func() bool { return tc.protected }
				target := t.TempDir()
				use.prepare(t, target)
				ownedByUID(t, bob, target)
				stage := filepath.Join(t.TempDir(), "stage")
				require.NoError(t, os.Mkdir(stage, 0755))
				mode := os.FileMode(0777)
				if tc.sticky {
					mode |= os.ModeSticky
				}
				require.NoError(t, os.Chmod(stage, mode))
				link := filepath.Join(stage, "alice")
				require.NoError(t, os.Symlink(target, link))
				err := use.open(link)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "stage")
			})
		}
	}
}
