package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

// Checking a private leaf before its ancestors lets a replaceable parent temporarily
// name a trusted directory for its own check, then return to the attacker's tree.
// A new symlink must also be rejected rather than vouched for by its target's owner.
func TestMaildirCacheRejectsDirectoryPivotDuringAncestryChecks(t *testing.T) {
	for _, beforeParent := range []bool{false, true} {
		name := "after leaf check"
		if beforeParent {
			name = "before parent check"
		}
		t.Run(name, func(t *testing.T) {
			withoutHardLinkProtection(t)
			grand := t.TempDir()
			require.NoError(t, os.Chmod(grand, 0777|os.ModeSticky))
			parent := filepath.Join(grand, "parent")
			leaf := filepath.Join(parent, "cache")
			require.NoError(t, os.MkdirAll(leaf, 0700))
			physical, err := resolveMaildirDir(leaf)
			require.NoError(t, err)
			parent = filepath.Dir(physical)
			grand = filepath.Dir(parent)
			safe := t.TempDir()
			safe, err = resolveMaildirDir(safe)
			require.NoError(t, err)
			require.NoError(t, os.Mkdir(filepath.Join(safe, "cache"), 0700))
			saved := filepath.Join(grand, "saved-parent")
			phase := 0
			swap := func() {
				require.NoError(t, os.Rename(parent, saved))
				require.NoError(t, os.Symlink(safe, parent))
				phase = 1
			}
			restore := func() { require.NoError(t, os.Remove(parent)); require.NoError(t, os.Rename(saved, parent)); phase = 2 }
			original := directoryOwnerAndMode
			directoryOwnerAndMode = func(path string) (int, uint32, error) {
				if beforeParent && path == parent && phase == 0 {
					swap()
				}
				owner, mode, err := original(path)
				if err != nil {
					return owner, mode, err
				}
				// Model the unprivileged parent owner's UID, just as geteuid models the
				// operator in the existing ownership tests; all path operations are real.
				if path == parent && phase == 0 {
					owner = os.Geteuid() + 1
				}
				if !beforeParent && path == physical && phase == 0 {
					swap()
				} else if path == parent && phase == 1 {
					restore()
				}
				return owner, mode, nil
			}
			t.Cleanup(func() {
				directoryOwnerAndMode = original
				if phase == 1 {
					restore()
				}
			})
			cache, err := openMaildirCacheAt(t, physical)
			if err != nil {
				assert.Contains(t, err.Error(), "maildir database")
				return
			}
			defer cache.Close()
			require.Equal(t, 2, phase)
			// The attacker can now replace the leaf below their own restored parent.
			// sql.DB has not opened its connection yet; SQLite opens the sidecars later.
			require.NoError(t, os.Rename(physical, filepath.Join(grand, "checked-cache")))
			require.NoError(t, os.Mkdir(physical, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(physical, maildirCacheName), nil, 0600))
			victim := filepath.Join(t.TempDir(), "victim")
			content := bytes.Repeat([]byte("private data\n"), 40)
			require.NoError(t, os.WriteFile(victim, content, 0600))
			require.NoError(t, os.Link(victim, filepath.Join(physical, maildirCacheName+"-shm")))
			_, execErr := cache.Exec("CREATE TABLE proof (id INTEGER)")
			got, readErr := os.ReadFile(victim)
			require.NoError(t, readErr)
			t.Fatalf("admitted cache after ancestor pivot; SQLite error=%v, linked victim changed=%v (%d to %d bytes)", execErr, !bytes.Equal(content, got), len(content), len(got))
		})
	}
}
