package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The export checks the directory --maildir-path leads to, creating what is missing,
// and opens it as the root it writes through. The walk opens the directories above it
// for search only, so, as for os.MkdirAll, they need not be readable; and once the root
// is open nothing reaches a directory by the path again: the user can rename ~/Maildir
// right after the check and put a link to bob's maildir in its place, and the cache
// must then be created in the directory that was checked, or the export refuse to
// start, leaving bob's maildir as it was (#1729, #1785).

func TestNewExporterNeedsOnlySearchPermissionAboveTheRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may read every directory")
	}
	for _, tc := range []struct{ name, below string }{
		{"existing maildir", filepath.Join("alice", "Maildir")},
		{"missing directories", filepath.Join("bob", "new", "Maildir")},
		{"missing directory in the searchable one", "Maildir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			require.NoError(t, os.MkdirAll(filepath.Join(home, "alice", "Maildir"), 0755))
			require.NoError(t, os.Mkdir(filepath.Join(home, "bob"), 0755))
			require.NoError(t, os.Chmod(home, 0311))
			t.Cleanup(func() { os.Chmod(home, 0755) })
			_, err := os.ReadDir(home)
			require.ErrorIs(t, err, fs.ErrPermission, "the test user may still list the directory")
			maildirPath := filepath.Join(home, tc.below)

			exporter, err := NewExporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ExporterOptions{})
			require.NoError(t, err)
			require.NoError(t, exporter.Close())
			assert.FileExists(t, filepath.Join(maildirPath, maildirCacheName))
		})
	}
}

func TestNewExporterUsesOnlyTheCheckedRootWhenThePathIsReplaced(t *testing.T) {
	for _, victimCache := range []bool{false, true} {
		name := "victim without a cache"
		if victimCache {
			name = "victim with a cache"
		}
		t.Run(name, func(t *testing.T) {
			maildirPath := filepath.Join(t.TempDir(), "Maildir")
			require.NoError(t, os.Mkdir(maildirPath, 0755))
			victim := newMaildirWith(t, nil)
			if victimCache {
				// An empty file is an empty SQLite database.
				require.NoError(t, os.WriteFile(filepath.Join(victim, maildirCacheName), nil, 0644))
			}
			before := treeNames(t, victim)
			checked := maildirPath + ".checked"
			exportRootOpened = func() {
				require.NoError(t, os.Rename(maildirPath, checked))
				require.NoError(t, os.Symlink(victim, maildirPath))
			}
			t.Cleanup(func() { exportRootOpened = nil })

			exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ExporterOptions{})
			if err == nil {
				require.NoError(t, exporter.Close())
				assert.FileExists(t, filepath.Join(checked, maildirCacheName), "the cache is not in the directory that was checked")
			} else {
				assert.ErrorContains(t, err, "maildir database", "not a refusal of the replaced path")
			}
			assert.Equal(t, before, treeNames(t, victim), "the export created files in the directory the path leads to now")
			if victimCache {
				info, err := os.Stat(filepath.Join(victim, maildirCacheName))
				require.NoError(t, err)
				assert.Zero(t, info.Size(), "the export wrote the cache the path leads to now")
			}
		})
	}
}
