package main

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openImportRoot checks the directory --maildir-path leads to and opens it as the
// root. The maildir's owner can replace the path right after, renaming ~/Maildir and
// putting a link to bob's maildir in its place. Nothing may then reach a directory by
// that name again: the cache is created, and the folders are listed, in the directory
// that was checked, or the import refuses to start; the directory the path leads to
// now is left as it was (#1729).

// replaceMaildirPath renames the directory at path to path + ".checked" and puts a
// symbolic link to victim at path, as the owner of the directory holding path can.
func replaceMaildirPath(t *testing.T, path, victim string) (checked string) {
	t.Helper()
	checked = path + ".checked"
	require.NoError(t, os.Rename(path, checked))
	require.NoError(t, os.Symlink(victim, path))
	return checked
}

// treeOf returns the size of every file below dir, by name relative to it.
func treeOf(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	tree := make(map[string]int64)
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		tree[rel] = info.Size()
		return nil
	}))
	return tree
}

func TestNewImporterUsesOnlyTheCheckedRootWhenThePathIsReplaced(t *testing.T) {
	const aliceName = "1700000001.M1P1.host:2,S"
	const bobName = "1700000002.M2P1.host:2,S"

	for _, victimCache := range []bool{false, true} {
		name := "victim without a cache"
		if victimCache {
			name = "victim with a cache"
		}
		t.Run(name, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{aliceName: cachedSizeMessage("Alice", 100)})
			victim := newMaildirWith(t, map[string][]byte{bobName: cachedSizeMessage("Bob", 100)})
			if victimCache {
				// An empty file is an empty SQLite database.
				require.NoError(t, os.WriteFile(filepath.Join(victim, maildirCacheName), nil, 0644))
			}
			before := treeOf(t, victim)
			var checked string
			importRootOpened = func() { checked = replaceMaildirPath(t, maildirPath, victim) }
			t.Cleanup(func() { importRootOpened = nil })

			importer, err := NewImporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			if err == nil {
				t.Cleanup(func() { importer.Close() })
				importer.rdb = newMockResilientDatabase()
				assert.FileExists(t, filepath.Join(checked, maildirCacheName), "the cache is not in the directory that was checked")
				require.NoError(t, importer.scanMaildir())
				assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", aliceName): "INBOX"}, scannedMessages(t, importer))
			} else {
				assert.ErrorContains(t, err, "maildir database", "not a refusal of the replaced path")
			}
			assert.Equal(t, before, treeOf(t, victim), "the import changed the directory the path leads to now")
		})
	}
}

func TestScanMaildirWalksTheCheckedRootWhenThePathIsReplaced(t *testing.T) {
	const aliceName = "1700000001.M1P1.host:2,S"
	const aliceSent = "1700000002.M2P1.host:2,S"
	const bobName = "1700000003.M3P1.host:2,S"
	maildirPath := newMaildirWith(t, map[string][]byte{aliceName: cachedSizeMessage("Alice", 100)})
	addMaildirFolder(t, maildirPath, ".AliceSent", aliceSent, cachedSizeMessage("AliceSent", 100))
	victim := newMaildirWith(t, nil)
	addMaildirFolder(t, victim, ".BobPrivate", bobName, cachedSizeMessage("Bob", 100))

	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
	replaceMaildirPath(t, maildirPath, victim)
	logs := &importLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	err := importer.scanMaildir()
	logger.Swap(prev)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		filepath.Join(maildirPath, "cur", aliceName):               "INBOX",
		filepath.Join(maildirPath, ".AliceSent", "cur", aliceSent): "AliceSent",
	}, scannedMessages(t, importer), "the scan did not walk the directory that was checked")
	assert.NotContains(t, logs.String(), "BobPrivate", "the scan listed a folder of the directory the path leads to now")
}
