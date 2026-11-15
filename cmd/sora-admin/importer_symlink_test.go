package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scannedMessages returns the mailbox and path of every message the scan cached.
func scannedMessages(t *testing.T, importer *Importer) map[string]string {
	t.Helper()
	rows, err := importer.sqliteDB.Query("SELECT mailbox, path FROM messages")
	require.NoError(t, err)
	defer rows.Close()
	got := make(map[string]string)
	for rows.Next() {
		var mailbox, path string
		require.NoError(t, rows.Scan(&mailbox, &path))
		got[path] = mailbox
	}
	require.NoError(t, rows.Err())
	return got
}

// addMaildirFolder adds folder name below maildirPath holding one message, name -> content.
func addMaildirFolder(t *testing.T, maildirPath, folder, name string, content []byte) {
	t.Helper()
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, folder, dir), 0755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(maildirPath, folder, "cur", name), content, 0644))
}

// --path naming a symbolic link to a maildir passes validation (isMaildirFolder
// stats through the link), so the scan must walk the maildir the link names, not
// stop at the link: filepath.Walk lstats its root and saw a non-directory, and the
// run imported nothing. Paths stay under the path given, which mailbox names,
// keywords and uidlists are all resolved against (#1398).
func TestScanMaildirFollowsASymlinkedRoot(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const sentName = "1700000002.M2P1.host:2,S"
	real := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
	addMaildirFolder(t, real, ".Sent", sentName, cachedSizeMessage("Two", 100))

	link := filepath.Join(t.TempDir(), "Maildir")
	require.NoError(t, os.Symlink(real, link))

	importer := newTestModeImporter(t, link, newMockResilientDatabase(), ImporterOptions{})
	require.NoError(t, importer.scanMaildir())

	assert.Equal(t, map[string]string{
		filepath.Join(link, "cur", inboxName):         "INBOX",
		filepath.Join(link, ".Sent", "cur", sentName): "Sent",
	}, scannedMessages(t, importer))
}

// A folder below the root that is a symbolic link is not followed (a link to
// another folder of the same maildir is an alias, which dsync skips too; one
// pointing elsewhere would have the import read outside the path it was given),
// but it must not be dropped silently either: the run names it in a warning (#1398).
func TestScanMaildirWarnsAboutASymlinkedFolder(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const otherName = "1700000002.M2P1.host:2,S"

	for _, tc := range []struct {
		name   string
		target func(t *testing.T, maildirPath string) string
	}{
		{"outside the maildir", func(t *testing.T, _ string) string {
			return newMaildirWith(t, map[string][]byte{otherName: cachedSizeMessage("Archived", 100)})
		}},
		{"alias of a folder", func(t *testing.T, maildirPath string) string {
			addMaildirFolder(t, maildirPath, ".Sent", otherName, cachedSizeMessage("Sent", 100))
			return ".Sent"
		}},
		// The volume the folder lives on is not mounted: the link dangles, so it
		// cannot be told from a link to a file, and is named all the same.
		{"target missing", func(t *testing.T, _ string) string {
			return filepath.Join(t.TempDir(), "unmounted", ".Archive")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
			linkPath := filepath.Join(maildirPath, ".Archive")
			require.NoError(t, os.Symlink(tc.target(t, maildirPath), linkPath))

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			logs := scanMaildirWarnings(t, importer)

			for path, mailbox := range scannedMessages(t, importer) {
				assert.NotEqual(t, "Archive", mailbox, "the linked folder was imported: %s", path)
			}
			assert.Contains(t, logs, linkPath, "the linked folder was skipped without a warning naming it")
		})
	}
}

// Links inside cur/, new/ and tmp/ are message files, which the folder's own scan
// reads through the link or refuses by path; tmp/ is never read. None of them is a
// skipped folder, dangling or not, so none gets the symbolic-link warning.
func TestScanMaildirDoesNotWarnAboutLinkedMessageFiles(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
	missing := filepath.Join(t.TempDir(), "missing")
	require.NoError(t, os.Symlink(filepath.Join(maildirPath, "cur", inboxName), filepath.Join(maildirPath, "new", "1700000002.M2P1.host")))
	require.NoError(t, os.Symlink(missing, filepath.Join(maildirPath, "new", "1700000003.M3P1.host")))
	require.NoError(t, os.Symlink(missing, filepath.Join(maildirPath, "tmp", "1700000004.M4P1.host")))

	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
	logs := scanMaildirWarnings(t, importer)

	assert.NotContains(t, logs, "symbolic link")
}

// scanMaildirWarnings runs the scan and returns what it logged at warning level.
func scanMaildirWarnings(t *testing.T, importer *Importer) string {
	t.Helper()
	logs := &importLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	err := importer.scanMaildir()
	logger.Swap(prev)
	require.NoError(t, err)
	return logs.String()
}

// A Maildir root can itself be named cur, new or tmp. Its direct children are
// folders, not message files merely because the root has one of those names.
func TestScanMaildirWarnsAboutLinkedFoldersBelowMessageNamedRoot(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	for _, rootName := range []string{"cur", "new", "tmp"} {
		for _, dangling := range []bool{false, true} {
			name := rootName + "/existing"
			if dangling {
				name = rootName + "/dangling"
			}
			t.Run(name, func(t *testing.T) {
				original := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
				root := filepath.Join(t.TempDir(), rootName)
				require.NoError(t, os.Rename(original, root))
				target := filepath.Join(t.TempDir(), "unmounted", ".Archive")
				if !dangling {
					target = newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("Archived", 100)})
				}
				link := filepath.Join(root, ".Archive")
				require.NoError(t, os.Symlink(target, link))
				importer := newTestModeImporter(t, root, newMockResilientDatabase(), ImporterOptions{})
				logs := scanMaildirWarnings(t, importer)
				assert.Contains(t, logs, link, "the root's name hid its skipped folder")
				assert.Equal(t, map[string]string{filepath.Join(root, "cur", inboxName): "INBOX"}, scannedMessages(t, importer))
			})
		}
	}
}
