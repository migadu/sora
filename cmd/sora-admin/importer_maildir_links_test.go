package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The maildir an operator imports may have been written by its owner (a copy from a
// host where users had shell or FTP access, made with rsync -a, which keeps links as
// links), and the import runs with privileges the owner lacks. No symbolic link below
// the maildir may have the import read a file outside it, at any level: a message
// file, cur/ or new/, or a metadata file (#1548). A folder that is a link is not
// followed at all (#1398).

// outsideFile writes content to a file outside any maildir and returns its path.
func outsideFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(path, content, 0644))
	return path
}

// relativeLink returns target as seen from the directory link is in.
func relativeLink(t *testing.T, link, target string) string {
	t.Helper()
	rel, err := filepath.Rel(filepath.Dir(link), target)
	require.NoError(t, err)
	return rel
}

func TestScanMaildirRefusesMessageLinksOutOfTheMaildir(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const linkName = "1700000002.M2P1.host:2,S"

	for _, tc := range []struct {
		name     string
		relative bool
	}{
		{"absolute link", false},
		{"relative link", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
			secret := outsideFile(t, cachedSizeMessage("Secret", 100))
			link := filepath.Join(maildirPath, "cur", linkName)
			target := secret
			if tc.relative {
				target = relativeLink(t, link, secret)
			}
			require.NoError(t, os.Symlink(target, link))

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())

			assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", inboxName): "INBOX"},
				scannedMessages(t, importer), "a message file linked out of the maildir was cached for import")
			assert.Len(t, failureReasons(importer, link), 1, "the linked message file is not refused by path")
		})
	}

	// A link to a message of another folder of the same maildir reads nothing the
	// import was not given, and is read as before.
	t.Run("link within the maildir", func(t *testing.T) {
		const sentName = "1700000003.M3P1.host:2,S"
		maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
		addMaildirFolder(t, maildirPath, ".Sent", sentName, cachedSizeMessage("Sent", 100))
		link := filepath.Join(maildirPath, "cur", linkName)
		require.NoError(t, os.Symlink(relativeLink(t, link, filepath.Join(maildirPath, ".Sent", "cur", sentName)), link))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Equal(t, "INBOX", scannedMessages(t, importer)[link])
		assert.Empty(t, failureReasons(importer, link))
	})
}

func TestScanMaildirRefusesAMessageDirectoryLinkedOutOfTheMaildir(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const otherName = "1700000002.M2P1.host:2,S"

	for _, subDir := range []string{"cur", "new"} {
		t.Run(subDir, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
			other := newMaildirWith(t, nil)
			require.NoError(t, os.WriteFile(filepath.Join(other, subDir, otherName), cachedSizeMessage("Other", 100), 0644))

			folder := filepath.Join(maildirPath, ".Work")
			for _, dir := range []string{"cur", "new", "tmp"} {
				if dir != subDir {
					require.NoError(t, os.MkdirAll(filepath.Join(folder, dir), 0755))
				}
			}
			link := filepath.Join(folder, subDir)
			require.NoError(t, os.Symlink(filepath.Join(other, subDir), link))

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			logs := scanMaildirWarnings(t, importer)

			assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", inboxName): "INBOX"},
				scannedMessages(t, importer), "a message directory linked out of the maildir was read")
			assert.Contains(t, logs, link, "the linked message directory was skipped without a warning naming it")
		})
	}
}

// The import phase reads every cached row again, by the path the cache holds: one an
// earlier run cached for a file that is a link (as runs before #1548 did), or a file
// replaced by a link since the scan.
func TestImportRefusesACachedMessageLinkedOutOfTheMaildir(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"

	// cachedThenLinked returns an importer whose scan cached the maildir's message,
	// and the message's path, now a link to a file outside the maildir.
	cachedThenLinked := func(t *testing.T) (*Importer, string) {
		t.Helper()
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("Kept", 100)})
		path := filepath.Join(maildirPath, "cur", name)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.lookupAccount())
		require.NoError(t, importer.scanMaildir())
		require.Equal(t, "INBOX", scannedMessages(t, importer)[path])

		secret := outsideFile(t, cachedSizeMessage("Secret", 100))
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Symlink(secret, path))
		importer.totalMessages = 1
		return importer, path
	}

	t.Run("import", func(t *testing.T) {
		importer, path := cachedThenLinked(t)
		require.NoError(t, importer.importMessages())
		assert.Zero(t, importer.importedMessages, "imported the file the cached message is now a link to")
		assert.Len(t, failureReasons(importer, path), 1)
	})

	t.Run("dry run", func(t *testing.T) {
		importer, _ := cachedThenLinked(t)
		out := captureStdout(t, importer.performDryRun)
		assert.NotContains(t, out, "Secret", "the dry run read the file the cached message is now a link to")
	})
}

func TestImportReadsNoMaildirMetadataThroughALinkOutOfTheMaildir(t *testing.T) {
	const name = "1700000001.M1P1.host:2,a"

	t.Run("subscriptions", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		require.NoError(t, os.Symlink(outsideFile(t, []byte("V\t2\n\nSecret\n")), filepath.Join(maildirPath, "subscriptions")))

		mockDB := &recordingSubMockDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, maildirPath, mockDB, ImporterOptions{Dovecot: true})
		require.NoError(t, importer.lookupAccount())

		assert.Error(t, importer.processSubscriptions())
		assert.Empty(t, mockDB.subscribed, "subscribed to the lines of a file outside the maildir")
	})

	t.Run("root dovecot-keywords", func(t *testing.T) {
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("One", 100)})
		require.NoError(t, os.Symlink(outsideFile(t, []byte("0 Secret\n")), filepath.Join(maildirPath, "dovecot-keywords")))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})

		assert.Empty(t, importer.keywordsForMessagePath(filepath.Join(maildirPath, "cur", name)),
			"keywords read from a file outside the maildir")
	})

	t.Run("folder dovecot-keywords", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		addMaildirFolder(t, maildirPath, ".Work", name, cachedSizeMessage("One", 100))
		require.NoError(t, os.Symlink(outsideFile(t, []byte("0 Secret\n")), filepath.Join(maildirPath, ".Work", "dovecot-keywords")))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})

		assert.Empty(t, importer.keywordsForMessagePath(filepath.Join(maildirPath, ".Work", "cur", name)),
			"keywords read from a file outside the maildir")
	})

	t.Run("dovecot-uidlist", func(t *testing.T) {
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("One", 100)})
		uidlist := outsideFile(t, []byte("3 V1234 N8\n7 :"+name+"\n"))
		require.NoError(t, os.Symlink(uidlist, filepath.Join(maildirPath, "dovecot-uidlist")))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{PreserveUIDs: true})
		require.NoError(t, importer.scanMaildir())

		assert.Empty(t, importer.dovecotUIDLists, "a dovecot-uidlist outside the maildir was loaded")
	})
}

// The cache keeps the path a file was first scanned under. A run given another
// spelling of the same maildir (a link to it, or the directory a link names) imports
// those rows as before.
func TestImportReadsCachedRowsUnderAnotherSpellingOfTheMaildir(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"

	for _, tc := range []struct {
		name            string
		scanVia, runVia func(real, link string) string
	}{
		{"cached via a link, run on the directory",
			func(_, link string) string { return link }, func(real, _ string) string { return real }},
		{"cached on the directory, run via a link",
			func(real, _ string) string { return real }, func(_, link string) string { return link }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			real := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("One", 100)})
			link := filepath.Join(t.TempDir(), "Maildir")
			require.NoError(t, os.Symlink(real, link))

			earlier := newTestModeImporter(t, tc.scanVia(real, link), newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, earlier.scanMaildir())
			require.NoError(t, earlier.Close())

			importer := newTestModeImporter(t, tc.runVia(real, link), newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.Run())
			assert.Equal(t, int64(1), importer.importedMessages)
			assert.Zero(t, importer.failedMessages)
		})
	}
}
