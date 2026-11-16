package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A hard link is another name for the same file, which the root the import reads
// through cannot tell from the file's first name: a user who can write in their maildir
// or home directory can name with one a file elsewhere on the same file system, where
// the system lets them link a file they cannot read (BSD and macOS do, as Linux does
// with fs.protected_hardlinks = 0). The import runs with privileges the user lacks, so
// it must not read such a file into their account (#1663).

// ownedByAnotherUser makes the files at paths appear to belong to another user than
// the owner of the directories the test made, as root's files do to a user: only root
// can give a file away (fileUID).
func ownedByAnotherUser(t *testing.T, paths ...string) {
	t.Helper()
	var others []fs.FileInfo
	for _, path := range paths {
		info, err := os.Stat(path)
		require.NoError(t, err)
		others = append(others, info)
	}
	realFileUID := fileUID
	t.Cleanup(func() { fileUID = realFileUID })
	fileUID = func(info fs.FileInfo) uint32 {
		for _, other := range others {
			if os.SameFile(info, other) {
				return realFileUID(info) + 1
			}
		}
		return realFileUID(info)
	}
}

// anotherUsersFile writes content, readable by its owner only, to a file outside any
// maildir that appears to belong to another user, and returns its path.
func anotherUsersFile(t *testing.T, content []byte) string {
	t.Helper()
	path := outsideFile(t, content)
	require.NoError(t, os.Chmod(path, 0600))
	ownedByAnotherUser(t, path)
	return path
}

func TestScanMaildirRefusesAHardLinkToAnotherUsersFile(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const linkName = "1700000002.M2P1.host:2,S"

	for _, subDir := range []string{"cur", "new"} {
		t.Run(subDir, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
			link := filepath.Join(maildirPath, subDir, linkName)
			require.NoError(t, os.Link(anotherUsersFile(t, cachedSizeMessage("Secret", 100)), link))

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())

			assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", inboxName): "INBOX"},
				scannedMessages(t, importer), "a hard link to another user's file was cached for import")
			if reasons := failureReasons(importer, link); assert.Len(t, reasons, 1, "the hard link is not refused by path") {
				assert.Contains(t, reasons[0], "another user")
			}
		})
	}

	// Dovecot copies a message between folders as a hard link
	// (maildir_copy_with_hardlinks), and a backup made with cp -al or rsnapshot links
	// every file: the owner's own files are read however many names they have.
	t.Run("hard link to a file of the maildir's owner", func(t *testing.T) {
		const sentName = "1700000003.M3P1.host:2,S"
		maildirPath := newMaildirWith(t, nil)
		inbox := filepath.Join(maildirPath, "cur", inboxName)
		require.NoError(t, os.WriteFile(inbox, cachedSizeMessage("One", 100), 0600))
		addMaildirFolder(t, maildirPath, ".Sent", sentName, cachedSizeMessage("Sent", 100))
		copied := filepath.Join(maildirPath, ".Sent", "cur", linkName)
		require.NoError(t, os.Link(inbox, copied))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		got := scannedMessages(t, importer)
		assert.Equal(t, "INBOX", got[inbox])
		assert.Equal(t, "Sent", got[copied])
		assert.Empty(t, importer.failedPaths)
	})

	// A file anyone may read gives the user nothing they could not read themselves.
	t.Run("hard link to another user's file anyone may read", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		public := outsideFile(t, cachedSizeMessage("Public", 100))
		ownedByAnotherUser(t, public)
		link := filepath.Join(maildirPath, "cur", linkName)
		require.NoError(t, os.Link(public, link))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Equal(t, "INBOX", scannedMessages(t, importer)[link])
		assert.Empty(t, importer.failedPaths)
	})
}

// The import phase reads every cached row again, by the path the cache holds: one an
// earlier run cached, or a file replaced by a hard link since the scan.
func TestImportRefusesACachedMessageHardLinkedToAnotherUsersFile(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"

	cachedThenLinked := func(t *testing.T) (*Importer, string) {
		t.Helper()
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("Kept", 100)})
		path := filepath.Join(maildirPath, "cur", name)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.lookupAccount())
		require.NoError(t, importer.scanMaildir())
		require.Equal(t, "INBOX", scannedMessages(t, importer)[path])

		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Link(anotherUsersFile(t, cachedSizeMessage("Secret", 100)), path))
		importer.totalMessages = 1
		return importer, path
	}

	t.Run("import", func(t *testing.T) {
		importer, path := cachedThenLinked(t)
		require.NoError(t, importer.importMessages())
		assert.Zero(t, importer.importedMessages, "imported the file the cached message is now a hard link to")
		assert.Len(t, failureReasons(importer, path), 1)
	})

	t.Run("dry run", func(t *testing.T) {
		importer, _ := cachedThenLinked(t)
		out := captureStdout(t, importer.performDryRun)
		assert.NotContains(t, out, "Secret", "the dry run read the file the cached message is now a hard link to")
	})
}

func TestImportSieveScriptRefusesAHardLinkToAnotherUsersFile(t *testing.T) {
	const secret = "root:secret-hash:19000:0:99999:7:::\n"

	for _, dryRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "import", true: "dry run"}[dryRun], func(t *testing.T) {
			sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
			require.NoError(t, os.Link(anotherUsersFile(t, []byte(secret)), sievePath))

			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath, DryRun: dryRun})
			require.NoError(t, importer.lookupAccount())

			err := importer.importSieveScript()
			if assert.Error(t, err, "the hard link was read") {
				assert.Contains(t, err.Error(), sievePath, "the refusal does not name the file")
				assert.Contains(t, err.Error(), "another user")
			}
			assert.Empty(t, rdb.stored, "the file the hard link names was stored as a Sieve script")
			assert.Empty(t, importer.sieveOutcome, "the outcome says the script was or would be stored")
		})
	}

	// --sieve may name a file the operator wrote in a directory of another user's, as
	// /tmp is root's: one anyone may read is read, one only its owner may read is not.
	t.Run("file in another user's directory", func(t *testing.T) {
		dir := t.TempDir()
		ownedByAnotherUser(t, dir)
		for _, tc := range []struct {
			name   string
			perm   os.FileMode
			stored bool
		}{{"public.sieve", 0644, true}, {"private.sieve", 0600, false}} {
			sievePath := filepath.Join(dir, tc.name)
			require.NoError(t, os.WriteFile(sievePath, []byte("keep;\n"), tc.perm))
			require.NoError(t, os.Chmod(sievePath, tc.perm))

			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
			require.NoError(t, importer.lookupAccount())

			err := importer.importSieveScript()
			if tc.stored {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, []string{"keep;\n"}, rdb.stored, tc.name)
			} else {
				assert.Error(t, err, tc.name)
				assert.Empty(t, rdb.stored, tc.name)
			}
		}
	})
}

// worldWritableDirOf returns a directory anyone may write into (mode 1777) that appears
// to belong to the owner of the files at paths, as /tmp is root's.
func worldWritableDirOf(t *testing.T, paths ...string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o1777))
	ownedByAnotherUser(t, append([]string{dir}, paths...)...)
	return dir
}

// The user chooses the directory --maildir-path names when it is a link they made, and
// can point it at a directory of the linked file's owner that anyone may write into, as
// /tmp is root's: its owner vouches for none of the names in it.
func TestScanMaildirRefusesAHardLinkInAMaildirLinkedToADirectoryAnyoneMayWrite(t *testing.T) {
	const linkName = "1700000002.M2P1.host:2,S"
	secret := outsideFile(t, cachedSizeMessage("Secret", 100))
	require.NoError(t, os.Chmod(secret, 0600))
	shared := worldWritableDirOf(t, secret)
	for _, dir := range []string{"cur", "new"} {
		require.NoError(t, os.Mkdir(filepath.Join(shared, dir), 0755))
	}
	require.NoError(t, os.Link(secret, filepath.Join(shared, "cur", linkName)))
	require.NoError(t, os.WriteFile(filepath.Join(shared, "dovecot-keywords"), []byte("0 Secret\n"), 0600))
	ownedByAnotherUser(t, filepath.Join(shared, "dovecot-keywords"))
	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	require.NoError(t, os.Symlink(shared, maildirPath))

	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})
	require.NoError(t, importer.scanMaildir())

	assert.Empty(t, scannedMessages(t, importer), "a hard link to another user's file was cached for import")
	assert.Len(t, failureReasons(importer, filepath.Join(maildirPath, "cur", linkName)), 1)
	assert.Empty(t, importer.dovecotKeywords, "a dovecot-keywords file in a directory anyone may write was read")
}

// A maildir extracted as root into a directory root made keeps its files' owner below
// that directory. The owner's own messages are theirs to import; a file of root's they
// linked into their cur/ is not, though it belongs to the owner of the maildir root.
func TestScanMaildirInADirectoryOfAnotherUser(t *testing.T) {
	const ownName = "1700000001.M1P1.host:2,S"
	const linkName = "1700000002.M2P1.host:2,S"
	maildirPath := newMaildirWith(t, nil)
	own := filepath.Join(maildirPath, "cur", ownName)
	require.NoError(t, os.WriteFile(own, cachedSizeMessage("Own", 100), 0600))
	secret := outsideFile(t, cachedSizeMessage("Secret", 100))
	require.NoError(t, os.Chmod(secret, 0600))
	ownedByAnotherUser(t, maildirPath, secret)
	link := filepath.Join(maildirPath, "cur", linkName)
	require.NoError(t, os.Link(secret, link))

	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
	require.NoError(t, importer.scanMaildir())

	assert.Equal(t, map[string]string{own: "INBOX"}, scannedMessages(t, importer),
		"the owner's own message was refused, or root's file they linked in was cached")
	assert.Len(t, failureReasons(importer, link), 1)
	assert.Empty(t, failureReasons(importer, own))
}

// --sieve may name a file in a directory anyone may write into, as /tmp is root's, or in
// one a link the user made leads to: anyone may have named there a file of the
// directory's owner.
func TestImportSieveScriptRefusesAHardLinkInADirectoryAnyoneMayWrite(t *testing.T) {
	secret := outsideFile(t, []byte("root:secret-hash:19000:0:99999:7:::\n"))
	require.NoError(t, os.Chmod(secret, 0600))
	shared := worldWritableDirOf(t, secret)
	require.NoError(t, os.Link(secret, filepath.Join(shared, "x.sieve")))
	home := t.TempDir()
	require.NoError(t, os.Symlink(shared, filepath.Join(home, "sieve")))

	for name, sievePath := range map[string]string{
		"named":          filepath.Join(shared, "x.sieve"),
		"through a link": filepath.Join(home, "sieve", "x.sieve"),
	} {
		t.Run(name, func(t *testing.T) {
			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
			require.NoError(t, importer.lookupAccount())

			err := importer.importSieveScript()
			if assert.Error(t, err, "the hard link was read") {
				assert.Contains(t, err.Error(), "another user")
			}
			assert.Empty(t, rdb.stored, "the file the hard link names was stored as a Sieve script")
		})
	}
}
