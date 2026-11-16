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

// --maildir-path may be a link root made to a directory of the linked file's owner that
// anyone may write into, as /tmp is root's: its owner vouches for none of the names in
// it. (A link the user made there is refused before the scan, #1729.)
func TestScanMaildirRefusesAHardLinkInAMaildirLinkedToADirectoryAnyoneMayWrite(t *testing.T) {
	// Exercise the content-reader policy on the protected-hardlink cache branch.
	// The unprotected branch now refuses this world-writable cache directory before
	// the scan; TestMaildirCacheRefusesADirectoryOthersCanWrite covers that boundary.
	previousProtection := hardLinksProtected
	t.Cleanup(func() { hardLinksProtected = previousProtection })
	hardLinksProtected = func() bool { return true }
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
	ownedByUID(t, 0, maildirPath)

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
// one a link root made leads to: anyone may have named there a file of the directory's
// owner. (A link the user made there is refused before the file is opened, #1729.)
func TestImportSieveScriptRefusesAHardLinkInADirectoryAnyoneMayWrite(t *testing.T) {
	secret := outsideFile(t, []byte("root:secret-hash:19000:0:99999:7:::\n"))
	require.NoError(t, os.Chmod(secret, 0600))
	shared := worldWritableDirOf(t, secret)
	require.NoError(t, os.Link(secret, filepath.Join(shared, "x.sieve")))
	home := t.TempDir()
	require.NoError(t, os.Symlink(shared, filepath.Join(home, "sieve")))
	ownedByUID(t, 0, filepath.Join(home, "sieve"))

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

// A name that is a link vouches for a file others may not read only below its own
// directory. Pigeonhole's ~/.dovecot.sieve -> sieve/<name>.sieve is, and Pigeonhole
// writes the script for its owner only; a message file linked to another folder's
// is not.
func TestImportFollowsALinkToAFileOthersMayNotReadOnlyBelowItsDirectory(t *testing.T) {
	t.Run("Pigeonhole link to a script only its owner may read", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(home, "sieve"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(home, "sieve", "managesieve.sieve"), []byte("keep;\n"), 0600))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())
		require.NoError(t, importer.importSieveScript())
		assert.Equal(t, []string{"keep;\n"}, rdb.stored)
	})

	t.Run("message link to another folder's file only its owner may read", func(t *testing.T) {
		const sentName = "1700000003.M3P1.host:2,S"
		const linkName = "1700000002.M2P1.host:2,S"
		maildirPath := newMaildirWith(t, nil)
		addMaildirFolder(t, maildirPath, ".Sent", sentName, cachedSizeMessage("Sent", 100))
		sent := filepath.Join(maildirPath, ".Sent", "cur", sentName)
		require.NoError(t, os.Chmod(sent, 0600))
		link := filepath.Join(maildirPath, "cur", linkName)
		require.NoError(t, os.Symlink(relativeLink(t, link, sent), link))

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Equal(t, map[string]string{sent: "Sent"}, scannedMessages(t, importer))
		if reasons := failureReasons(importer, link); assert.Len(t, reasons, 1) {
			assert.Contains(t, reasons[0], "not found below the directory that holds its name")
		}
	})
}

// A group member with write access can place the same hard link as any other writer.
// The directory's matching owner alone cannot vouch for a private file in that case.
func TestScanMaildirRefusesPrivateHardLinkInGroupWritableDirectory(t *testing.T) {
	for _, tc := range []struct {
		name          string
		directoryMode os.FileMode
		fileMode      os.FileMode
		wantCached    bool
	}{
		{"group write and private file", 0770, 0600, false},
		{"group read without write and private file", 0750, 0600, true},
		{"group write and public file", 0770, 0644, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const name = "1700000002.M2P1.host:2,S"
			maildir := newMaildirWith(t, nil)
			directory := filepath.Join(maildir, "cur")
			require.NoError(t, os.Chmod(directory, tc.directoryMode))
			secret := outsideFile(t, cachedSizeMessage("Group secret", 100))
			require.NoError(t, os.Chmod(secret, tc.fileMode))
			ownedByAnotherUser(t, directory, secret)
			path := filepath.Join(directory, name)
			require.NoError(t, os.Link(secret, path))
			importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())
			_, cached := scannedMessages(t, importer)[path]
			assert.Equal(t, tc.wantCached, cached)
			if !tc.wantCached {
				require.Len(t, failureReasons(importer, path), 1)
				assert.Contains(t, failureReasons(importer, path)[0], "group or others may write")
			}
		})
	}
}

// ownedByUID makes the entries at paths (without following symbolic links) appear to
// belong to uid (fileUID).
func ownedByUID(t *testing.T, uid uint32, paths ...string) {
	t.Helper()
	var entries []fs.FileInfo
	for _, path := range paths {
		info, err := os.Lstat(path)
		require.NoError(t, err)
		entries = append(entries, info)
	}
	prevFileUID := fileUID
	t.Cleanup(func() { fileUID = prevFileUID })
	fileUID = func(info fs.FileInfo) uint32 {
		for _, entry := range entries {
			if os.SameFile(info, entry) {
				return uid
			}
		}
		return prevFileUID(info)
	}
}

// Unix evaluates owner, group, and other permission classes in strict first-match order:
// a file with mode 0604 or 0404 (other-read set, group-read clear) denies read access to
// every member of its group, so only 0444 makes a file readable by every local user.
func TestScanMaildirAndSieveRefuseNegativeGroupPermissionHardLinks(t *testing.T) {
	const name = "1700000002.M2P1.host:2,S"

	for _, mode := range []os.FileMode{0604, 0404} {
		t.Run("maildir hard link/"+mode.String(), func(t *testing.T) {
			maildir := newMaildirWith(t, nil)
			secret := outsideFile(t, cachedSizeMessage("GroupExcluded", 100))
			require.NoError(t, os.Chmod(secret, mode))
			ownedByAnotherUser(t, secret)
			link := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.Link(secret, link))

			importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())

			assert.Empty(t, scannedMessages(t, importer), "hard link with mode %04o was cached", mode)
			if reasons := failureReasons(importer, link); assert.Len(t, reasons, 1) {
				assert.Contains(t, reasons[0], "another user")
			}
		})

		t.Run("sieve hard link/"+mode.String(), func(t *testing.T) {
			secret := outsideFile(t, []byte("keep;\n"))
			require.NoError(t, os.Chmod(secret, mode))
			ownedByAnotherUser(t, secret)
			sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
			require.NoError(t, os.Link(secret, sievePath))

			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
			require.NoError(t, importer.lookupAccount())

			err := importer.importSieveScript()
			if assert.Error(t, err, "sieve hard link with mode %04o was read", mode) {
				assert.Contains(t, err.Error(), "another user")
			}
			assert.Empty(t, rdb.stored)
		})
	}

	t.Run("group-writable directory with 0604 file", func(t *testing.T) {
		maildir := newMaildirWith(t, nil)
		directory := filepath.Join(maildir, "cur")
		require.NoError(t, os.Chmod(directory, 0770))
		secret := outsideFile(t, cachedSizeMessage("GroupExcluded", 100))
		require.NoError(t, os.Chmod(secret, 0604))
		ownedByAnotherUser(t, directory, secret)
		link := filepath.Join(directory, name)
		require.NoError(t, os.Link(secret, link))

		importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Empty(t, scannedMessages(t, importer))
		if reasons := failureReasons(importer, link); assert.Len(t, reasons, 1) {
			assert.Contains(t, reasons[0], "group or others may write")
		}
	})

	t.Run("owner's own 0604 file in non-writable directory is read", func(t *testing.T) {
		maildir := newMaildirWith(t, nil)
		own := filepath.Join(maildir, "cur", name)
		require.NoError(t, os.WriteFile(own, cachedSizeMessage("Own0604", 100), 0604))
		require.NoError(t, os.Chmod(own, 0604))

		importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Equal(t, map[string]string{own: "INBOX"}, scannedMessages(t, importer))
		assert.Empty(t, importer.failedPaths)
	})
}

// A non-root owner matches the owner permission class even when group or other read bits
// are set: without 0400, the file's own owner cannot read it.
func TestImportRefusesOwnerUnreadableFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0000, 0200, 0040, 0044, 0004} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Chmod(dir, 0700))
			path := filepath.Join(dir, "msg")
			require.NoError(t, os.WriteFile(path, []byte("secret"), 0600))
			require.NoError(t, os.Chmod(path, mode))
			ownedByUID(t, 1000, dir, path)

			info, err := os.Stat(path)
			require.NoError(t, err)
			root, err := os.OpenRoot(dir)
			require.NoError(t, err)
			defer root.Close()

			err = checkNamedByOwner(root, "msg", info)
			if assert.ErrorIs(t, err, errAnotherUsersFile, "mode %04o was accepted for non-root owner", mode) {
				assert.Contains(t, err.Error(), "owner may not read")
			}
		})
	}

	t.Run("non-root owner with 0400 is allowed", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0700))
		path := filepath.Join(dir, "msg")
		require.NoError(t, os.WriteFile(path, []byte("own"), 0400))
		require.NoError(t, os.Chmod(path, 0400))
		ownedByUID(t, 1000, dir, path)

		info, err := os.Stat(path)
		require.NoError(t, err)
		root, err := os.OpenRoot(dir)
		require.NoError(t, err)
		defer root.Close()

		assert.NoError(t, checkNamedByOwner(root, "msg", info))
	})

	t.Run("root owner with 0000 in root directory is allowed", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0700))
		path := filepath.Join(dir, "msg")
		require.NoError(t, os.WriteFile(path, []byte("root"), 0600))
		require.NoError(t, os.Chmod(path, 0000))
		ownedByUID(t, 0, dir, path)

		info, err := os.Stat(path)
		require.NoError(t, err)
		root, err := os.OpenRoot(dir)
		require.NoError(t, err)
		defer root.Close()

		assert.NoError(t, checkNamedByOwner(root, "msg", info))
	})
}

// When a symbolic link below the import root delegates to a subdirectory (such as
// /home/alice/.dovecot.sieve -> sieve/managesieve.sieve under a root-owned ChrootDirectory
// home), checkNamedByOwner must verify the directory that actually holds the target file.
func TestImportSieveAndMaildirCheckTargetDirectoryOfSymbolicLink(t *testing.T) {
	const secret = "root:secret-hash:19000:0:99999:7:::\n"

	t.Run("root home link into user sieve directory refuses root hard link", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Chmod(home, 0755))
		sieveDir := filepath.Join(home, "sieve")
		require.NoError(t, os.Mkdir(sieveDir, 0700))
		shadow := outsideFile(t, []byte(secret))
		require.NoError(t, os.Chmod(shadow, 0600))
		target := filepath.Join(sieveDir, "managesieve.sieve")
		require.NoError(t, os.Link(shadow, target))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))

		ownedByUID(t, 1000, sieveDir)
		ownedByUID(t, 0, home, sievePath, shadow)

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		err := importer.importSieveScript()
		if assert.Error(t, err, "root's file hard-linked in user's sieve/ was read") {
			assert.Contains(t, err.Error(), "another user")
		}
		assert.Empty(t, rdb.stored)
	})

	t.Run("root home link into user sieve directory allows user private script", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Chmod(home, 0755))
		sieveDir := filepath.Join(home, "sieve")
		require.NoError(t, os.Mkdir(sieveDir, 0700))
		target := filepath.Join(sieveDir, "managesieve.sieve")
		require.NoError(t, os.WriteFile(target, []byte("keep;\n"), 0600))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))

		ownedByUID(t, 1000, sieveDir, target)
		ownedByUID(t, 0, home, sievePath)

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		require.NoError(t, importer.importSieveScript())
		assert.Equal(t, []string{"keep;\n"}, rdb.stored)
	})

	t.Run("link into group-writable sieve subdirectory is refused", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Chmod(home, 0700))
		sieveDir := filepath.Join(home, "sieve")
		require.NoError(t, os.Mkdir(sieveDir, 0770))
		require.NoError(t, os.Chmod(sieveDir, 0770))
		target := filepath.Join(sieveDir, "managesieve.sieve")
		require.NoError(t, os.WriteFile(target, []byte("keep;\n"), 0600))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		err := importer.importSieveScript()
		if assert.Error(t, err, "private script in group-writable sieve/ was read") {
			assert.Contains(t, err.Error(), "group or others may write")
		}
		assert.Empty(t, rdb.stored)
	})

	t.Run("user-owned link in root home to root subdirectory is refused", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Chmod(home, 0755))
		rootSub := filepath.Join(home, "root_secrets")
		require.NoError(t, os.Mkdir(rootSub, 0700))
		shadow := filepath.Join(rootSub, "shadow")
		require.NoError(t, os.WriteFile(shadow, []byte(secret), 0600))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("root_secrets", "shadow"), sievePath))

		ownedByUID(t, 1000, sievePath)
		ownedByUID(t, 0, home, rootSub, shadow)

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		err := importer.importSieveScript()
		if assert.Error(t, err, "user's link to root's private file was read") {
			assert.Contains(t, err.Error(), "another user")
		}
		assert.Empty(t, rdb.stored)
	})

	t.Run("non-root other user home link into user sieve directory is refused", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.Chmod(home, 0755))
		sieveDir := filepath.Join(home, "sieve")
		require.NoError(t, os.Mkdir(sieveDir, 0700))
		target := filepath.Join(sieveDir, "managesieve.sieve")
		require.NoError(t, os.WriteFile(target, []byte("keep;\n"), 0600))
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))

		ownedByUID(t, 1000, sieveDir, target)
		ownedByUID(t, 1001, home, sievePath)

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		err := importer.importSieveScript()
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "another user")
		}
		assert.Empty(t, rdb.stored)
	})

	t.Run("link using dotdot through symlinked subdirectory is refused", func(t *testing.T) {
		const sentName = "1700000009.M9P1.host:2,S"
		maildir := newMaildirWith(t, nil)
		addMaildirFolder(t, maildir, ".Sent", sentName, cachedSizeMessage("DotDotSent", 100))
		sentPath := filepath.Join(maildir, ".Sent", "cur", sentName)
		require.NoError(t, os.Chmod(sentPath, 0600))

		curDir := filepath.Join(maildir, "cur")
		upLink := filepath.Join(curDir, ".up")
		require.NoError(t, os.Symlink("../cur", upLink))
		msgLink := filepath.Join(curDir, "1700000002.M2P1.host:2,S")
		require.NoError(t, os.Symlink(".up/../.Sent/cur/"+sentName, msgLink))

		importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Equal(t, map[string]string{sentPath: "Sent"}, scannedMessages(t, importer))
		if reasons := failureReasons(importer, msgLink); assert.Len(t, reasons, 1) {
			assert.Contains(t, reasons[0], "not found below the directory that holds its name")
		}
	})
}

// A symbolic link on an intermediate directory component (such as .Sent/cur) must not
// escape its folder or vouch for another user's private directory.
func TestScanMaildirRefusesPrivateFilesThroughSymlinkedMessageDirectory(t *testing.T) {
	const name = "1700000002.M2P1.host:2,S"

	t.Run("cur linked out of folder to another user's directory in maildir", func(t *testing.T) {
		maildir := newMaildirWith(t, nil)
		rootSecrets := filepath.Join(maildir, "root_secrets")
		require.NoError(t, os.Mkdir(rootSecrets, 0700))
		secret := filepath.Join(rootSecrets, name)
		require.NoError(t, os.WriteFile(secret, cachedSizeMessage("RootSecret", 100), 0600))

		sentFolder := filepath.Join(maildir, ".Sent")
		require.NoError(t, os.MkdirAll(filepath.Join(sentFolder, "new"), 0700))
		require.NoError(t, os.MkdirAll(filepath.Join(sentFolder, "tmp"), 0700))
		require.NoError(t, os.Chmod(sentFolder, 0700))
		curLink := filepath.Join(sentFolder, "cur")
		require.NoError(t, os.Symlink(filepath.Join("..", "root_secrets"), curLink))

		ownedByUID(t, 1000, sentFolder, curLink)
		ownedByUID(t, 0, maildir, rootSecrets, secret)

		importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Empty(t, scannedMessages(t, importer), "root's private file was cached via .Sent/cur -> ../root_secrets")
		msgPath := filepath.Join(sentFolder, "cur", name)
		if reasons := failureReasons(importer, msgPath); assert.Len(t, reasons, 1) {
			assert.Contains(t, reasons[0], "not found below the directory that holds its name")
		}
	})

	t.Run("cur linked to root subdirectory inside user's folder", func(t *testing.T) {
		maildir := newMaildirWith(t, nil)
		sentFolder := filepath.Join(maildir, ".Sent")
		require.NoError(t, os.MkdirAll(filepath.Join(sentFolder, "new"), 0700))
		require.NoError(t, os.MkdirAll(filepath.Join(sentFolder, "tmp"), 0700))
		require.NoError(t, os.Chmod(sentFolder, 0700))

		subSecrets := filepath.Join(sentFolder, "sub_secrets")
		require.NoError(t, os.Mkdir(subSecrets, 0700))
		secret := filepath.Join(subSecrets, name)
		require.NoError(t, os.WriteFile(secret, cachedSizeMessage("RootSecret", 100), 0600))
		curLink := filepath.Join(sentFolder, "cur")
		require.NoError(t, os.Symlink("sub_secrets", curLink))

		ownedByUID(t, 1000, maildir, sentFolder, curLink)
		ownedByUID(t, 0, subSecrets, secret)

		importer := newTestModeImporter(t, maildir, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.scanMaildir())

		assert.Empty(t, scannedMessages(t, importer), "root's private file was cached via .Sent/cur -> sub_secrets")
		msgPath := filepath.Join(sentFolder, "cur", name)
		if reasons := failureReasons(importer, msgPath); assert.Len(t, reasons, 1) {
			assert.Contains(t, reasons[0], "another user")
		}
	})
}
