package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedTempDir makes a temporary directory every user can write, with the sticky bit,
// as /tmp, and points TMPDIR at it.
func sharedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0777|os.ModeSticky))
	t.Setenv("TMPDIR", dir)
	return dir
}

// linkBesideWorkDatabases stands in for another local user of the temporary directory
// dir. It hard-links victim at the -shm name of every database of `import s3` it can
// find under dir, where that user may create a name: in a directory that others may
// write in, reached through directories others may list and enter.
func linkBesideWorkDatabases(dir, victim string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	info, err := os.Stat(dir)
	writable := err == nil && info.Mode().Perm()&0o003 == 0o003
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir():
			if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o005 == 0o005 {
				linkBesideWorkDatabases(path, victim)
			}
		case writable && e.Type().IsRegular() && strings.HasPrefix(e.Name(), "sora-s3-import") && strings.HasSuffix(e.Name(), ".db"):
			_ = os.Link(victim, path+"-shm")
		}
	}
}

// `import s3` keeps its work database in the temporary directory, which other users
// can often write (/tmp). SQLite opens the database's -wal and -shm files by name at
// the first transaction and writes through a hard link at those names, so another
// user who saw the new database in a listing could link a file of someone else's at
// its -shm name in time, and the import, often run as root, wrote its WAL index into
// that file (#1739). The database is kept where no other user can add a name.
func TestS3ImporterWorkDatabaseIsOutOfReachOfOtherUsers(t *testing.T) {
	const runs = 20
	content := bytes.Repeat([]byte("this file is not the import's to write\n"), 40)
	overwritten := 0
	var sample []byte
	for range runs {
		tmpDir := sharedTempDir(t)
		victim := filepath.Join(t.TempDir(), "victim")
		require.NoError(t, os.WriteFile(victim, content, 0644))
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					linkBesideWorkDatabases(tmpDir, victim)
				}
			}
		}()

		si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
		if err == nil {
			err = si.Close()
		}
		close(stop)
		<-done

		got, readErr := os.ReadFile(victim)
		require.NoError(t, readErr)
		if !bytes.Equal(content, got) {
			overwritten++
			sample = got
		}
		assert.NoError(t, err)
	}
	assert.Zero(t, overwritten, "wrote the file a hard link at the work database's -shm names in %d of %d runs: now %d bytes, starting %q",
		overwritten, runs, len(sample), sample[:min(len(sample), 16)])
}

// The work database is in a directory of the run's own, which only its owner can add
// a name to, inside TMPDIR.
func TestS3ImporterKeepsWorkDatabaseInAPrivateDirectory(t *testing.T) {
	tmpDir := sharedTempDir(t)
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
	require.NoError(t, err)
	defer si.Close()

	dir := filepath.Dir(si.dbPath)
	assert.Equal(t, realTmpDir, filepath.Dir(dir), "the work database is not in a directory of its own in TMPDIR")
	assert.True(t, strings.HasPrefix(filepath.Base(dir), "sora-s3-import-"), "directory %s", dir)
	info, err := os.Lstat(dir)
	require.NoError(t, err)
	assert.Equal(t, "drwx------", info.Mode().String(), "directory %s", dir)
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, os.Geteuid(), int(st.Uid), "directory %s", dir)
}

// The run's directory is made by its name, and SQLite opens the database's files by
// that name later. Where a user may hard-link a file they cannot write, a user who can
// rename an entry in a directory above it (TMPDIR or one of its parents) could put a
// directory of their own, with a hard link at -shm, at its name in between, so the run
// refuses such a TMPDIR before it creates the database, as the maildir cache does
// (#1669). The sticky bit, as on /tmp, keeps others from renaming an entry they do not
// own, and where hard links are protected (Linux, fs.protected_hardlinks = 1) such a
// link gains its maker nothing: both are allowed.
func TestS3ImporterRefusesATempDirOthersCanReplaceItsDirectoryIn(t *testing.T) {
	cases := []struct {
		name                string
		tmpMode, parentMode os.FileMode
		otherOwner          bool
		protected           bool
		refused             bool
	}{
		{"others can write in TMPDIR", 0777, 0700, false, false, true},
		{"its group can write in TMPDIR", 0770, 0700, false, false, true},
		{"others can write above TMPDIR", 0700, 0777, false, false, true},
		{"TMPDIR belongs to another user", 0700, 0700, true, false, true},
		{"others can write in TMPDIR with the sticky bit", 0777 | os.ModeSticky, 0700, false, false, false},
		{"others can write in TMPDIR with the sticky bit and protected hard links", 0777 | os.ModeSticky, 0700, false, true, false},
		{"others can write in TMPDIR with protected hard links", 0777, 0777, false, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			realProtection := hardLinksProtected
			t.Cleanup(func() { hardLinksProtected = realProtection })
			hardLinksProtected = func() bool { return c.protected }
			parent := t.TempDir()
			tmpDir := filepath.Join(parent, "tmp")
			require.NoError(t, os.Mkdir(tmpDir, 0700))
			require.NoError(t, os.Chmod(tmpDir, c.tmpMode))
			require.NoError(t, os.Chmod(parent, c.parentMode))
			if c.otherOwner {
				realGeteuid := geteuid
				t.Cleanup(func() { geteuid = realGeteuid })
				geteuid = func() int { return os.Geteuid() + 1 }
			}
			t.Setenv("TMPDIR", tmpDir)
			realTmpDir, err := filepath.EvalSymlinks(tmpDir)
			require.NoError(t, err)

			si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
			if err == nil {
				require.NoError(t, si.Close())
			}

			if !c.refused {
				require.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, "refusing to keep the S3 import's work database in "+realTmpDir)
			assert.ErrorContains(t, err, "TMPDIR")
			assert.Empty(t, dirNames(t, tmpDir), "the refused run left its directory in TMPDIR")
		})
	}
}

// The run's directory is made by its name in TMPDIR, and --cleanup-db removes it with
// everything in it. A user who may rename entries of TMPDIR (one without the sticky
// bit) can move it aside the moment it appears and put a symbolic link to another
// directory at its name. Even where hard links are protected, rename and symlink swaps
// in a non-sticky TMPDIR are still allowed by the kernel, so such a TMPDIR must be
// refused before creating anything and without writing into or removing the link's target.
func TestS3ImporterCleanupRemovesOnlyItsOwnDirectory(t *testing.T) {
	for _, protected := range []bool{true, false} {
		t.Run(fmt.Sprintf("protected hard links %t", protected), func(t *testing.T) {
			realProtection, realMkdirTemp := hardLinksProtected, mkdirTemp
			t.Cleanup(func() { hardLinksProtected, mkdirTemp = realProtection, realMkdirTemp })
			hardLinksProtected = func() bool { return protected }
			tmpDir := t.TempDir()
			require.NoError(t, os.Chmod(tmpDir, 0777))
			t.Setenv("TMPDIR", tmpDir)
			realTmpDir, err := filepath.EvalSymlinks(tmpDir)
			require.NoError(t, err)
			precious := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(precious, "keep"), []byte("not the import's\n"), 0600))
			mkdirTemp = func(dir, pattern string) (string, error) {
				name, err := realMkdirTemp(dir, pattern)
				if err == nil {
					require.NoError(t, os.Rename(name, name+".moved"))
					require.NoError(t, os.Symlink(precious, name))
				}
				return name, err
			}

			si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
			if err == nil {
				require.NoError(t, si.Close())
			}

			assert.FileExists(t, filepath.Join(precious, "keep"), "--cleanup-db removed the directory the link at the run's directory named")
			assert.ErrorContains(t, err, "refusing to keep the S3 import's work database in ")
			assert.ErrorContains(t, err, "can rename entries of "+realTmpDir+" above it")
			assert.Equal(t, []string{"keep"}, dirNames(t, precious), "the refused run wrote in the directory the link named")
		})
	}
}

func TestS3ImporterConfinesPrivateDirectoryAgainstSwapAndCleanup(t *testing.T) {
	t.Run("symlink swap at creation in sticky TMPDIR", func(t *testing.T) {
		for _, protected := range []bool{true, false} {
			t.Run(fmt.Sprintf("protected_%t", protected), func(t *testing.T) {
				realProtection, realMkdirTemp := hardLinksProtected, mkdirTemp
				t.Cleanup(func() { hardLinksProtected, mkdirTemp = realProtection, realMkdirTemp })
				hardLinksProtected = func() bool { return protected }
				sharedTempDir(t)
				precious := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(precious, "keep"), []byte("not the import's\n"), 0600))
				mkdirTemp = func(dir, pattern string) (string, error) {
					name, err := realMkdirTemp(dir, pattern)
					if err == nil {
						require.NoError(t, os.Rename(name, name+".moved"))
						require.NoError(t, os.Symlink(precious, name))
					}
					return name, err
				}

				si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
				if si != nil {
					_ = si.Close()
				}
				require.Error(t, err, "must refuse private directory replaced with a symlink")
				assert.Equal(t, []string{"keep"}, dirNames(t, precious), "must not create work database through swapped symlink")
			})
		}
	})

	t.Run("directory replacement before Close preserves replacement contents", func(t *testing.T) {
		sharedTempDir(t)
		si, err := NewS3Importer(context.Background(), nil, nil, S3ImporterOptions{Workers: 1, CleanupDB: true})
		require.NoError(t, err)
		dir := filepath.Dir(si.dbPath)

		replacement := filepath.Join(t.TempDir(), "replacement")
		require.NoError(t, os.Mkdir(replacement, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(replacement, "keep"), []byte("other user's file"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(replacement, s3ImportDBName), []byte("other user's db"), 0600))

		moved := dir + ".moved"
		require.NoError(t, os.Rename(dir, moved))
		t.Cleanup(func() { _ = os.RemoveAll(moved); _ = os.RemoveAll(dir) })
		require.NoError(t, os.Rename(replacement, dir))

		require.NoError(t, si.Close())
		assert.ElementsMatch(t, []string{"keep", s3ImportDBName}, dirNames(t, dir),
			"Close must not remove files from a directory renamed onto the work directory path")
		assert.Empty(t, dirNames(t, moved), "Close must unlink its own work database files via the held directory descriptor")
	})
}
