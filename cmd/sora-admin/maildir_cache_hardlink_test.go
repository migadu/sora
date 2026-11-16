package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withoutHardLinkProtection makes the system appear to let a user hard-link a file
// they cannot write, as macOS and FreeBSD do, and Linux with fs.protected_hardlinks =
// 0. Every file a test makes belongs to the user running it, so a protected system
// lets it link them all, and writing through such a link gains that user nothing.
func withoutHardLinkProtection(t *testing.T) {
	t.Helper()
	real := hardLinksProtected
	t.Cleanup(func() { hardLinksProtected = real })
	hardLinksProtected = func() bool { return false }
}

// maildirCacheRuns open the maildir cache in a directory the way an import and an
// export do, write a row into it, and close it.
var maildirCacheRuns = []struct {
	name string
	run  func(dir string) error
}{
	{"import", func(dir string) error {
		importer, err := NewImporter(context.Background(), dir, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
		if err != nil {
			return err
		}
		defer importer.Close()
		_, err = importer.sqliteDB.Exec(`INSERT OR REPLACE INTO messages (path, filename, hash, size, mailbox) VALUES ('cur/m', 'm', 'h', 1, 'INBOX')`)
		return err
	}},
	{"export", func(dir string) error {
		exporter, err := NewExporter(context.Background(), dir, "user@example.com", 1, nil, nil, ExporterOptions{})
		if err != nil {
			return err
		}
		defer exporter.Close()
		_, err = exporter.db.Exec(`INSERT OR REPLACE INTO messages (path, filename, hash, size, mailbox) VALUES ('cur/m', 'm', 'h', 1, 'INBOX')`)
		return err
	}},
}

// SQLite opens sora-maildir.db and its -wal, -shm and -journal files by name, and a
// hard link is a regular file. Where a user may hard-link a file they cannot write,
// the maildir's owner could have an import (or export) running as root write such a
// file: the WAL index into a -shm link on every run, WAL frames into a -wal link on a
// re-run, and the cache itself into a link at sora-maildir.db to an empty file or to
// another database. The run is refused, naming the link, and the file is left as it
// was (#1669).
func TestMaildirCacheRefusesHardLinks(t *testing.T) {
	withoutHardLinkProtection(t)
	text := bytes.Repeat([]byte("this file is not the maildir's to write\n"), 40)
	cases := []struct {
		name string
		// rerun runs once before the link is made, so that the cache exists: SQLite
		// writes a -wal only of a database in WAL mode, and unlinks a stray one
		// beside an empty database.
		rerun   bool
		content []byte
	}{
		{"sora-maildir.db", false, []byte{}},
		{"sora-maildir.db-wal", true, text},
		{"sora-maildir.db-shm", false, text},
		{"sora-maildir.db-journal", false, text},
	}

	for _, r := range maildirCacheRuns {
		for _, c := range cases {
			t.Run(r.name+"/"+c.name, func(t *testing.T) {
				dir := newMaildirWith(t, nil)
				if c.rerun {
					require.NoError(t, r.run(dir))
				}
				victim := filepath.Join(t.TempDir(), "victim")
				require.NoError(t, os.WriteFile(victim, c.content, 0644))
				require.NoError(t, os.Link(victim, filepath.Join(dir, c.name)))
				realDir, err := filepath.EvalSymlinks(dir)
				require.NoError(t, err)

				err = r.run(dir)

				assert.ErrorContains(t, err, filepath.Join(realDir, c.name)+": it is a hard link", "the hard link was not refused by name")
				got, err := os.ReadFile(victim)
				require.NoError(t, err)
				assert.True(t, bytes.Equal(c.content, got), "wrote the file the hard link is another name of: now %d bytes, starting %q", len(got), got[:min(len(got), 16)])
			})
		}
	}
}

// A hard link is refused where it can be checked without a race: in a directory no
// other user can write, nobody can put one there while the run starts. In one that
// another user can write, a check of its files cannot be race-free, since SQLite opens
// the -wal and -shm files by name after any check, so the cache is not kept there at
// all: the run is refused before it creates anything.
func TestMaildirCacheRefusesADirectoryOthersCanWrite(t *testing.T) {
	withoutHardLinkProtection(t)
	cases := []struct {
		name       string
		mode       os.FileMode
		otherOwner bool
	}{
		{"its group can write", 0775, false},
		{"others can write", 0757, false},
		{"it belongs to another user", 0755, true},
	}

	for _, r := range maildirCacheRuns {
		for _, c := range cases {
			t.Run(r.name+"/"+c.name, func(t *testing.T) {
				dir := newMaildirWith(t, nil)
				require.NoError(t, os.Chmod(dir, c.mode))
				if c.otherOwner {
					realGeteuid := geteuid
					t.Cleanup(func() { geteuid = realGeteuid })
					geteuid = func() int { return os.Geteuid() + 1 }
				}
				realDir, err := filepath.EvalSymlinks(dir)
				require.NoError(t, err)

				err = r.run(dir)

				assert.ErrorContains(t, err, "refusing to keep the maildir database in "+realDir)
				assert.NotContains(t, dirNames(t, dir), maildirCacheName, "created the cache")
			})
		}
	}
}

// Where the system lets a user hard-link only a file they own or may read and write
// (Linux, fs.protected_hardlinks = 1), a hard link at the cache's names can only make
// the run write a file whoever put it there could write themselves: the cache is kept
// in a directory others can write, as before.
func TestMaildirCacheOpensInADirectoryOthersCanWriteWithProtectedHardLinks(t *testing.T) {
	real := hardLinksProtected
	t.Cleanup(func() { hardLinksProtected = real })
	hardLinksProtected = func() bool { return true }

	for _, r := range maildirCacheRuns {
		t.Run(r.name, func(t *testing.T) {
			dir := newMaildirWith(t, nil)
			require.NoError(t, os.Chmod(dir, 0777))

			require.NoError(t, r.run(dir))
			assert.FileExists(t, filepath.Join(dir, maildirCacheName))
		})
	}
}
