//go:build darwin || linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Crash without sql.DB.Close: committed data is deliberately left in WAL, not
// checkpointed into the DB. The same path can leave a rollback journal instead.
func TestExportSnapshotCrashFixture(t *testing.T) {
	mode := os.Getenv("SORA_EXPORT_SNAPSHOT_FIXTURE")
	if mode == "" {
		return
	}
	dir := os.Getenv("SORA_EXPORT_SNAPSHOT_SOURCE")
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(dir, maildirCacheName)}).String()
	d, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT,path TEXT,size INTEGER);
		INSERT INTO messages VALUES('seed','INBOX','seed.eml','',1)`)
	require.NoError(t, err)
	require.NoError(t, d.Close())
	d, err = sql.Open("sqlite", dsn)
	require.NoError(t, err)
	if mode == "wal" {
		_, err = d.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
			INSERT INTO messages VALUES('committed','INBOX','committed.eml','',1);
			BEGIN IMMEDIATE; INSERT INTO messages VALUES('uncommitted','INBOX','uncommitted.eml','',1)`)
	} else {
		_, err = d.Exec(`PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE; UPDATE messages SET path='not-committed'`)
	}
	require.NoError(t, err)
	os.Exit(0)
}

func crashExportSnapshotSource(t *testing.T, mode string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Mail dir #1 100% ?")
	require.NoError(t, os.Mkdir(dir, 0700))
	cmd := exec.Command(os.Args[0], "-test.run=^TestExportSnapshotCrashFixture$")
	cmd.Env = append(os.Environ(), "SORA_EXPORT_SNAPSHOT_FIXTURE="+mode, "SORA_EXPORT_SNAPSHOT_SOURCE="+dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return dir
}

// Include every directory entry and byte, including the source WAL and SHM.
// Comparing before Close as well as after catches transient source sidecars.
func exportCacheSourceState(t *testing.T, dir string) map[string]string {
	t.Helper()
	state := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
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
		state[rel] = fmt.Sprintf("mode=%s,size=%d", info.Mode(), info.Size())
		if info.Mode().IsRegular() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			state[rel] += fmt.Sprintf(",sha=%x", sha256.Sum256(b))
		}
		return nil
	})
	require.NoError(t, err)
	return state
}

func TestExporterDryRunCrashWALSnapshotPreservesAllSourceFiles(t *testing.T) {
	dir := crashExportSnapshotSource(t, "wal")
	wal, err := os.Stat(filepath.Join(dir, maildirCacheName+"-wal"))
	require.NoError(t, err)
	require.Greater(t, wal.Size(), int64(32), "committed data must reside in WAL")
	// A stale/corrupt source SHM is not trusted or rebuilt in place.
	require.NoError(t, os.WriteFile(filepath.Join(dir, maildirCacheName+"-shm"), []byte("source SHM must remain untouched"), 0600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "cur"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", "committed.eml"), []byte("body"), 0600))
	before := exportCacheSourceState(t, dir)
	e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	require.NoError(t, err)
	private := e.privateCacheDir
	require.NotEmpty(t, private)
	info, err := os.Stat(private)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	var n int
	require.NoError(t, e.db.QueryRow(`SELECT count(*) FROM messages WHERE hash='committed'`).Scan(&n))
	require.Equal(t, 1, n, "must replay committed WAL content, not immutable=1 main-only view")
	require.NoError(t, e.db.QueryRow(`SELECT count(*) FROM messages WHERE hash='uncommitted'`).Scan(&n))
	require.Zero(t, n)
	exists, name, err := e.isMessageExported("committed", "INBOX")
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, "committed.eml", name)
	_, err = e.db.Exec(`DELETE FROM messages`)
	require.ErrorContains(t, err, "readonly", "private SQL connection is query-only")
	require.Equal(t, before, exportCacheSourceState(t, dir), "source must be unchanged while private reader remains open")
	require.NoError(t, e.Close())
	_, err = os.Stat(private)
	require.True(t, os.IsNotExist(err), "Close must remove private DB/WAL/SHM directory")
	require.Equal(t, before, exportCacheSourceState(t, dir))
}

func TestExporterDryRunRefusesLiveSQLiteWithoutTouchingSource(t *testing.T) {
	for _, transaction := range []bool{false, true} {
		t.Run(fmt.Sprintf("write_transaction_%t", transaction), func(t *testing.T) {
			dir := t.TempDir()
			d, err := openMaildirCacheAt(t, dir)
			require.NoError(t, err)
			defer d.Close()
			_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT); INSERT INTO messages VALUES('live','INBOX','live.eml')`)
			require.NoError(t, err)
			if transaction {
				_, err = d.Exec(`BEGIN IMMEDIATE; INSERT INTO messages VALUES('pending','INBOX','pending.eml')`)
				require.NoError(t, err)
				defer d.Exec("ROLLBACK")
			}
			before := exportCacheSourceStateFromAnotherProcess(t, dir)
			e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			require.ErrorContains(t, err, "exclusively locked")
			require.Nil(t, e)
			require.Equal(t, before, exportCacheSourceStateFromAnotherProcess(t, dir))
			var n int
			require.NoError(t, d.QueryRow(`SELECT count(*) FROM messages`).Scan(&n))
			require.Greater(t, n, 0, "failed helper must not release/corrupt caller's SQLite locks")
		})
	}
}

func TestExporterDryRunRefusesRollbackRecoveryWithoutSourceChanges(t *testing.T) {
	dir := crashExportSnapshotSource(t, "rollback")
	info, err := os.Stat(filepath.Join(dir, maildirCacheName+"-journal"))
	require.NoError(t, err)
	require.Positive(t, info.Size())
	before := exportCacheSourceState(t, dir)
	e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	require.ErrorContains(t, err, "rollback journal")
	require.Nil(t, e)
	require.Equal(t, before, exportCacheSourceState(t, dir))
}

func TestExporterDryRunSnapshotFailureCleanup(t *testing.T) {
	for _, mode := range []string{"no_messages_schema", "incompatible_messages_schema", "corrupt", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			temporary := t.TempDir()
			t.Setenv("TMPDIR", temporary)
			dir := t.TempDir()
			path := filepath.Join(dir, maildirCacheName)
			if mode == "corrupt" {
				require.NoError(t, os.WriteFile(path, []byte("not SQLite"), 0600))
			} else {
				d, err := sql.Open("sqlite", path)
				require.NoError(t, err)
				schema := "CREATE TABLE other(value TEXT)"
				if mode == "incompatible_messages_schema" {
					schema = "CREATE TABLE messages(hash TEXT)"
				}
				_, err = d.Exec(schema)
				require.NoError(t, err)
				require.NoError(t, d.Close())
			}
			before := exportCacheSourceState(t, dir)
			ctx := context.Background()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			e, err := NewExporter(ctx, dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			if mode == "no_messages_schema" {
				require.NoError(t, err)
				require.Nil(t, e.db)
				require.NoError(t, e.Close())
			} else {
				require.Error(t, err)
				require.Nil(t, e)
			}
			require.Equal(t, before, exportCacheSourceState(t, dir))
			entries, err := os.ReadDir(temporary)
			require.NoError(t, err)
			require.Empty(t, entries, "failed/unused snapshots must not leak")
		})
	}
}

// Hashing a live main DB in its SQLite-owning process would close an extra FD
// for the inode and release its POSIX locks. Keep test observation separate too.
func TestExportSnapshotStateFixture(t *testing.T) {
	dir := os.Getenv("SORA_EXPORT_STATE_SOURCE")
	if dir == "" {
		return
	}
	data, err := json.Marshal(exportCacheSourceState(t, dir))
	require.NoError(t, err)
	fmt.Println("STATEJSON:" + string(data))
}

func exportCacheSourceStateFromAnotherProcess(t *testing.T, dir string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExportSnapshotStateFixture$")
	cmd.Env = append(os.Environ(), "SORA_EXPORT_STATE_SOURCE="+dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "STATEJSON:") {
			var state map[string]string
			require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "STATEJSON:")), &state))
			return state
		}
	}
	t.Fatalf("missing source state: %s", out)
	return nil
}

func TestExporterDryRunRejectsUnsafeCacheComponents(t *testing.T) {
	for _, kind := range []string{"main_symlink", "main_hardlink", "main_fifo", "main_directory", "wal_symlink", "wal_hardlink", "wal_fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, maildirCacheName)
			outside := filepath.Join(t.TempDir(), "outside.db")
			d, err := sql.Open("sqlite", outside)
			require.NoError(t, err)
			_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT)`)
			require.NoError(t, err)
			require.NoError(t, d.Close())
			switch kind {
			case "main_symlink":
				require.NoError(t, os.Symlink(outside, name))
			case "main_hardlink":
				require.NoError(t, os.Link(outside, name))
			case "main_fifo":
				require.NoError(t, makeExportSnapshotFIFO(name))
			case "main_directory":
				require.NoError(t, os.Mkdir(name, 0700))
			default:
				b, err := os.ReadFile(outside)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(name, b, 0600))
				if kind == "wal_symlink" {
					require.NoError(t, os.Symlink(outside, name+"-wal"))
				} else if kind == "wal_hardlink" {
					require.NoError(t, os.Link(outside, name+"-wal"))
				} else {
					require.NoError(t, makeExportSnapshotFIFO(name+"-wal"))
				}
			}
			before := exportCacheSourceState(t, dir)
			external := exportCacheSourceState(t, filepath.Dir(outside))
			e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			require.Error(t, err)
			require.Nil(t, e)
			require.Equal(t, before, exportCacheSourceState(t, dir))
			require.Equal(t, external, exportCacheSourceState(t, filepath.Dir(outside)))
		})
	}
}

func TestExporterDryRunFollowsSelectedDirectoryLink(t *testing.T) {
	dir := t.TempDir()
	d, err := sql.Open("sqlite", filepath.Join(dir, maildirCacheName))
	require.NoError(t, err)
	_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT);INSERT INTO messages VALUES('hash','INBOX','message.eml')`)
	require.NoError(t, err)
	require.NoError(t, d.Close())
	link := filepath.Join(t.TempDir(), "selected")
	require.NoError(t, os.Symlink(dir, link))
	before := exportCacheSourceState(t, dir)
	e, err := NewExporter(context.Background(), link, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	require.NoError(t, err)
	defer e.Close()
	ok, filename, err := e.isMessageExported("hash", "INBOX")
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "message.eml", filename)
	require.NoError(t, e.Close())
	require.NoError(t, e.Close(), "Close remains idempotent")
	require.Equal(t, before, exportCacheSourceState(t, dir))
}

// This uses only the public exporter API so the same assertion can run against
// the authored source-opening helper, without relying on the new private API.
func TestExporterDryRunKeepsCrashWALSource(t *testing.T) {
	dir := crashExportSnapshotSource(t, "wal")
	before := exportCacheSourceState(t, dir)
	e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	require.NoError(t, err)
	var n int
	require.NoError(t, e.db.QueryRow(`SELECT count(*) FROM messages WHERE hash='committed'`).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, e.Close())
	require.Equal(t, before, exportCacheSourceState(t, dir), "dry run changed crash-WAL source bytes or sidecars")
}

func TestExporterDryRunFailureDoesNotLeakDescriptors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, maildirCacheName), []byte("invalid sqlite"), 0600))
	attempt := func() {
		e, err := NewExporter(context.Background(), dir, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.Error(t, err)
		require.Nil(t, e)
	}
	attempt() // Warm up Go's process/poller and SQLite initialization before counting.
	before := countExportSnapshotFDs()
	for n := 0; n < 6; n++ {
		attempt()
	}
	require.Equal(t, before, countExportSnapshotFDs(), "failed private reads must close connections, pipes and directory descriptors")
}

func TestExporterDryRunSnapshotTempDirPathShapes(t *testing.T) {
	newSource := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "maildir")
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "cur"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", "seed.eml"), []byte("body"), 0600))
		d, err := sql.Open("sqlite", filepath.Join(dir, maildirCacheName))
		require.NoError(t, err)
		_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT); INSERT INTO messages VALUES('seed','INBOX','seed.eml')`)
		require.NoError(t, err)
		require.NoError(t, d.Close())
		return dir
	}

	t.Run("relative dot TMPDIR", func(t *testing.T) {
		source := newSource(t)
		work := t.TempDir()
		t.Chdir(work)
		t.Setenv("TMPDIR", ".")

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.NoError(t, err)
		exists, name, err := e.isMessageExported("seed", "INBOX")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, "seed.eml", name)
		require.NoError(t, e.Close())
		assert.Empty(t, dirNames(t, work))
	})

	t.Run("relative subdirectory TMPDIR", func(t *testing.T) {
		source := newSource(t)
		work := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(work, "tmp"), 0700))
		t.Chdir(work)
		t.Setenv("TMPDIR", "tmp")

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.NoError(t, err)
		exists, name, err := e.isMessageExported("seed", "INBOX")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, "seed.eml", name)
		require.NoError(t, e.Close())
		assert.Empty(t, dirNames(t, filepath.Join(work, "tmp")))
	})

	t.Run("relative localhost TMPDIR", func(t *testing.T) {
		source := newSource(t)
		work := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(work, "localhost"), 0700))
		t.Chdir(work)
		t.Setenv("TMPDIR", "localhost")

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.NoError(t, err)
		exists, name, err := e.isMessageExported("seed", "INBOX")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, "seed.eml", name)
		require.NoError(t, e.Close())
		assert.Empty(t, dirNames(t, filepath.Join(work, "localhost")))
	})

	t.Run("URI special characters and symlinked TMPDIR", func(t *testing.T) {
		source := newSource(t)
		root := t.TempDir()
		realTmp := filepath.Join(root, "tmp?a#b%25c")
		require.NoError(t, os.Mkdir(realTmp, 0700))
		linkTmp := filepath.Join(root, "tmp-link")
		require.NoError(t, os.Symlink(realTmp, linkTmp))
		t.Setenv("TMPDIR", linkTmp)

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.NoError(t, err)
		exists, name, err := e.isMessageExported("seed", "INBOX")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, "seed.eml", name)
		require.NoError(t, e.Close())
		assert.Empty(t, dirNames(t, realTmp))
	})
}

func TestExporterDryRunRefusesUnsafeTempDir(t *testing.T) {
	cases := []struct {
		name                string
		tmpMode, parentMode os.FileMode
		otherOwner          bool
		protected           bool
		refused             bool
	}{
		{"others can write in TMPDIR (unprotected)", 0777, 0700, false, false, true},
		{"others can write in TMPDIR (protected)", 0777, 0700, false, true, true},
		{"group can write in TMPDIR", 0770, 0700, false, true, true},
		{"others can write above TMPDIR", 0700, 0777, false, true, true},
		{"TMPDIR belongs to another user", 0700, 0700, true, true, true},
		{"others can write in TMPDIR with sticky bit", 0777 | os.ModeSticky, 0700, false, false, false},
		{"others can write in TMPDIR with sticky bit and protected hard links", 0777 | os.ModeSticky, 0700, false, true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			realProtection := hardLinksProtected
			t.Cleanup(func() { hardLinksProtected = realProtection })
			hardLinksProtected = func() bool { return c.protected }

			source := t.TempDir()
			d, err := sql.Open("sqlite", filepath.Join(source, maildirCacheName))
			require.NoError(t, err)
			_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT); INSERT INTO messages VALUES('seed','INBOX','seed.eml')`)
			require.NoError(t, err)
			require.NoError(t, d.Close())

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

			e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			if e != nil {
				require.NoError(t, e.Close())
			}
			if !c.refused {
				require.NoError(t, err)
				assert.Empty(t, dirNames(t, tmpDir))
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, "TMPDIR")
			assert.Empty(t, dirNames(t, tmpDir), "refused dry-run must not create or leave entries in unsafe TMPDIR")
		})
	}
}

func TestExporterDryRunConfinesPrivateTempDirAgainstSwapAndCleanup(t *testing.T) {
	newSource := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		d, err := sql.Open("sqlite", filepath.Join(dir, maildirCacheName))
		require.NoError(t, err)
		_, err = d.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT); INSERT INTO messages VALUES('seed','INBOX','seed.eml')`)
		require.NoError(t, err)
		require.NoError(t, d.Close())
		return dir
	}

	t.Run("symlink swap at creation in sticky TMPDIR", func(t *testing.T) {
		source := newSource(t)
		tmpDir := sharedTempDir(t)
		precious := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(precious, "keep"), []byte("precious"), 0600))

		realMkdirTemp := mkdirTemp
		t.Cleanup(func() { mkdirTemp = realMkdirTemp })
		mkdirTemp = func(dir, pattern string) (string, error) {
			name, err := realMkdirTemp(dir, pattern)
			if err == nil {
				require.NoError(t, os.Rename(name, name+".moved"))
				require.NoError(t, os.Symlink(precious, name))
			}
			return name, err
		}

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		if e != nil {
			_ = e.Close()
		}
		require.Error(t, err, "must refuse private preview directory replaced by a symlink")
		assert.Equal(t, []string{"keep"}, dirNames(t, precious), "must not write snapshot into or delete symlink target")
		_ = tmpDir
	})

	t.Run("directory replacement before Close preserves replacement contents", func(t *testing.T) {
		source := newSource(t)
		sharedTempDir(t)

		e, err := NewExporter(context.Background(), source, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
		require.NoError(t, err)
		private := e.privateCacheDir
		require.NotEmpty(t, private)

		replacement := filepath.Join(t.TempDir(), "replacement")
		require.NoError(t, os.Mkdir(replacement, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(replacement, "keep"), []byte("other user's file"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(replacement, maildirCacheName), []byte("other user's db"), 0600))

		moved := private + ".moved"
		require.NoError(t, os.Rename(private, moved))
		t.Cleanup(func() { _ = os.RemoveAll(moved); _ = os.RemoveAll(private) })
		require.NoError(t, os.Rename(replacement, private))

		require.NoError(t, e.Close())
		assert.ElementsMatch(t, []string{"keep", maildirCacheName}, dirNames(t, private),
			"Close must not remove files from a directory renamed onto privateCacheDir")
		assert.Empty(t, dirNames(t, moved), "Close must unlink its own snapshot files via the held directory descriptor")
	})
}

func TestOpenExportSnapshotSourceClearsNonblockAndRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, maildirCacheName), []byte("db-bytes"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, maildirCacheName+"-wal"), []byte("wal-bytes"), 0600))
	require.NoError(t, makeExportSnapshotFIFO(filepath.Join(dir, "fifo-db")))
	require.NoError(t, makeExportSnapshotFIFO(filepath.Join(dir, "fifo-wal")))

	rootFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(rootFD) })

	for _, tc := range []struct {
		name string
		flag int
	}{
		{maildirCacheName, unix.O_RDWR},
		{maildirCacheName + "-wal", unix.O_RDONLY},
	} {
		t.Run("regular_"+tc.name, func(t *testing.T) {
			f, err := openExportSnapshotSource(rootFD, tc.name, tc.flag)
			require.NoError(t, err)
			defer f.Close()

			conn, err := f.SyscallConn()
			require.NoError(t, err)
			var flags int
			var flErr error
			require.NoError(t, conn.Control(func(fd uintptr) {
				flags, flErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
			}))
			require.NoError(t, flErr)
			assert.Zero(t, flags&unix.O_NONBLOCK, "regular snapshot source %s must have O_NONBLOCK cleared before io.Copy", tc.name)
		})
	}

	for _, tc := range []struct {
		name string
		flag int
	}{
		{"fifo-db", unix.O_RDWR},
		{"fifo-wal", unix.O_RDONLY},
	} {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			f, err := openExportSnapshotSource(rootFD, tc.name, tc.flag)
			require.Error(t, err)
			assert.Nil(t, f)
		})
	}
}
