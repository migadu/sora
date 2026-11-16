package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/sqlitefile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Import and export open sora-maildir.db in a directory the maildir's owner may be
// able to write to (the maildir of an in-place import, or a copy made with rsync -a,
// which keeps links; the destination of an export), and they often run as root. A
// link the owner leaves at the cache's name, or at the -wal, -shm or -journal name
// SQLite keeps beside it, must not make them create or write a file outside that
// directory: the open is refused, naming the link (#1606).
func TestMaildirCacheRefusesLinks(t *testing.T) {
	openers := []struct {
		name string
		open func(t *testing.T, dir string) error
	}{
		{"import", func(t *testing.T, dir string) error {
			importer, err := NewImporter(context.Background(), dir, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			if err == nil {
				t.Cleanup(func() { importer.Close() })
			}
			return err
		}},
		{"export", func(t *testing.T, dir string) error {
			exporter, err := NewExporter(context.Background(), dir, "user@example.com", 1, nil, nil, ExporterOptions{})
			if err == nil {
				t.Cleanup(func() { exporter.Close() })
			}
			return err
		}},
	}
	names := []string{"sora-maildir.db", "sora-maildir.db-wal", "sora-maildir.db-shm", "sora-maildir.db-journal"}

	for _, o := range openers {
		for _, name := range names {
			for _, existing := range []bool{false, true} {
				target := "missing target"
				if existing {
					target = "empty file"
				}
				t.Run(o.name+"/"+name+"/"+target, func(t *testing.T) {
					dir := newMaildirWith(t, nil)
					outDir := t.TempDir()
					outside := filepath.Join(outDir, "outside")
					if existing {
						require.NoError(t, os.WriteFile(outside, nil, 0644))
					}
					link := filepath.Join(dir, name)
					require.NoError(t, os.Symlink(outside, link))
					// The refusal names the file in the directory the cache is opened in.
					realDir, err := filepath.EvalSymlinks(dir)
					require.NoError(t, err)

					err = o.open(t, dir)

					assert.ErrorContains(t, err, filepath.Join(realDir, name)+": it is a symbolic link", "the link was not refused by name")
					want := []string{}
					if existing {
						want = []string{"outside"}
					}
					assert.Equal(t, want, dirNames(t, outDir), "created a file outside the maildir through the link")
					if existing {
						info, err := os.Stat(outside)
						require.NoError(t, err)
						assert.Zero(t, info.Size(), "wrote the file the link names")
					}
				})
			}
		}
	}
}

// The check before the open leaves a window in which the owner can put a link at the
// cache's name. Every connection is therefore checked again, before SQLite reads or
// writes anything, to have opened the file under its own name and not through a link;
// SQLite opens the cache without creating it, so a link to a missing file creates
// nothing either.
func TestMaildirCacheRefusesALinkSwappedInBeforeSQLiteOpensIt(t *testing.T) {
	targets := map[string][]byte{
		"empty file":          {},
		"file not a database": []byte("not a database\n"),
		"missing target":      nil,
	}
	for name, content := range targets {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			outDir := t.TempDir()
			outside := filepath.Join(outDir, "outside")
			want := []string{}
			if content != nil {
				require.NoError(t, os.WriteFile(outside, content, 0644))
				want = []string{"outside"}
			}
			path := filepath.Join(dir, maildirCacheName)
			require.NoError(t, os.Symlink(outside, path))

			cache, err := openMaildirCacheFile(path)
			require.NoError(t, err)
			defer cache.Close()
			err = cache.Ping()

			require.Error(t, err)
			if content != nil {
				assert.ErrorContains(t, err, "through a symbolic link")
				got, err := os.ReadFile(outside)
				require.NoError(t, err)
				assert.Equal(t, content, got, "wrote the file the link names")
			}
			assert.Equal(t, want, dirNames(t, outDir), "created a file outside the maildir through the link")
		})
	}
}

// The maildir path is the operator's, and may itself be or go through a link; the
// cache is opened in the directory it names, as the OS resolves it (a ".." after a
// link is taken from the link's target).
func TestMaildirCacheOpensThroughALinkedMaildirPath(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(filepath.Join(real, "Maildir"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "Maildir"), 0755))
	require.NoError(t, os.Symlink(real, filepath.Join(root, "link")))
	t.Chdir(root)

	for _, maildirPath := range []string{
		filepath.Join(root, "link", "Maildir"),
		filepath.Join("link", "Maildir"),
		"link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "Maildir",
	} {
		t.Run(maildirPath, func(t *testing.T) {
			cache, err := openMaildirCache(maildirPath)
			require.NoError(t, err)
			assertMaildirCacheSettings(t, cache)
			require.NoError(t, cache.Close())
		})
	}
	assert.FileExists(t, filepath.Join(real, "Maildir", maildirCacheName))
	assert.FileExists(t, filepath.Join(root, "a", "Maildir", maildirCacheName), `"link/../Maildir" is a/Maildir, not ./Maildir`)
	assert.NoFileExists(t, filepath.Join(root, "Maildir", maildirCacheName))
}

// A cache another process holds locked when an import or export opens it is waited
// for up to the busy timeout, not refused: the journal mode is set on every new
// connection and needs the lock, so the timeout must already be in force then.
func TestMaildirCacheWaitsForALockedCache(t *testing.T) {
	openers := []struct {
		name string
		open func(t *testing.T, dir string) error
	}{
		{"import", func(t *testing.T, dir string) error {
			importer, err := NewImporter(context.Background(), dir, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			if err == nil {
				t.Cleanup(func() { importer.Close() })
			}
			return err
		}},
		{"export", func(t *testing.T, dir string) error {
			exporter, err := NewExporter(context.Background(), dir, "user@example.com", 1, nil, nil, ExporterOptions{})
			if err == nil {
				t.Cleanup(func() { exporter.Close() })
			}
			return err
		}},
	}
	for _, o := range openers {
		t.Run(o.name, func(t *testing.T) {
			dir := newMaildirWith(t, nil)
			dsn, err := sqlitefile.DSN(filepath.Join(dir, maildirCacheName), "")
			require.NoError(t, err)
			other, err := sql.Open("sqlite", dsn)
			require.NoError(t, err)
			defer other.Close()
			ctx := context.Background()
			conn, err := other.Conn(ctx)
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.ExecContext(ctx, `CREATE TABLE held (n INTEGER)`)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx, `BEGIN EXCLUSIVE`)
			require.NoError(t, err)

			released := make(chan error, 1)
			go func() {
				time.Sleep(200 * time.Millisecond)
				_, err := conn.ExecContext(ctx, `COMMIT`)
				released <- err
			}()
			err = o.open(t, dir)
			require.NoError(t, <-released)
			require.NoError(t, err, "did not wait for the lock")
		})
	}
}

// The files beside the cache are checked in the directory the cache is opened in:
// the maildir path as the OS resolves it, where "link/../Maildir" is a/Maildir when
// link names a/b, not ./Maildir as a lexical join would take it.
func TestMaildirCacheChecksTheDirectoryItIsOpenedIn(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, d := range []string{filepath.Join("a", "b"), filepath.Join("a", "Maildir"), "Maildir"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0755))
	}
	require.NoError(t, os.Symlink(filepath.Join(root, "a", "b"), filepath.Join(root, "link")))
	outside := filepath.Join(root, "outside")
	t.Chdir(root)
	maildirPath := "link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "Maildir"

	// A link beside ./Maildir is not beside the cache.
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "Maildir", maildirCacheName+"-wal")))
	cache, err := openMaildirCache(maildirPath)
	require.NoError(t, err, "refused a link in a directory the cache is not in")
	require.NoError(t, cache.Close())
	require.FileExists(t, filepath.Join(root, "a", "Maildir", maildirCacheName))

	// A link beside the cache, in a/Maildir, is refused by its name.
	link := filepath.Join(root, "a", "Maildir", maildirCacheName+"-shm")
	require.NoError(t, os.Symlink(outside, link))
	_, err = openMaildirCache(maildirPath)
	assert.ErrorContains(t, err, link+": it is a symbolic link")
	assert.NoFileExists(t, outside)
}
