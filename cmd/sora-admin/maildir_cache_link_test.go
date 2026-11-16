package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
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
// cache's name. Every connection is therefore checked again, after SQLite may have
// read the header but before cache settings are applied, to have opened the file
// under its own name and not through a link;
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

type dotDotRecordingDB struct {
	*mockResilientDatabase
	inserted   []*db.InsertMessageOptions
	subscribed []string
}

func (r *dotDotRecordingDB) InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error) {
	r.inserted = append(r.inserted, opts)
	return r.mockResilientDatabase.InsertMessageFromImporterWithRetry(ctx, opts)
}

func (r *dotDotRecordingDB) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	r.inserted = append(r.inserted, opts...)
	return r.mockResilientDatabase.InsertMessagesFromImporterBatchWithRetry(ctx, opts)
}

func (r *dotDotRecordingDB) SubscribeWithRetry(ctx context.Context, accountID int64, mailboxName string) error {
	r.subscribed = append(r.subscribed, mailboxName)
	return nil
}

// Import and export must open the maildir root, scan/read/write messages and Dovecot
// metadata, and remove the cache on --cleanup-db in the same OS-resolved directory
// openMaildirCache opens when --maildir-path crosses a symbolic link followed by "..".
// Lexical filepath.Clean / filepath.Join collapses "link/.." to "." and either fails
// with ENOENT when sibling ./Maildir is absent or operates on ./Maildir while keeping
// sora-maildir.db in a/Maildir.
func TestMaildirCacheImportAndExportResolveDotDotAfterLink(t *testing.T) {
	setupLayout := func(t *testing.T) (root, target, relPath, absPath string) {
		t.Helper()
		var err error
		root, err = filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0755))
		require.NoError(t, os.Symlink(filepath.Join(root, "a", "b"), filepath.Join(root, "link")))
		target = filepath.Join(root, "a", "Maildir")
		sep := string(filepath.Separator)
		relPath = "link" + sep + ".." + sep + "Maildir"
		absPath = root + sep + relPath
		return root, target, relPath, absPath
	}

	populateMaildir := func(t *testing.T, dir, msgName, subject, keyword, subscribed string) {
		t.Helper()
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0755))
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", msgName), cachedSizeMessage(subject, 100), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "dovecot-keywords"), []byte("0 "+keyword+"\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "subscriptions"), []byte(subscribed+"\n"), 0644))
	}

	for _, useAbs := range []bool{false, true} {
		spelling := "relative"
		if useAbs {
			spelling = "absolute"
		}

		t.Run("import without sibling Maildir/"+spelling, func(t *testing.T) {
			root, target, relPath, absPath := setupLayout(t)
			populateMaildir(t, target, "1700000001.M1P1.host:2,Sa", "Target", "$Target", "Sent")
			maildirPath := absPath
			if !useAbs {
				t.Chdir(root)
				maildirPath = relPath
			}

			importer, err := NewImporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{
				TestMode:      true,
				CleanupDB:     true,
				PreserveFlags: true,
				Dovecot:       true,
			})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			rdb := &dotDotRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer.rdb = rdb

			require.NoError(t, importer.Run())

			require.Len(t, rdb.inserted, 1)
			assert.Equal(t, "Target", rdb.inserted[0].Subject)
			assert.Contains(t, rdb.inserted[0].Flags, imap.Flag("$Target"))
			assert.Equal(t, []string{"Sent"}, rdb.subscribed)
			assert.NoFileExists(t, filepath.Join(target, maildirCacheName))
			assert.NoDirExists(t, filepath.Join(root, "Maildir"))
		})

		t.Run("export without sibling Maildir/"+spelling, func(t *testing.T) {
			root, target, relPath, absPath := setupLayout(t)
			maildirPath := absPath
			if !useAbs {
				t.Chdir(root)
				maildirPath = relPath
			}

			exporter, err := NewExporter(context.Background(), maildirPath, "user@example.com", 1, nil, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })

			msg := linkTestMessage()
			filename := exporter.generateMaildirFilename(&msg, "INBOX")
			require.NoError(t, exporter.createMailboxDirectory("INBOX"))
			require.NoError(t, exporter.exportMessage(&msg, "INBOX"))
			var recordedPath string
			require.NoError(t, exporter.db.QueryRow(`SELECT path FROM messages`).Scan(&recordedPath))
			require.NoError(t, exporter.Close())

			wantFile := filepath.Join(target, "cur", filename)
			assert.FileExists(t, wantFile)
			assert.Equal(t, wantFile, recordedPath)
			assert.FileExists(t, filepath.Join(target, maildirCacheName))
			assert.NoDirExists(t, filepath.Join(root, "Maildir"))
		})
	}

	t.Run("import with sibling Maildir", func(t *testing.T) {
		root, target, relPath, _ := setupLayout(t)
		populateMaildir(t, target, "1700000001.M1P1.host:2,Sa", "Target", "$Target", "Sent")
		decoy := filepath.Join(root, "Maildir")
		populateMaildir(t, decoy, "1700000999.M9P1.host:2,Sa", "Decoy", "$Decoy", "Junk")
		decoyDB := filepath.Join(decoy, maildirCacheName)
		decoyBytes := []byte("decoy cache\n")
		require.NoError(t, os.WriteFile(decoyDB, decoyBytes, 0644))
		t.Chdir(root)

		importer, err := NewImporter(context.Background(), relPath, "user@example.com", 1, nil, nil, ImporterOptions{
			TestMode:      true,
			CleanupDB:     true,
			PreserveFlags: true,
			Dovecot:       true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		rdb := &dotDotRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer.rdb = rdb

		require.NoError(t, importer.Run())

		if assert.Len(t, rdb.inserted, 1) {
			assert.Equal(t, "Target", rdb.inserted[0].Subject, "imported from sibling ./Maildir instead of a/Maildir")
			assert.Contains(t, rdb.inserted[0].Flags, imap.Flag("$Target"))
		}
		assert.Equal(t, []string{"Sent"}, rdb.subscribed, "read subscriptions from sibling ./Maildir")
		assert.NoFileExists(t, filepath.Join(target, maildirCacheName), "--cleanup-db left a/Maildir/sora-maildir.db behind")
		assertUnchanged(t, decoyDB, decoyBytes)
	})

	t.Run("export with sibling Maildir", func(t *testing.T) {
		root, target, relPath, _ := setupLayout(t)
		decoy := filepath.Join(root, "Maildir")
		require.NoError(t, os.MkdirAll(decoy, 0755))
		t.Chdir(root)

		exporter, err := NewExporter(context.Background(), relPath, "user@example.com", 1, nil, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{
			Dovecot:       true,
			ExportUIDList: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { exporter.Close() })

		msg := linkTestMessage()
		msg.CustomFlags = []string{"$Work"}
		require.NoError(t, exporter.createMailboxDirectory("INBOX"))
		require.NoError(t, exporter.prepareKeywords("INBOX", []db.Message{msg}))
		filename := exporter.generateMaildirFilename(&msg, "INBOX")
		require.NoError(t, exporter.exportMessage(&msg, "INBOX"))
		require.NoError(t, exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}}))
		require.NoError(t, exporter.Close())

		assertEmptyDir(t, decoy)
		assert.FileExists(t, filepath.Join(target, "cur", filename))
		assert.FileExists(t, filepath.Join(target, "dovecot-keywords"))
		assert.FileExists(t, filepath.Join(target, "dovecot-uidlist"))
		assert.FileExists(t, filepath.Join(target, maildirCacheName))
	})
}
