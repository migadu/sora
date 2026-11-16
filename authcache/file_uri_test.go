package authcache

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/sqlitefile"
)

// A file: URI names the cache by the URI's path. New created the database file 0600, and
// chmodded an existing one to 0600, only for a plain path; given a URI, SQLite created the
// database, and its -wal and -shm files after it, with its default mode, so the password
// hashes were readable by every local user (#1397). Every spelling of the URI must give
// the configured file, 0600.
func TestFileURIIsTheConfiguredFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  string
		uri  func(file string) string
	}{
		{"file:path", "d", func(f string) string { return "file:" + f }},
		{"empty authority", "d", func(f string) string { return "file://" + f }},
		{"localhost authority", "d", func(f string) string { return "file://localhost" + f }},
		{"query", "d", func(f string) string { return "file:" + f + "?mode=rwc" }},
		{"fragment", "d", func(f string) string { return "file:" + f + "#fragment" }},
		{"escaped", "a?b", func(f string) string { return (&url.URL{Scheme: "file", Path: f}).String() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, tc.dir), 0700); err != nil {
				t.Fatal(err)
			}
			assertCacheIsFile(t, root, tc.dir, tc.uri(filepath.Join(root, tc.dir, "auth_cache.db")))
		})
	}

	t.Run("relative", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		if err := os.Mkdir("d", 0700); err != nil {
			t.Fatal(err)
		}
		assertCacheIsFile(t, root, "d", "file:d/auth_cache.db")
	})

	t.Run("existing world-readable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "auth_cache.db")
		c, err := New(path, time.Hour, 24*time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		c, err = New("file:"+path, time.Hour, 24*time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer c.Close()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Errorf("%s has mode %o after New(file URI), want 600", path, mode)
		}
	})
}

// Corruption recovery removes the database the URI names. It removed files named after
// the URI's spelling, which do not exist, so the corrupt database stayed and New failed.
func TestCorruptDatabaseAtFileURIIsRecreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_cache.db")
	if err := os.WriteFile(path, []byte("this is not a valid sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}

	c, err := New("file:"+path, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() of a corrupt database should recreate it, got error: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.Put(ctx, "user@example.com", 42, "$2a$10$hash"); err != nil {
		t.Fatalf("Put() after recreation error: %v", err)
	}
	header := make([]byte, 16)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Read(header)
	f.Close()
	if err != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		t.Errorf("%s is not the recreated database (header %q, err %v)", path, header, err)
	}
}

// SQLite creates the -wal and -shm files with the database file's mode, but reuses the
// ones left behind by a process that exited with the database open, with the mode they
// have. A cache that ran before its files were 0600 (a file: URI, #1397) leaves 0644
// ones, which then keep receiving the password hashes, readable by every local user. New makes
// them 0600 as it does the database file.
func TestExistingWorldReadableWALIsMadePrivate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spell func(path string) string
	}{
		{"path", func(p string) string { return p }},
		{"file URI", func(p string) string { return "file:" + p }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth_cache.db")
			leaveWorldReadableWAL(t, path)
			c, err := New(tc.spell(path), time.Hour, 24*time.Hour, time.Hour)
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}
			defer c.Close()
			var committed int
			if err := c.db.QueryRow("SELECT x FROM t").Scan(&committed); err != nil || committed != 1 {
				t.Fatalf("committed WAL contents were lost: x=%d, err=%v", committed, err)
			}
			if err := c.Put(context.Background(), "user@example.com", 42, "$2a$10$hash"); err != nil {
				t.Fatalf("Put() error: %v", err)
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				info, err := os.Stat(path + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if mode := info.Mode().Perm(); mode != 0600 {
					t.Errorf("%s has mode %o, want 600", path+suffix, mode)
				}
			}
		})
	}
}

// leaveWorldReadableWAL leaves at path a WAL-mode database whose 0644 -wal and -shm files
// hold a committed transaction, as a process killed with the database open leaves them:
// it copies the files of a database that is still open.
func leaveWorldReadableWAL(t *testing.T, path string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src.db")
	dsn, err := sqlitefile.DSN(src, "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; CREATE TABLE t (x); INSERT INTO t VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(src + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+suffix, data, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+suffix, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
