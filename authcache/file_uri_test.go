package authcache

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
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
