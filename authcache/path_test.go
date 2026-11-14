package authcache

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The auth cache is the configured file for every path. A plain SQLite DSN is cut at its
// first '?' (the rest is read as DSN parameters), so a '?' in the path used to put the
// cache, password hashes included, at the path truncated there, created with SQLite's
// default permissions, while the configured file stayed an empty 0600 placeholder.
// '#' and '%' are special in a file: URI and must reach SQLite as part of the name too.
func TestCacheIsTheConfiguredFile(t *testing.T) {
	for _, dir := range []string{"a?b", "a#b", "a%3Fb", "a%b"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
				t.Fatal(err)
			}
			assertCacheIsFile(t, root, dir, filepath.Join(root, dir, "auth_cache.db"))
		})
	}

	t.Run("relative path", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		if err := os.Mkdir("a?b", 0700); err != nil {
			t.Fatal(err)
		}
		assertCacheIsFile(t, root, "a?b", filepath.Join("a?b", "auth_cache.db"))
	})
}

// assertCacheIsFile opens the cache at dbPath, which is <root>/<dir>/auth_cache.db, and
// checks that the cache data lives in that file, that every file SQLite keeps for it is
// 0600, and that nothing is created outside dir.
func assertCacheIsFile(t *testing.T, root, dir, dbPath string) {
	t.Helper()
	ctx := context.Background()

	c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := c.Put(ctx, "user@example.com", 42, "$2a$10$hash"); err != nil {
		t.Fatalf("Put() error: %v", err)
	}
	err = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Errorf("%s has mode %o, want 600", path, mode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if names := dirNames(t, root); !reflect.DeepEqual(names, []string{dir}) {
		t.Errorf("files outside %s: %q", dir, names)
	}
	header := make([]byte, 16)
	f, err := os.Open(filepath.Join(root, dir, "auth_cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Read(header)
	f.Close()
	if err != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		t.Errorf("the configured file is not the cache database (header %q, err %v)", header, err)
	}

	c, err = New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() on reopen error: %v", err)
	}
	defer c.Close()
	if accountID, _, err := c.Get(ctx, "user@example.com"); err != nil || accountID != 42 {
		t.Errorf("Get() after reopen = %d, %v; want 42", accountID, err)
	}
}

// dirNames lists the names in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
