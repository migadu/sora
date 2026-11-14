package affinitycache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The affinity cache is the configured file for every path. A plain SQLite DSN is cut at
// its first '?' (the rest is read as DSN parameters), so a '?' in the path used to put the
// cache at the path truncated there while the configured file stayed an empty placeholder.
// '#' and '%' are special in a file: URI and must reach SQLite as part of the name too.
func TestStoreIsTheConfiguredFile(t *testing.T) {
	for _, dir := range []string{"a?b", "a#b", "a%3Fb", "a%b"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
				t.Fatal(err)
			}
			assertStoreIsFile(t, root, dir, filepath.Join(root, dir, "affinity.db"))
		})
	}

	t.Run("relative path", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		if err := os.Mkdir("a?b", 0700); err != nil {
			t.Fatal(err)
		}
		assertStoreIsFile(t, root, "a?b", filepath.Join("a?b", "affinity.db"))
	})

	// The OS resolves a ".." that follows a symlink from the symlink's target, both for
	// the 0600 file openAndValidate creates and for SQLite; the store must not be the
	// file a lexically cleaned path names instead.
	t.Run("symlink then ..", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "dir", "sub"), 0700); err != nil {
			t.Fatal(err)
		}
		linkDir := t.TempDir()
		if err := os.Symlink(filepath.Join(root, "dir", "sub"), filepath.Join(linkDir, "link")); err != nil {
			t.Fatal(err)
		}
		// Not filepath.Join, which would clean the ".." away.
		assertStoreIsFile(t, root, "dir", filepath.Join(linkDir, "link")+"/../affinity.db")
		if names := dirNames(t, linkDir); !reflect.DeepEqual(names, []string{"link"}) {
			t.Errorf("files next to the symlink: %q", names)
		}
	})
}

// assertStoreIsFile opens the store at dbPath, which is <root>/<dir>/affinity.db, and
// checks that the store data lives in that file and that nothing is created outside dir.
func assertStoreIsFile(t *testing.T, root, dir, dbPath string) {
	t.Helper()
	ctx := context.Background()

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	now := time.Now()
	entry := AffinityEntry{Username: "alice@example.com", Protocol: "imap", Backend: "backend1:143",
		AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"}
	if err := store.Set(ctx, entry); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if names := dirNames(t, root); !reflect.DeepEqual(names, []string{dir}) {
		t.Errorf("files outside %s: %q", dir, names)
	}
	header := make([]byte, 16)
	f, err := os.Open(filepath.Join(root, dir, "affinity.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Read(header)
	f.Close()
	if err != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		t.Errorf("the configured file is not the store database (header %q, err %v)", header, err)
	}

	store, err = New(dbPath)
	if err != nil {
		t.Fatalf("New() on reopen error: %v", err)
	}
	defer store.Close()
	if entries, err := store.LoadAll(ctx); err != nil || len(entries) != 1 {
		t.Errorf("LoadAll() after reopen = %d entries, %v; want 1", len(entries), err)
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
