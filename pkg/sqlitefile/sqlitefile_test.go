package sqlitefile

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// A DSN from DSN opens exactly the named file, whatever characters its path holds, and
// applies the given parameters.
func TestDSNOpensTheNamedFile(t *testing.T) {
	for _, name := range []string{"plain.db", "a b.db", "a?b.db", "a#b.db", "a%3Fb.db", "a%b.db", "a?mode=ro&b.db"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			assertOpensFile(t, dir, filepath.Join(dir, name), name)
		})
	}

	t.Run("relative path", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		assertOpensFile(t, dir, "a?b.db", "a?b.db")
	})
}

// The OS resolves a ".." that follows a symlink from the symlink's target, and so does
// SQLite, so the DSN opens the file the OS opens for the path: not the one the path names
// once it is cleaned lexically, which a caller's os.OpenFile or os.Remove of the path
// never touches.
func TestDSNResolvesDotDotAfterSymlink(t *testing.T) {
	target := t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	if err := os.Symlink(filepath.Join(target, "sub"), filepath.Join(linkDir, "link")); err != nil {
		t.Fatal(err)
	}
	// Not filepath.Join, which would clean the ".." away.
	path := filepath.Join(linkDir, "link") + "/../a.db"

	dsn, err := DSN(path, "")
	if err != nil {
		t.Fatalf("DSN(%q) error: %v", path, err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open(%q) error: %v", dsn, err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatalf("CREATE TABLE through %q: %v", dsn, err)
	}

	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Errorf("DSN %q did not open %s, the file the OS opens for it (stat: %v)", dsn, path, err)
	}
	if entries, err := os.ReadDir(linkDir); err != nil || len(entries) != 1 {
		t.Errorf("DSN %q created files next to the symlink: %v (err %v)", dsn, entries, err)
	}
}

// assertOpensFile opens path through DSN and checks that dir then holds only name and
// that the connection runs with the requested busy timeout.
func assertOpensFile(t *testing.T, dir, path, name string) {
	t.Helper()
	dsn, err := DSN(path, "_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("DSN(%q) error: %v", path, err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open(%q) error: %v", dsn, err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatalf("CREATE TABLE through %q: %v", dsn, err)
	}
	var busyTimeout int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil || busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, %v; want 5000", busyTimeout, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("DSN %q created %q in %s, want only %q", dsn, names, dir, name)
	}
}

// Parse reads a file: URI by SQLite's rules (https://www.sqlite.org/uri.html, section 3)
// and any other name as a path, and reports the names that open no file.
func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, path, query string
	}{
		{"/var/cache/sora/auth.db", "/var/cache/sora/auth.db", ""},
		{"rel/a?b.db", "rel/a?b.db", ""}, // a path is the file name, '?' and all
		{"FILE:/x.db", "FILE:/x.db", ""}, // the scheme is "file:", lower case
		{"file:/var/cache/sora/auth.db", "/var/cache/sora/auth.db", ""},
		{"file:///var/cache/sora/auth.db", "/var/cache/sora/auth.db", ""},
		{"file://localhost/var/cache/sora/auth.db", "/var/cache/sora/auth.db", ""},
		{"file:rel/auth.db", "rel/auth.db", ""},
		{"file:/x.db?mode=rwc&cache=private", "/x.db", "mode=rwc&cache=private"},
		{"file:/x.db#frag?mode=memory", "/x.db", ""}, // the fragment ends the URI
		{"file:/a%3Fb%23c%25d.db", "/a?b#c%d.db", ""},
		{"file:/a%b%zz%4.db", "/a%b%zz%4.db", ""}, // not %HH: a literal '%'
		{"file:/a.db%00ignored?mode=rwc", "/a.db", "mode=rwc"},
		{"file:/x.db?mode=memory&mode=rwc", "/x.db", "mode=memory&mode=rwc"}, // the last mode wins
		{"file:/x.db?vfs=memdb&vfs=unix", "/x.db", "vfs=memdb&vfs=unix"},
		{"file:/x.db?mode=memor", "/x.db", "mode=memor"},

		// Names that open no file.
		{":memory:", "", ""},
		{"", "", ""},
		{"file:", "", ""},
		{"file://", "", ""},
		{"file://localhost", "", ""},
		{"file:?mode=rwc", "", ""},
		{"file::memory:", "", ""},
		{"file::memory:?cache=shared", "", ""},
		{"file:/x.db?mode=memory", "", ""},
		{"file:/x.db?mode=rwc&mode=memory", "", ""},
		{"file:/x.db?mode=memor%79", "", ""},
		{"file:/x.db?vfs=memdb", "", ""},
		{"file:/x.db?%76fs=memdb", "", ""},
	} {
		path, query, err := Parse(tc.name)
		if err != nil || path != tc.path || query != tc.query {
			t.Errorf("Parse(%q) = %q, %q, %v; want %q, %q, nil", tc.name, path, query, err, tc.path, tc.query)
		}
	}

	for _, name := range []string{"file://example.com/x.db", "file://localhost:80/x.db", "file://user@localhost/x.db"} {
		if path, _, err := Parse(name); err == nil {
			t.Errorf("Parse(%q) = %q, nil; want an invalid authority error", name, path)
		}
	}
}
