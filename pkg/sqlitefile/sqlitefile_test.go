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
		{"file:/x.db?vfs=unix&vfs=unix", "/x.db", "vfs=unix&vfs=unix"},
		{"file:/x.db?vfs=&vfs=unix", "/x.db", "vfs=&vfs=unix"},
		{"file:/x.db?_defensive=1", "/x.db", "_defensive=1"},
		{"file:/x.db?_defensive=0", "/x.db", "_defensive=0"},
		{"file:/x.db?_error_rc=1", "/x.db", "_error_rc=1"},
		{"file:/x.db?_error_rc=0", "/x.db", "_error_rc=0"},
		{"file:/x.db?_error_rc=", "/x.db", "_error_rc="},
		{"file:/x.db?_error_rc=1&_error_rc=bad", "/x.db", "_error_rc=1&_error_rc=bad"},
		{"file:/x.db?_error_rc=&_error_rc=bad", "/x.db", "_error_rc=&_error_rc=bad"},

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

	for _, name := range []string{
		"file://example.com/x.db",
		"file://localhost:80/x.db",
		"file://user@localhost/x.db",
		"file:/x.db?mode=memor",
		"file:/x.db?mode=",
		"file:/x.db?mode=ro&mode=rwc",
		"file:/x.db?vfs=memdb&vfs=unix",
		"file:/x.db?_defensive=bad",
		"file:/x.db?_defensive=",
		"file:/x.db?_defensive=1&_defensive=1",
		"file:/x.db?_defensive=1&_defensive=0",
		"file:/x.db?%5Fdefensive=bad",
		"file:/x.db?_error_rc=bad",
		"file:/x.db?_error_rc=bad&_error_rc=1",
		"file:/x.db?%5Ferror_rc=bad",
	} {
		if path, _, err := Parse(name); err == nil {
			t.Errorf("Parse(%q) = %q, nil; want an invalid authority, mode or driver parameter error", name, path)
		}
	}
}

// modernc.org/sqlite validates _defensive and _error_rc before sqlite3_open_v2.
// Parse, CanCreate and Prepare must mirror that validation so rejected DSNs do
// not create a missing database file or chmod an existing file before SQLite
// opens it, while valid forms continue to pass both sqlitefile and the driver.
func TestPrepareMatchesDriverPreOpenValidation(t *testing.T) {
	for _, query := range []string{
		"_defensive=bad",
		"_defensive=",
		"_defensive=on",
		"_defensive=1&_defensive=1",
		"_defensive=1&_defensive=0",
		"%5Fdefensive=bad",
		"_error_rc=bad",
		"_error_rc=on",
		"_error_rc=bad&_error_rc=1",
		"%5Ferror_rc=bad",
	} {
		t.Run("reject/"+query, func(t *testing.T) {
			driverPath := filepath.Join(t.TempDir(), "driver.db")
			dsn, err := DSN(driverPath, query)
			if err != nil {
				t.Fatalf("DSN(%q, %q) error: %v", driverPath, query, err)
			}
			db, err := sql.Open("sqlite", dsn)
			if err != nil {
				t.Fatalf("sql.Open(%q) error: %v", dsn, err)
			}
			defer db.Close()
			if err := db.Ping(); err == nil {
				t.Fatalf("driver unexpectedly accepted %q", dsn)
			}
			if _, statErr := os.Stat(driverPath); !os.IsNotExist(statErr) {
				t.Fatalf("driver touched %s before rejecting %q: %v", driverPath, dsn, statErr)
			}

			missingPath := filepath.Join(t.TempDir(), "missing.db")
			if _, _, err := Parse("file:" + missingPath + "?" + query); err == nil {
				t.Errorf("Parse accepted rejected driver query %q", query)
			}
			if _, err := CanCreate(query); err == nil {
				t.Errorf("CanCreate accepted rejected driver query %q", query)
			}
			if err := Prepare(missingPath, query); err == nil {
				t.Errorf("Prepare accepted rejected driver query %q", query)
			}
			if _, statErr := os.Stat(missingPath); !os.IsNotExist(statErr) {
				t.Errorf("Prepare(%q) created %s before driver rejection (stat: %v)", query, missingPath, statErr)
			}

			existingPath := filepath.Join(t.TempDir(), "existing.db")
			for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
				p := existingPath + suffix
				if err := os.WriteFile(p, []byte("keep mode"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := Prepare(existingPath, query); err == nil {
				t.Errorf("Prepare on existing file accepted rejected driver query %q", query)
			}
			for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
				info, err := os.Stat(existingPath + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != 0644 {
					t.Errorf("Prepare(%q) mutated %s mode to %04o, want 0644", query, existingPath+suffix, got)
				}
			}
		})
	}

	for _, query := range []string{
		"_defensive=1",
		"_defensive=0",
		"_defensive=true",
		"_defensive=false",
		"_error_rc=1",
		"_error_rc=0",
		"_error_rc=true",
		"_error_rc=false",
		"_error_rc=",
		"_error_rc=1&_error_rc=bad",
		"_error_rc=&_error_rc=bad",
	} {
		t.Run("accept/"+query, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "valid.db")
			gotPath, gotQuery, err := Parse("file:" + dbPath + "?" + query)
			if err != nil || gotPath != dbPath || gotQuery != query {
				t.Fatalf("Parse(%q) = %q, %q, %v; want %q, %q, nil", query, gotPath, gotQuery, err, dbPath, query)
			}
			canCreate, err := CanCreate(query)
			if err != nil || !canCreate {
				t.Fatalf("CanCreate(%q) = %v, %v; want true, nil", query, canCreate, err)
			}
			if err := Prepare(dbPath, query); err != nil {
				t.Fatalf("Prepare(%q) error: %v", query, err)
			}
			info, err := os.Stat(dbPath)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("prepared file stat = %v, %v; want mode 0600", info, err)
			}
			dsn, err := DSN(dbPath, query)
			if err != nil {
				t.Fatalf("DSN(%q) error: %v", query, err)
			}
			db, err := sql.Open("sqlite", dsn)
			if err != nil {
				t.Fatalf("sql.Open(%q) error: %v", dsn, err)
			}
			defer db.Close()
			if err := db.Ping(); err != nil {
				t.Fatalf("driver rejected valid query %q: %v", query, err)
			}
		})
	}
}
