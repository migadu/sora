package authcache

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openCacheForURIModeTest(t *testing.T, path string) (*Cache, error) {
	t.Helper()
	return New(path, time.Hour, 24*time.Hour, time.Hour)
}
func TestURIModesDoNotCreateMissingFile(t *testing.T) {
	for _, mode := range []string{"rw", "ro", "rwc&mode=rw", "rwc&mode=ro"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.db")
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Error("New accepted missing file with no-create URI mode")
			}
			if _, e := os.Stat(path); !os.IsNotExist(e) {
				t.Errorf("no-create URI left a database file (stat %v)", e)
			}
		})
	}
}
func TestFileURIEnforcesExistingSidecarPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := openCacheForURIModeTest(t, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.db.Exec("CREATE TABLE review_live_wal (x)"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0644); err != nil {
			t.Fatal(err)
		}
	}
	d, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		i, e := os.Stat(path + suffix)
		if e != nil {
			t.Fatal(e)
		}
		if i.Mode().Perm() != 0600 {
			t.Errorf("%s mode %o, want0600", suffix, i.Mode().Perm())
		}
	}
}

func TestURIModesPreserveCorruptExistingFile(t *testing.T) {
	for _, mode := range []string{"rw", "ro", "rwc&mode=rw", "%6dode=%72o"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "corrupt.db")
			want := []byte("not a sqlite database; preserve me")
			if err := os.WriteFile(path, want, 0600); err != nil {
				t.Fatal(err)
			}
			query := "mode=" + mode
			if mode == "%6dode=%72o" {
				query = mode
			}
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("corrupt no-create file accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(want) {
				t.Fatalf("corrupt no-create file changed: %q, %v", got, err)
			}
		})
	}
}
func TestInvalidURIModeDoesNotTouchFile(t *testing.T) {
	for _, mode := range []string{"bad", "", "rwc&mode=", "ro&mode=rwc", "rw&mode=rwc"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.db")
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("invalid URI mode accepted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid mode touched file: %v", err)
			}
		})
	}
}
func TestURIExistingFileRetainsOptions(t *testing.T) {
	for _, mode := range []string{"rw", "ro", "rwc", "rwc&mode=rw", "%6dode=%72w"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing.db")
			c, err := openCacheForURIModeTest(t, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			query := "mode=" + mode
			if mode == "%6dode=%72w" {
				query = mode
			}
			d, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()+"&_pragma=cache_size(-17)")
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			for pragma, want := range map[string]int{"busy_timeout": 5000, "synchronous": 1, "cache_size": -17} {
				var got int
				if err := d.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil || got != want {
					t.Errorf("%s=%d,%v want%d", pragma, got, err, want)
				}
			}
		})
	}
}

func TestURIOptionsThatAllowFileCreation(t *testing.T) {
	for _, query := range []string{"mode=rwc", "mode=memory&mode=rwc", "vfs=unix&vfs=unix", "vfs=&vfs=unix", "_defensive=1", "_defensive=0", "_error_rc=1", "_error_rc=0", "_error_rc="} {
		t.Run(query, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "created.db")
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var file string
			if err := c.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&file); err != nil || file == "" {
				t.Fatalf("not a physical file: %q,%v", file, err)
			}
			i, err := os.Stat(path)
			if err != nil || i.Mode().Perm() != 0600 {
				t.Fatalf("created file mode/stat: %v,%v", i, err)
			}
		})
	}
}

// The modernc driver rejects conflicting VFS values before SQLite opens the DB.
// Keep the original query so its driver-level option validation still runs.
func TestURIConflictingVFSIsRefused(t *testing.T) {
	for _, query := range []string{"vfs=memdb&vfs=unix", "vfs=unix&vfs=", "%76fs=memdb&vfs=unix"} {
		t.Run(query, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.db")
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("conflicting VFS values accepted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("rejected VFS options touched database file: %v", err)
			}
		})
	}
}

func TestURIInvalidPreOpenDriverOptionsDoNotTouchFile(t *testing.T) {
	for _, query := range []string{"_defensive=bad", "_defensive=", "_defensive=1&_defensive=1", "_error_rc=bad"} {
		t.Run(query, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing.db")
			c, err := openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: missing, RawQuery: query}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Error("invalid driver option accepted")
			}
			if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
				t.Errorf("rejected driver option %q created database file: %v", query, statErr)
			}

			existing := filepath.Join(t.TempDir(), "existing.db")
			if err := os.WriteFile(existing, []byte("existing"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(existing, 0644); err != nil {
				t.Fatal(err)
			}
			c, err = openCacheForURIModeTest(t, (&url.URL{Scheme: "file", Path: existing, RawQuery: query}).String())
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Error("invalid driver option accepted on existing file")
			}
			info, err := os.Stat(existing)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0644 {
				t.Errorf("rejected driver option %q mutated existing file mode to %04o, want 0644", query, got)
			}
		})
	}
}
