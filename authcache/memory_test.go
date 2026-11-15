package authcache

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// An in-memory or temporary SQLite database is private to the connection that opened it
// (unless shared, and then it lasts only while a connection is open), and the cache's
// *sql.DB is a pool: the schema openAndValidate created and the rows Put wrote lived on
// one pooled connection, every other connection (Get runs without the mutex, so
// concurrent logins open more) failed with "no such table", and the pool closing an idle
// connection dropped its rows. None of them survives the restart the cache exists for,
// so New refuses them, and creates nothing on disk for them.
func TestDatabaseThatIsNotAFileIsRefused(t *testing.T) {
	for _, dbPath := range []string{
		":memory:",
		"file::memory:",
		"file::memory:?cache=shared",
		"file:auth_cache.db?mode=memory",
		"file:/auth_cache.db?vfs=memdb",
		"file:", // no name: a temporary database
	} {
		t.Run(dbPath, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
			if err == nil {
				defer c.Close()
				ctx := context.Background()
				putErr := c.Put(ctx, "user@example.com", 42, "$2a$10$hash")
				conn, err := c.db.Conn(ctx) // hold one connection, as a concurrent login does
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_, _, getErr := c.Get(ctx, "user@example.com")
				t.Fatalf("New(%q) accepted a database that is not a file (Put: %v; Get with a connection held: %v)", dbPath, putErr, getErr)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Errorf("New(%q) left %d files in the working directory (err %v)", dbPath, len(entries), err)
			}
		})
	}
}

// Refusing a database that is not a file is not corruption. Handled as corruption, New
// logged "Database appears corrupted, recreating", deleted the files named after the
// configured path (a file merely called ":memory:" in the working directory), opened it
// again, and reported "failed to recreate auth cache db".
func TestDatabaseThatIsNotAFileIsNotTreatedAsCorrupt(t *testing.T) {
	for _, dbPath := range []string{":memory:", "file::memory:", "file:auth_cache.db?mode=memory", "file:"} {
		t.Run(dbPath, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile(dbPath, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
			if err == nil {
				c.Close()
				t.Fatalf("New(%q) accepted a database that is not a file", dbPath)
			}
			if strings.Contains(err.Error(), "recreate") {
				t.Errorf("New(%q) handled the refusal as corruption: %v", dbPath, err)
			}
			if _, statErr := os.Stat(dbPath); statErr != nil {
				t.Errorf("New(%q) removed a file named after the path: %v", dbPath, statErr)
			}
		})
	}
}
