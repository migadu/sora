package authcache

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// busy_timeout and synchronous are settings of one SQLite connection, and the cache's
// *sql.DB is a pool: set by an Exec after sql.Open they configured only the connection
// that ran it, and every further connection the pool opened (Get runs without the mutex,
// so concurrent logins open more) failed at once on a lock and synced at FULL. That holds
// for a path and for a DSN given as the path alike.
func TestEveryPooledConnectionHasThePragmas(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dbPath func(dir string) string
	}{
		{"path", func(dir string) string { return filepath.Join(dir, "auth_cache.db") }},
		{"file URI", func(dir string) string { return "file:" + filepath.Join(dir, "auth_cache.db") }},
		{"file URI params", func(dir string) string { return "file:" + filepath.Join(dir, "auth_cache.db") + "?mode=rwc" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.dbPath(t.TempDir()), time.Hour, 24*time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx := context.Background()
			for i := 1; i <= 3; i++ {
				conn, err := c.db.Conn(ctx) // the earlier ones are still held: a new connection
				if err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
				defer conn.Close()
				var busyTimeout, synchronous int
				if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
				if err := conn.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
				if busyTimeout != 5000 || synchronous != 1 {
					t.Errorf("connection %d: busy_timeout=%d synchronous=%d, want 5000 and 1 (NORMAL)", i, busyTimeout, synchronous)
				}
			}
		})
	}
}
