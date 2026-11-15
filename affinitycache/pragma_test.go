package affinitycache

import (
	"context"
	"path/filepath"
	"testing"
)

// busy_timeout and synchronous are settings of one SQLite connection, and the store's
// *sql.DB is a pool: set by an Exec after sql.Open they configured only the connection
// that ran it, and every further connection the pool opened failed at once on a lock and
// synced at FULL. That holds for a path and for a DSN given as the path alike.
func TestEveryPooledConnectionHasThePragmas(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dbPath func(dir string) string
	}{
		{"path", func(dir string) string { return filepath.Join(dir, "affinity.db") }},
		{"file URI", func(dir string) string { return "file:" + filepath.Join(dir, "affinity.db") }},
		{"file URI params", func(dir string) string { return "file:" + filepath.Join(dir, "affinity.db") + "?mode=rwc" }},
		{"memory", func(string) string { return ":memory:" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.dbPath(t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			for i := 1; i <= 3; i++ {
				conn, err := s.db.Conn(ctx) // the earlier ones are still held: a new connection
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
