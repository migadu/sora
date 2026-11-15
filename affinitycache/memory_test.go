package affinitycache

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// An in-memory or temporary SQLite database is private to the connection that opened it
// (unless shared, and then it lasts only while a connection is open), and the store's
// *sql.DB is a pool: the schema openAndValidate created and the rows Set wrote lived on
// one pooled connection, every other connection failed with "no such table", and the
// pool closing an idle connection dropped its rows. None of them survives the restart
// the store exists for, so New refuses them, and creates nothing on disk for them.
func TestDatabaseThatIsNotAFileIsRefused(t *testing.T) {
	for _, dbPath := range []string{
		":memory:",
		"file::memory:",
		"file::memory:?cache=shared",
		"file:affinity.db?mode=memory",
		"file:/affinity.db?vfs=memdb",
		"file:", // no name: a temporary database
	} {
		t.Run(dbPath, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			s, err := New(dbPath)
			if err == nil {
				defer s.Close()
				ctx := context.Background()
				now := time.Now()
				setErr := s.Set(ctx, AffinityEntry{Username: "user@example.com", Protocol: "imap", Backend: "10.0.0.1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"})
				conn, err := s.db.Conn(ctx) // hold one connection, so the next query opens another
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_, loadErr := s.LoadAll(ctx)
				t.Fatalf("New(%q) accepted a database that is not a file (Set: %v; LoadAll with a connection held: %v)", dbPath, setErr, loadErr)
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
// again, and reported "failed to recreate affinity cache db".
func TestDatabaseThatIsNotAFileIsNotTreatedAsCorrupt(t *testing.T) {
	for _, dbPath := range []string{":memory:", "file::memory:", "file:affinity.db?mode=memory", "file:"} {
		t.Run(dbPath, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile(dbPath, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := New(dbPath)
			if err == nil {
				s.Close()
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
