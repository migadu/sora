package affinitycache

import (
	"os"
	"testing"
)

// A SQLite memory URI never opens its literal spelling as a filesystem path.
// Refusing it must not run corrupt-file recovery against unrelated files.
func TestNonFileDatabaseRefusalPreservesLiteralPaths(t *testing.T) {
	for _, path := range []string{":memory:", "file:malformed?mode=memory"} {
		t.Run(path, func(t *testing.T) {
			t.Chdir(t.TempDir())
			suffixes := []string{"", "-wal", "-shm", "-journal"}
			for _, suffix := range suffixes {
				if err := os.WriteFile(path+suffix, []byte("unrelated literal file"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c, _ := New(path)
			if c != nil {
				c.Close()
			}
			for _, suffix := range suffixes {
				got, err := os.ReadFile(path + suffix)
				if err != nil || string(got) != "unrelated literal file" {
					t.Errorf("literal path %q changed or removed: %q, %v", path+suffix, got, err)
				}
			}
		})
	}
}
