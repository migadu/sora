package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Import and export open sora-maildir.db in a directory the maildir's owner may be
// able to write to (the maildir of an in-place import, or a copy made with rsync -a,
// which keeps links; the destination of an export), and they often run as root. A
// link the owner leaves at the cache's name, or at the -wal, -shm or -journal name
// SQLite keeps beside it, must not make them create or write a file outside that
// directory: the open is refused, naming the link (#1606).
func TestMaildirCacheRefusesLinks(t *testing.T) {
	openers := []struct {
		name string
		open func(t *testing.T, dir string) error
	}{
		{"import", func(t *testing.T, dir string) error {
			importer, err := NewImporter(context.Background(), dir, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			if err == nil {
				t.Cleanup(func() { importer.Close() })
			}
			return err
		}},
		{"export", func(t *testing.T, dir string) error {
			exporter, err := NewExporter(context.Background(), dir, "user@example.com", 1, nil, nil, ExporterOptions{})
			if err == nil {
				t.Cleanup(func() { exporter.Close() })
			}
			return err
		}},
	}
	names := []string{"sora-maildir.db", "sora-maildir.db-wal", "sora-maildir.db-shm", "sora-maildir.db-journal"}

	for _, o := range openers {
		for _, name := range names {
			for _, existing := range []bool{false, true} {
				target := "missing target"
				if existing {
					target = "empty file"
				}
				t.Run(o.name+"/"+name+"/"+target, func(t *testing.T) {
					dir := newMaildirWith(t, nil)
					outDir := t.TempDir()
					outside := filepath.Join(outDir, "outside")
					if existing {
						require.NoError(t, os.WriteFile(outside, nil, 0644))
					}
					link := filepath.Join(dir, name)
					require.NoError(t, os.Symlink(outside, link))

					err := o.open(t, dir)

					assert.ErrorContains(t, err, link, "the link was not refused by name")
					want := []string{}
					if existing {
						want = []string{"outside"}
					}
					assert.Equal(t, want, dirNames(t, outDir), "created a file outside the maildir through the link")
					if existing {
						info, err := os.Stat(outside)
						require.NoError(t, err)
						assert.Zero(t, info.Size(), "wrote the file the link names")
					}
				})
			}
		}
	}
}
