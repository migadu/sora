package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The maildir cache is <maildir-path>/sora-maildir.db for every maildir path. A plain
// SQLite DSN is cut at its first '?' (the rest is read as DSN parameters), so a '?' in
// the path used to open the cache outside the maildir, at the path truncated there.
// '#' and '%' are special in a file: URI and must reach SQLite as part of the name too.
func TestMaildirCacheStaysInsideMaildirPath(t *testing.T) {
	type opener struct {
		name string
		open func(t *testing.T, maildirPath string) *sql.DB
	}
	openers := []opener{
		{"import", func(t *testing.T, maildirPath string) *sql.DB {
			importer, err := NewImporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			return importer.sqliteDB
		}},
		{"export", func(t *testing.T, maildirPath string) *sql.DB {
			exporter, err := NewExporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ExporterOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })
			return exporter.db
		}},
	}
	dirs := []string{"a?b", "a#b", "a%3Fb", "a%b", "a?_journal_mode=DELETE&b"}

	for _, o := range openers {
		for _, dir := range dirs {
			t.Run(o.name+"/"+dir, func(t *testing.T) {
				root := t.TempDir()
				maildirPath := filepath.Join(root, dir, "Maildir")
				require.NoError(t, os.MkdirAll(maildirPath, 0755))

				cache := o.open(t, maildirPath)
				assertMaildirCacheSettings(t, cache)

				assert.FileExists(t, filepath.Join(maildirPath, "sora-maildir.db"))
				assert.Equal(t, []string{dir}, dirNames(t, root), "the cache was created outside the maildir")
			})
		}

		t.Run(o.name+"/relative path", func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			maildirPath := filepath.Join("a?b", "Maildir")
			require.NoError(t, os.MkdirAll(maildirPath, 0755))

			cache := o.open(t, maildirPath)
			assertMaildirCacheSettings(t, cache)

			assert.FileExists(t, filepath.Join(root, "a?b", "Maildir", "sora-maildir.db"))
			assert.Equal(t, []string{"a?b"}, dirNames(t, root), "the cache was created outside the maildir")
		})
	}
}

// assertMaildirCacheSettings checks that the cache was opened with the connection
// settings the importer and exporter ask for (WAL, 5 s busy timeout, synchronous NORMAL).
func assertMaildirCacheSettings(t *testing.T, cache *sql.DB) {
	t.Helper()
	var journalMode string
	var busyTimeout, synchronous int
	require.NoError(t, cache.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode))
	require.NoError(t, cache.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout))
	require.NoError(t, cache.QueryRow(`PRAGMA synchronous`).Scan(&synchronous))
	assert.Equal(t, "wal", journalMode)
	assert.Equal(t, 5000, busyTimeout)
	assert.Equal(t, 1, synchronous, "synchronous NORMAL")
}

// dirNames lists the names in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
