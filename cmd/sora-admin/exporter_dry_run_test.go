package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// `export maildir --dry-run` is documented as a preview "without making changes", and
// its report reads only PostgreSQL and the cache of a previous export. A dry run against
// a path that does not exist yet must leave it that way: no directory, no
// sora-maildir.db.
func TestExporterDryRunCreatesNothing(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "does-not-exist")
	maildirPath := filepath.Join(parent, "Maildir")

	exporter, err := NewExporter(context.Background(), maildirPath, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	// Nothing has been exported to this path, so every message is reported as new.
	exported, filename, err := exporter.isMessageExported("somehash", "INBOX")
	if err != nil || exported || filename != "" {
		t.Errorf("isMessageExported = (%v, %q, %v), want (false, \"\", nil)", exported, filename, err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		var created []string
		_ = filepath.WalkDir(parent, func(path string, _ os.DirEntry, _ error) error {
			created = append(created, path)
			return nil
		})
		t.Errorf("dry run created %v", created)
	}
}

// A dry run against a maildir a previous export (or import) left behind reads that
// cache, as the export would, to report already exported messages as skipped, and
// leaves it exactly as it was: no schema creation, no migration, no -wal or -shm files.
func TestExporterDryRunReadsExistingCacheWithoutChangingIt(t *testing.T) {
	ctx := context.Background()

	t.Run("current schema", func(t *testing.T) {
		// Characters that need escaping in an SQLite URI filename.
		maildirPath := filepath.Join(t.TempDir(), "Mail dir #1 100%")

		// A real export writes the cache in WAL mode and records the exported file.
		exporter, err := NewExporter(ctx, maildirPath, "dryrun@example.com", 1, nil, nil, ExporterOptions{})
		if err != nil {
			t.Fatalf("NewExporter: %v", err)
		}
		const filename = "1700000000.M1P1.host:2,S"
		path := filepath.Join(maildirPath, "cur", filename)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("Subject: exported\r\n\r\nBody"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := exporter.recordExport("exportedhash", "INBOX", filename, path, 26); err != nil {
			t.Fatalf("recordExport: %v", err)
		}
		if err := exporter.Close(); err != nil {
			t.Fatal(err)
		}

		assertDryRunLeavesCache(t, maildirPath, "exportedhash", true, filename)
	})

	t.Run("pre-migration schema", func(t *testing.T) {
		maildirPath := filepath.Join(t.TempDir(), "Maildir")
		if err := os.MkdirAll(maildirPath, 0o755); err != nil {
			t.Fatal(err)
		}
		// Its one row points at a file that is gone, which the export recreates under
		// the recorded name.
		createPreMigrationCache(t, maildirPath)

		assertDryRunLeavesCache(t, maildirPath, "legacyhash", false, "legacy.eml")
	})
}

// assertDryRunLeavesCache runs a dry-run exporter against maildirPath, checks what it
// reads from the cache for hash in INBOX, and checks that the maildir's files and the
// cache's bytes are unchanged afterwards.
func assertDryRunLeavesCache(t *testing.T, maildirPath, hash string, wantExported bool, wantFilename string) {
	t.Helper()

	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	namesBefore := dirNames(t, maildirPath)
	cacheBefore, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	exporter, err := NewExporter(context.Background(), maildirPath, "dryrun@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	exported, filename, err := exporter.isMessageExported(hash, "INBOX")
	if err != nil || exported != wantExported || filename != wantFilename {
		t.Errorf("isMessageExported = (%v, %q, %v), want (%v, %q, nil)", exported, filename, err, wantExported, wantFilename)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if namesAfter := dirNames(t, maildirPath); !slices.Equal(namesAfter, namesBefore) {
		t.Errorf("dry run changed the maildir's files\nbefore: %v\nafter:  %v", namesBefore, namesAfter)
	}
	cacheAfter, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cacheAfter, cacheBefore) {
		t.Errorf("dry run changed %s (%d bytes before, %d after)", dbPath, len(cacheBefore), len(cacheAfter))
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
