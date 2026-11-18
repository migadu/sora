package main

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// previousMigrationVersion returns the version of the migration just below latest
// among the migration files in fsys: the version migrate down one step lands on.
// It asks golang-migrate's own source driver, so it orders the files as Steps does.
func previousMigrationVersion(fsys fs.FS, latest uint) (uint, error) {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return src.Prev(latest)
}

// Migration numbers need not be consecutive: while two open changes each add a
// migration, one is renumbered on merge and leaves a gap below the newest.
func TestPreviousMigrationVersion_SkipsAGap(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, name := range []string{"000001_a", "000002_b", "000005_c"} {
		fsys[name+".up.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
		fsys[name+".down.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	}

	prev, err := previousMigrationVersion(fsys, 5)
	if err != nil {
		t.Fatalf("previousMigrationVersion: %v", err)
	}
	if prev != 2 {
		t.Fatalf("previous version below 5 is %d, want 2 (the highest migration file below it)", prev)
	}
}
