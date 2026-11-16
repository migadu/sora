//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestMigrateDownAll_RevertsEveryMigrationAndSucceeds (#1600): `migrate down --all`
// passed the current version number to golang-migrate as the step count, but the
// migration numbers have gaps, so there are fewer migrations than the version says.
// golang-migrate reverted every migration, ran out of earlier ones and returned
// "limit N short", and the command exited 1 after a complete revert. It must exit 0
// with no migration applied, and a second run with nothing to revert must succeed too.
func TestMigrateDownAll_RevertsEveryMigrationAndSucceeds(t *testing.T) {
	cfg := adminTestDBConfig(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+cfg.Write.Name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(ctx) }) // after resetSchema: cleanups run last-in first-out
	// Migration 1's down is deliberately a no-op, so a full revert leaves its tables and
	// a later `migrate up` would fail on them. Start from, and leave behind, an empty
	// schema, which the other tests of this database migrate from.
	resetSchema := func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
			t.Fatalf("reset schema of %s: %v", cfg.Write.Name, err)
		}
	}
	resetSchema()
	t.Cleanup(resetSchema)

	configPath := filepath.Join(t.TempDir(), "config.toml")
	content := fmt.Sprintf("[database.write]\nhosts = [\"localhost\"]\nport = 5432\nuser = \"postgres\"\nname = %q\n", cfg.Write.Name)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up: exit code %d:\n%s", code, out)
	}

	out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--all")
	if code != 0 {
		t.Fatalf("migrate down --all: exit code %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "Migrations reverted successfully") {
		t.Errorf("migrate down --all did not report success:\n%s", out)
	}

	var version int64
	switch err := conn.QueryRow(ctx, "SELECT version FROM schema_migrations LIMIT 1").Scan(&version); {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		t.Fatalf("query schema_migrations: %v", err)
	default:
		t.Errorf("migration version %d is still applied after migrate down --all", version)
	}

	out, code = runAdminMain(t, "--config", configPath, "migrate", "down", "--all")
	if code != 0 {
		t.Fatalf("migrate down --all with nothing applied: exit code %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "No migrations to revert") {
		t.Errorf("migrate down --all with nothing applied did not say so:\n%s", out)
	}
}

// TestMigrateDownAll_RefusesDirtyNilVersion (#1689): a failed down migration of version 1
// records (version = -1, dirty = true) in schema_migrations (db/migrate_driver.go
// SetVersion). Migrate.Version returns ErrNilVersion before returning dirty, so `migrate
// down --all` must not mistake that dirty NilVersion for an empty schema and exit 0.
func TestMigrateDownAll_RefusesDirtyNilVersion(t *testing.T) {
	cfg := adminTestDBConfig(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+cfg.Write.Name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	resetSchema := func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
			t.Fatalf("reset schema of %s: %v", cfg.Write.Name, err)
		}
	}
	resetSchema()
	t.Cleanup(resetSchema)

	// A failed down migration of version 1 leaves (version = -1, dirty = true) in
	// schema_migrations (db/migrate_driver.go SetVersion).
	if _, err := conn.Exec(ctx, `
		CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL);
		INSERT INTO schema_migrations (version, dirty) VALUES (-1, true);
	`); err != nil {
		t.Fatalf("seed dirty NilVersion: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.toml")
	content := fmt.Sprintf("[database.write]\nhosts = [\"localhost\"]\nport = 5432\nuser = \"postgres\"\nname = %q\n", cfg.Write.Name)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--all")
	if code == 0 {
		t.Fatalf("migrate down --all on dirty version -1: exit code 0, want non-zero:\n%s", out)
	}
	if !strings.Contains(out, "Database is in a dirty state (version -1)") {
		t.Errorf("migrate down --all output did not report dirty version -1:\n%s", out)
	}
	if strings.Contains(out, "No migrations to revert") {
		t.Errorf("migrate down --all reported nothing to revert on dirty version -1:\n%s", out)
	}

	var version int64
	var dirty bool
	if err := conn.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if version != -1 || !dirty {
		t.Errorf("schema_migrations = (%d, %v), want (-1, true)", version, dirty)
	}
}
