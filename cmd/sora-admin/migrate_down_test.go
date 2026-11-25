//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// migrateTestDB connects to the admin test database with an empty schema and writes a
// sora-admin config file that points at it. The schema is emptied again afterwards,
// since the other tests of this database migrate from an empty schema.
func migrateTestDB(t *testing.T) (conn *pgx.Conn, configPath string) {
	t.Helper()
	cfg := adminTestDBConfig(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+cfg.Write.Name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(ctx) }) // after resetSchema: cleanups run last-in first-out
	resetSchema := func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
			t.Fatalf("reset schema of %s: %v", cfg.Write.Name, err)
		}
	}
	resetSchema()
	t.Cleanup(resetSchema)

	configPath = filepath.Join(t.TempDir(), "config.toml")
	content := fmt.Sprintf("[database.write]\nhosts = [\"localhost\"]\nport = 5432\nuser = \"postgres\"\nname = %q\n", cfg.Write.Name)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return conn, configPath
}

// schemaVersion returns the version recorded in schema_migrations, and false when no
// version is recorded.
func schemaVersion(t *testing.T, conn *pgx.Conn) (uint64, bool) {
	t.Helper()
	var version int64
	var dirty bool
	err := conn.QueryRow(context.Background(), "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if dirty || version < 0 {
		t.Fatalf("schema_migrations = (%d, dirty %v), want a clean version", version, dirty)
	}
	return uint64(version), true
}

// embeddedMigrationVersions returns the versions of the migrations built into the
// binary, in ascending order.
func embeddedMigrationVersions(t *testing.T) []uint64 {
	t.Helper()
	files, err := fs.Glob(db.MigrationsFS, "migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	var versions []uint64
	for _, file := range files {
		prefix, _, _ := strings.Cut(path.Base(file), "_")
		version, err := strconv.ParseUint(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration file %s: %v", file, err)
		}
		versions = append(versions, version)
	}
	if len(versions) < 1 {
		t.Fatal("found no embedded migrations")
	}
	slices.Sort(versions)
	return versions
}

// checkSchemaVersion reports an error unless schema_migrations records want.
func checkSchemaVersion(t *testing.T, conn *pgx.Conn, step string, want uint64) {
	t.Helper()
	got, ok := schemaVersion(t, conn)
	if !ok {
		t.Errorf("after %s: no migration version recorded, want %d", step, want)
	} else if got != want {
		t.Errorf("after %s: migration version %d, want %d", step, got, want)
	}
}

// TestMigrateDownAll_KeepsInitialMigrationSoUpSucceeds: `migrate down --all` reverts
// every migration after the first. #1600: it passed the version number to
// golang-migrate as the step count, ran out of migrations (the numbers have gaps) and
// exited 1 after a complete revert. #1667: it also ran the down file of the first
// migration, which was deliberately empty, so the initial tables stayed while no version was recorded,
// and the next `migrate up` (or sora's startup migration) failed creating them again
// and left version 1 dirty. It must leave the first migration applied, so that
// `migrate up` succeeds afterwards, and a second run with nothing to revert must
// succeed too.
func TestMigrateDownAll_KeepsInitialMigrationSoUpSucceeds(t *testing.T) {
	conn, configPath := migrateTestDB(t)
	versions := embeddedMigrationVersions(t)
	first, latest := versions[0], versions[len(versions)-1]

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up: exit code %d:\n%s", code, out)
	}
	checkSchemaVersion(t, conn, "migrate up", latest)

	out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--all")
	if code != 0 {
		t.Fatalf("migrate down --all: exit code %d, want 0:\n%s", code, out)
	}
	// With only the baseline embedded there is nothing after the first migration.
	wantReport := "Migrations reverted successfully"
	if first == latest {
		wantReport = "No migrations to revert"
	}
	if !strings.Contains(out, wantReport) {
		t.Errorf("migrate down --all did not report %q:\n%s", wantReport, out)
	}
	checkSchemaVersion(t, conn, "migrate down --all", first)

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up after migrate down --all: exit code %d, want 0:\n%s", code, out)
	}
	checkSchemaVersion(t, conn, "migrate up after migrate down --all", latest)

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--all"); code != 0 {
		t.Fatalf("migrate down --all: exit code %d, want 0:\n%s", code, out)
	}
	out, code = runAdminMain(t, "--config", configPath, "migrate", "down", "--all")
	if code != 0 {
		t.Fatalf("migrate down --all with nothing to revert: exit code %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "No migrations to revert") {
		t.Errorf("migrate down --all with nothing to revert did not say so:\n%s", out)
	}
	checkSchemaVersion(t, conn, "a second migrate down --all", first)
}

// TestMigrateDownAll_ThenSoraStartupMigrates (#1667): after `migrate down --all`, the
// startup migration of the next sora start ran 000001's up again, failed on the tables
// it had left, and stopped startup with version 1 dirty. It must apply the migrations
// after the first and reach the latest version.
func TestMigrateDownAll_ThenSoraStartupMigrates(t *testing.T) {
	conn, configPath := migrateTestDB(t)
	versions := embeddedMigrationVersions(t)
	latest := versions[len(versions)-1]

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up: exit code %d:\n%s", code, out)
	}
	if out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--all"); code != 0 {
		t.Fatalf("migrate down --all: exit code %d, want 0:\n%s", code, out)
	}

	// The startup migration of sora (db.migrate), as NewDatabaseFromConfig runs it.
	database, err := db.NewDatabaseFromConfig(context.Background(), adminTestDBConfig(t), true)
	if err != nil {
		t.Fatalf("sora startup migration after migrate down --all: %v", err)
	}
	database.Close()
	checkSchemaVersion(t, conn, "sora startup migration after migrate down --all", latest)
}

// TestMigrateDownLimit_RefusesToRevertInitialMigration (#1667): a `migrate down
// --limit N` that reaches past the first migration ran its deliberately empty down
// file, recording no version while the initial tables stayed. It must refuse before
// reverting anything, and a limit that stops at the first migration must succeed and
// leave a schema that `migrate up` brings back to the latest version.
func TestMigrateDownLimit_RefusesToRevertInitialMigration(t *testing.T) {
	conn, configPath := migrateTestDB(t)
	versions := embeddedMigrationVersions(t)
	first, latest := versions[0], versions[len(versions)-1]

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up: exit code %d:\n%s", code, out)
	}
	checkSchemaVersion(t, conn, "migrate up", latest)

	all := strconv.Itoa(len(versions))
	out, code := runAdminMain(t, "--config", configPath, "migrate", "down", "--limit", all)
	if code == 0 {
		t.Errorf("migrate down --limit %s (every migration): exit code 0, want non-zero:\n%s", all, out)
	}
	if strings.Contains(out, "Migrations reverted successfully") {
		t.Errorf("migrate down --limit %s reported success:\n%s", all, out)
	}
	if !strings.Contains(out, "would revert the first migration") {
		t.Errorf("migrate down --limit %s did not say why it refused:\n%s", all, out)
	}
	checkSchemaVersion(t, conn, "a refused migrate down --limit "+all, latest)

	if len(versions) == 1 {
		return // only the baseline: no limit stops at the first migration
	}
	allButFirst := strconv.Itoa(len(versions) - 1)
	out, code = runAdminMain(t, "--config", configPath, "migrate", "down", "--limit", allButFirst)
	if code != 0 {
		t.Fatalf("migrate down --limit %s: exit code %d, want 0:\n%s", allButFirst, code, out)
	}
	checkSchemaVersion(t, conn, "migrate down --limit "+allButFirst, first)

	if out, code := runAdminMain(t, "--config", configPath, "migrate", "up"); code != 0 {
		t.Fatalf("migrate up after migrate down --limit %s: exit code %d, want 0:\n%s", allButFirst, code, out)
	}
	checkSchemaVersion(t, conn, "migrate up after migrate down --limit "+allButFirst, latest)
}

// TestMigrateDownAll_RefusesDirtyNilVersion (#1689): a failed down migration of version 1
// records (version = -1, dirty = true) in schema_migrations (db/migrate_driver.go
// SetVersion). Migrate.Version returns ErrNilVersion before returning dirty, so `migrate
// down --all` must not mistake that dirty NilVersion for an empty schema and exit 0.
func TestMigrateDownAll_RefusesDirtyNilVersion(t *testing.T) {
	conn, configPath := migrateTestDB(t)
	ctx := context.Background()

	// A failed down migration of version 1 leaves (version = -1, dirty = true) in
	// schema_migrations (db/migrate_driver.go SetVersion).
	if _, err := conn.Exec(ctx, `
		CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL);
		INSERT INTO schema_migrations (version, dirty) VALUES (-1, true);
	`); err != nil {
		t.Fatalf("seed dirty NilVersion: %v", err)
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
