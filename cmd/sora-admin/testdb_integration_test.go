//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// adminTestDBName is the database the sora-admin integration tests own. Several of
// them drop its whole schema, so it must never be a database anything else uses.
// These tests used to hardcode sora_mail_db, the development database, and every
// run wiped it.
func adminTestDBName() string {
	base := os.Getenv("SORA_TEST_DB_NAME")
	if base == "" {
		base = "sora_test_db"
	}
	return base + "_admin"
}

// configTestDatabase returns config-test.toml's database settings, naming
// SORA_TEST_DB_NAME's database when that is set. The file names sora_test_db, but the
// other test packages and make's reset-test-db use SORA_TEST_DB_NAME.
func configTestDatabase(t *testing.T) *config.DatabaseConfig {
	t.Helper()
	var cfg AdminConfig
	if _, err := toml.DecodeFile("../../config-test.toml", &cfg); err != nil {
		t.Fatalf("Failed to load test configuration: %v", err)
	}
	if name := os.Getenv("SORA_TEST_DB_NAME"); name != "" {
		for _, endpoint := range []*config.DatabaseEndpointConfig{cfg.Database.Write, cfg.Database.Read} {
			if endpoint != nil {
				endpoint.Name = name
			}
		}
	}
	return &cfg.Database
}

// adminTestDBConfig returns the config for adminTestDBName, creating the database
// if it does not exist yet. It skips when PostgreSQL is unreachable.
func adminTestDBConfig(t *testing.T) *config.DatabaseConfig {
	t.Helper()
	ctx := context.Background()
	name := adminTestDBName()

	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer admin.Close(ctx)
	var exists bool
	err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists)
	if err == nil && !exists {
		_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	}
	if err != nil {
		t.Fatalf("Failed to create test database %s: %v", name, err)
	}

	return &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  name,
		},
	}
}

// openAdminTestDatabase connects to the admin test database and migrates it.
func openAdminTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()
	rdb, err := resilient.NewResilientDatabase(context.Background(), adminTestDBConfig(t), true, true)
	if err != nil {
		t.Fatalf("Failed to connect to and migrate test database %s: %v", adminTestDBName(), err)
	}
	return rdb
}

// setupTestDatabase gives a test an empty, freshly migrated admin test database.
func setupTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()
	ctx := context.Background()
	cfg := adminTestDBConfig(t)

	// Empty the schema so the migrations run from scratch.
	conn, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+cfg.Write.Name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to connect to test database %s: %v", cfg.Write.Name, err)
	}
	_, err = conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
	conn.Close(ctx)
	if err != nil {
		t.Fatalf("Failed to reset test database %s: %v", cfg.Write.Name, err)
	}

	return openAdminTestDatabase(t)
}

// TestConfigTestHelpersUseTheTestDatabase: the helpers that read config-test.toml,
// which names sora_test_db, must connect to SORA_TEST_DB_NAME's database, the one make's
// reset-test-db resets and the other test packages use. Otherwise an isolated run writes
// into, and migrates, the shared test database.
func TestConfigTestHelpersUseTheTestDatabase(t *testing.T) {
	want := os.Getenv("SORA_TEST_DB_NAME")
	if want == "" {
		want = "sora_test_db"
	}
	for _, helper := range []struct {
		name  string
		setup func(*testing.T) *resilient.ResilientDatabase
	}{
		{"setupACLTestDatabase", setupACLTestDatabase},
		{"setupMailboxTestDatabase", setupMailboxTestDatabase},
		{"setupSieveTestDatabase", setupSieveTestDatabase},
	} {
		t.Run(helper.name, func(t *testing.T) {
			rdb := helper.setup(t)
			defer rdb.Close()
			var got string
			if err := rdb.QueryRowWithRetry(context.Background(), "SELECT current_database()").Scan(&got); err != nil {
				t.Fatalf("query current database: %v", err)
			}
			if got != want {
				t.Errorf("%s connected to %s, want %s", helper.name, got, want)
			}
		})
	}
}
