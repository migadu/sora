//go:build integration

package main

import (
	"context"
	"os"
	"testing"

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
