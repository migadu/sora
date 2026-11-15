package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
)

// resetTestDBName is the database this test empties: a dedicated one, never the shared
// test database other packages use at the same time.
func resetTestDBName() string {
	base := os.Getenv("SORA_TEST_DB_NAME")
	if base == "" {
		base = "sora_test_db"
	}
	return base + "_reset"
}

// TestFallbackToTruncateEmptiesEveryTable: when DROP SCHEMA fails, the reset falls back
// to truncating tables. Whatever the migrations have created since, every table must
// come out empty, or later test runs start from rows an earlier run left behind. And
// the tables stay, so the migration state must stay with them: the next test run has
// to be able to migrate the database.
func TestFallbackToTruncateEmptiesEveryTable(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := resetTestDBName()

	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	admin.Close(ctx)

	conn, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect to %s: %v", name, err)
	}
	defer conn.Close(ctx)

	// Start from this branch's schema, whatever an earlier run or another branch left here.
	for _, q := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dbConfig := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name},
	}
	database, err := db.NewDatabaseFromConfig(ctx, dbConfig, true)
	if err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}
	database.Close()

	for _, q := range []string{
		`WITH a AS (INSERT INTO accounts DEFAULT VALUES RETURNING id)
			INSERT INTO credentials (account_id, address, password, primary_identity)
			SELECT id, 'reset@example.com', 'x', true FROM a`,
		`INSERT INTO locks (lock_name, acquired_at, expires_at) VALUES ('reset-test', now(), now())`,
		`INSERT INTO instance_heartbeats (instance_id) VALUES ('reset-test')`,
		`INSERT INTO backend_maintenance (host, instance_id) VALUES ('reset-test', 'reset-test')`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}

	fallbackToTruncate(ctx, conn)

	rows, err := conn.Query(ctx, "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'schema_migrations' ORDER BY tablename")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		var n int64
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("table %s still has %d rows after the fallback truncate", table, n)
		}
	}

	// Without its schema_migrations row, the next run starts again at 000001 and fails on
	// CREATE TABLE accounts: the fallback would leave a database no test can set up.
	database, err = db.NewDatabaseFromConfig(ctx, dbConfig, true)
	if err != nil {
		t.Fatalf("migrate %s after the fallback truncate: %v", name, err)
	}
	database.Close()
}
