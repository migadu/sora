//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/testutils"
)

// sora-admin migrate up/down/force must take no session-level advisory lock, which
// strands on a pooled backend behind a transaction-mode pooler.
func TestMigrateCommands_TakeNoSessionLevelAdvisoryLock(t *testing.T) {
	cfg := adminTestDBConfig(t)
	proxy := testutils.StartSQLRecordingProxy(t, "localhost:5432")

	saved := globalConfig.Database.Write
	t.Cleanup(func() { globalConfig.Database.Write = saved })
	globalConfig.Database.Write = &config.DatabaseEndpointConfig{
		Hosts: []string{proxy.Host},
		Port:  proxy.Port,
		User:  "postgres",
		Name:  cfg.Write.Name,
	}

	m, closer, err := getMigrateInstance(context.Background())
	if err != nil {
		t.Fatalf("getMigrateInstance: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		closer.Close()
		t.Fatalf("migrate up: %v", err)
	}
	closer.Close()

	if locks := proxy.SessionAdvisoryLockStatements(); len(locks) > 0 {
		t.Fatalf("sora-admin migrate issued %d session-level advisory lock statement(s): %q", len(locks), locks)
	}
	sawVersionTable := false
	for _, s := range proxy.Statements() {
		if strings.Contains(s, "schema_migrations") {
			sawVersionTable = true
		}
	}
	if !sawVersionTable {
		t.Fatal("the proxy recorded no schema_migrations statement; the test is not observing sora-admin migrate")
	}
}

// sora-admin migrate up/down/force must not run while a sora instance is migrating:
// they take the same migration leader lock the instances elect a leader with.
func TestMigrateCommands_RefusedWhileTheMigrationLeaderLockIsHeld(t *testing.T) {
	cfg := adminTestDBConfig(t)
	ctx := context.Background()

	holder, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/"+cfg.Write.Name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer holder.Close(ctx)
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(consts.SoraMigrationLeaderLockID)); err != nil {
		t.Fatalf("take the migration leader lock: %v", err)
	}

	saved := globalConfig.Database.Write
	t.Cleanup(func() { globalConfig.Database.Write = saved })
	globalConfig.Database.Write = cfg.Write

	_, closer, err := getMigrateInstance(ctx)
	if err == nil {
		closer.Close()
		t.Fatal("sora-admin migrate got a migration instance while another migrator holds the leader lock")
	}
	if !errors.Is(err, db.ErrMigrationInProgress) {
		t.Fatalf("getMigrateInstance failed with %v, want db.ErrMigrationInProgress", err)
	}
}

// The migration driver runs migrations both ways and records the version as
// golang-migrate expects: down one step, force, up again.
func TestMigrateCommands_DownForceUpRoundTrip(t *testing.T) {
	cfg := adminTestDBConfig(t)
	saved := globalConfig.Database.Write
	t.Cleanup(func() { globalConfig.Database.Write = saved })
	globalConfig.Database.Write = cfg.Write

	m, closer, err := getMigrateInstance(context.Background())
	if err != nil {
		t.Fatalf("getMigrateInstance: %v", err)
	}
	defer closer.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("up: %v", err)
	}
	latest, dirty, err := m.Version()
	if err != nil || dirty {
		t.Fatalf("version after up: %d dirty %v err %v", latest, dirty, err)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("down one step: %v", err)
	}
	if v, dirty, err := m.Version(); err != nil || dirty || v != latest-1 {
		t.Fatalf("version after down: %d dirty %v err %v, want %d clean", v, dirty, err, latest-1)
	}

	if err := m.Force(int(latest - 1)); err != nil {
		t.Fatalf("force: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if v, dirty, err := m.Version(); err != nil || dirty || v != latest {
		t.Fatalf("version after up again: %d dirty %v err %v, want %d clean", v, dirty, err, latest)
	}
}
