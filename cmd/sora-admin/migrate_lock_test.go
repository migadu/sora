//go:build integration

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
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

	m, closer, err := getMigrateInstance(ctx)
	if err == nil {
		_ = m
		closer.Close()
		t.Fatal("sora-admin migrate got a migration instance while another migrator holds the leader lock")
	}
}
