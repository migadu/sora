package db_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/testutils"
)

// freshMigrationDatabase creates an empty database of the test's own, so the
// migrations run from the start without touching a database anything else uses,
// and drops it afterwards.
func freshMigrationDatabase(t *testing.T, suffix string) string {
	t.Helper()
	ctx := context.Background()
	base := os.Getenv("SORA_TEST_DB_NAME")
	if base == "" {
		base = "sora_test_db"
	}
	name := base + suffix
	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
	})
	return name
}

// Startup migrations must work behind a transaction-mode pooler, where consecutive
// statements outside a transaction can run on different server connections: a
// session-level advisory lock taken by one statement and released by another is left
// held on a pooled backend. The migration leader election already serialises the
// migrators with a transaction-scoped lock, so no session-level lock may be issued.
func TestStartupMigrations_TakeNoSessionLevelAdvisoryLock(t *testing.T) {
	name := freshMigrationDatabase(t, "_sessionlock")
	proxy := testutils.StartSQLRecordingProxy(t, "localhost:5432")

	cfg := &config.DatabaseConfig{
		MigrationTimeout: "2m",
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{proxy.Host},
			Port:  int64(proxy.Port),
			User:  "postgres",
			Name:  name,
		},
	}
	database, err := db.NewDatabaseFromConfig(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("NewDatabaseFromConfig with migrations: %v", err)
	}
	var version int64
	var dirty bool
	err = database.WritePool.QueryRow(context.Background(), "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty)
	database.Close()
	if err != nil || dirty || version == 0 {
		t.Fatalf("migrations did not complete: version %d dirty %v err %v", version, dirty, err)
	}

	if !containsStatement(proxy.Statements(), "pg_try_advisory_xact_lock") {
		t.Fatal("the proxy did not record the migration leader election; the test is not observing the migration")
	}
	if locks := proxy.SessionAdvisoryLockStatements(); len(locks) > 0 {
		t.Fatalf("migrations issued %d session-level advisory lock statement(s), which strand behind a transaction-mode pooler: %q",
			len(locks), locks)
	}
}

func containsStatement(statements []string, fragment string) bool {
	for _, s := range statements {
		if strings.Contains(s, fragment) {
			return true
		}
	}
	return false
}
