package db_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/testutils"
)

// freshMigrationDatabase creates an empty database of the test's own, so the
// migrations run from the start without touching a database anything else uses,
// and drops it afterwards.
func freshMigrationDatabase(t *testing.T, suffix string) *config.DatabaseEndpointConfig {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	var fileCfg struct {
		Database struct {
			Write struct {
				Hosts    []string `toml:"hosts"`
				Port     int      `toml:"port"`
				User     string   `toml:"user"`
				Password string   `toml:"password"`
				Name     string   `toml:"name"`
				TLS      bool     `toml:"tls"`
			} `toml:"write"`
		} `toml:"database"`
	}
	_, _ = toml.DecodeFile("../config-test.toml", &fileCfg)

	hosts := fileCfg.Database.Write.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	var port any = fileCfg.Database.Write.Port
	if fileCfg.Database.Write.Port == 0 {
		port = 5432
	}
	user := fileCfg.Database.Write.User
	if user == "" {
		user = "postgres"
	}
	password := fileCfg.Database.Write.Password
	base := fileCfg.Database.Write.Name
	if base == "" {
		base = "sora_test_db"
	}

	if v := os.Getenv("SORA_TEST_DB_HOST"); v != "" {
		hosts = []string{v}
	}
	if v := os.Getenv("SORA_TEST_DB_PORT"); v != "" {
		port = v
	}
	if v := os.Getenv("SORA_TEST_DB_USER"); v != "" {
		user = v
	}
	if v, ok := os.LookupEnv("SORA_TEST_DB_PASSWORD"); ok {
		password = v
	}
	if v := os.Getenv("SORA_TEST_DB_NAME"); v != "" {
		base = v
	}

	endpoint := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		Port:     port,
		User:     user,
		Password: password,
		Name:     base + suffix,
		TLSMode:  fileCfg.Database.Write.TLS,
	}

	maintenance := *endpoint
	maintenance.Name = "postgres"
	adminURL, err := db.EndpointURL(&maintenance, maintenance.Hosts[0])
	if err != nil {
		t.Fatalf("build maintenance endpoint URL: %v", err)
	}

	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminURL.String())
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	quoted := pgx.Identifier{endpoint.Name}.Sanitize()
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop %s: %v", endpoint.Name, err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create %s: %v", endpoint.Name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", endpoint.Name, err)
		}
	})
	return endpoint
}

// Startup migrations must work behind a transaction-mode pooler, where consecutive
// statements outside a transaction can run on different server connections: a
// session-level advisory lock taken by one statement and released by another is left
// held on a pooled backend. The migration leader election already serialises the
// migrators with a transaction-scoped lock, so no session-level lock may be issued.
func TestStartupMigrations_TakeNoSessionLevelAdvisoryLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	endpoint := freshMigrationDatabase(t, "_sessionlock")
	targetURL, err := db.EndpointURL(endpoint, endpoint.Hosts[0])
	if err != nil {
		t.Fatalf("build target endpoint URL: %v", err)
	}
	proxy := testutils.StartSQLRecordingProxy(t, targetURL.Host)

	writeCfg := *endpoint
	writeCfg.Hosts = []string{proxy.Host}
	writeCfg.Port = int64(proxy.Port)
	cfg := &config.DatabaseConfig{
		MigrationTimeout: "2m",
		Write:            &writeCfg,
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
