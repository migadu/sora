//go:build integration

package resilient

import (
	"context"
	"database/sql"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

// freshDatabase creates an empty database of its own for a test that runs migrations,
// so the shared test database's schema is never touched, and drops it afterwards.
func freshDatabase(t *testing.T) string {
	t.Helper()
	name := testDatabaseConfig().Write.Name + "_failover"
	admin, err := sql.Open("pgx", "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + quoted + " WITH (FORCE)"); err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + quoted); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE IF EXISTS " + quoted + " WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
	})
	return name
}

func writeHostsConfig(name string, hosts ...string) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		MigrationTimeout: "2m",
		Write: &config.DatabaseEndpointConfig{
			Hosts: hosts,
			Port:  "5432",
			User:  "postgres",
			Name:  name,
		},
	}
}

func closeManager(m *RuntimeFailoverManager) {
	if m == nil {
		return
	}
	for _, p := range m.writePools {
		p.database.Close()
	}
}

// The migration must not depend on hosts[0] being up: it runs through the first write
// host that connects.
func TestNewRuntimeFailoverManager_MigratesThroughFirstReachableWriteHost(t *testing.T) {
	name := freshDatabase(t)
	cfg := writeHostsConfig(name, "127.0.0.1:1", "localhost") // nothing listens on port 1

	manager, err := newRuntimeFailoverManager(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatalf("newRuntimeFailoverManager: %v", err)
	}
	defer closeManager(manager)

	var version int64
	var dirty bool
	err = manager.writePools[0].database.WritePool.QueryRow(context.Background(),
		"SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty)
	if err != nil {
		t.Fatalf("the node started without running migrations (hosts[0] was down): %v", err)
	}
	if dirty || version == 0 {
		t.Fatalf("schema_migrations version %d dirty %v after startup", version, dirty)
	}
}

// A failed migration stops startup, also when another write host is configured.
func TestNewRuntimeFailoverManager_MigrationFailureIsFatalWithSeveralWriteHosts(t *testing.T) {
	name := freshDatabase(t)
	conn, err := pgx.Connect(context.Background(), "postgres://postgres@localhost:5432/"+name+"?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// A dirty schema: the previous migration run crashed half way.
	_, err = conn.Exec(context.Background(), `
		CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL);
		INSERT INTO schema_migrations VALUES (1, true)`)
	conn.Close(context.Background())
	if err != nil {
		t.Fatalf("prepare dirty schema: %v", err)
	}

	cfg := writeHostsConfig(name, "localhost", "127.0.0.1") // two names for one server
	manager, err := newRuntimeFailoverManager(context.Background(), cfg, true, true)
	if err == nil {
		closeManager(manager)
		t.Fatalf("startup went on with %d write pool(s) after the migration failed on the first host", len(manager.writePools))
	}
}

// switchableProxy forwards TCP connections to PostgreSQL while up, and drops them
// while down: a database host that can be taken down and brought back.
type switchableProxy struct {
	addr string
	up   atomic.Bool
}

func startSwitchableProxy(t *testing.T, target string) *switchableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &switchableProxy{addr: ln.Addr().String()}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			if !p.up.Load() {
				client.Close()
				continue
			}
			go func() {
				defer client.Close()
				server, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer server.Close()
				go io.Copy(server, client)
				io.Copy(client, server)
			}()
		}
	}()
	return p
}

// A write host that is down at startup must be added once it is reachable, as a
// read replica that is down at startup is.
func TestReconnect_WriteHostDownAtStartupIsAddedLater(t *testing.T) {
	base := testDatabaseConfig()
	migrateTestDatabase(t, base)
	proxy := startSwitchableProxy(t, "localhost:5432")
	cfg := writeHostsConfig(base.Write.Name, proxy.addr, "localhost")

	manager, err := newRuntimeFailoverManager(context.Background(), cfg, false, true)
	if err != nil {
		t.Fatalf("newRuntimeFailoverManager: %v", err)
	}
	defer closeManager(manager)
	if len(manager.writePools) != 1 {
		t.Fatalf("expected one write pool while %s is down, got %d", proxy.addr, len(manager.writePools))
	}

	rd := &ResilientDatabase{
		failoverManager: manager,
		config:          cfg,
		queryBreaker:    circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_query")),
		writeBreaker:    circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_write")),
	}

	proxy.up.Store(true)
	for _, f := range manager.failedHosts {
		f.lastAttempt = time.Now().Add(-time.Hour) // skip the reconnect backoff
	}
	rd.attemptReconnectFailedHosts(context.Background())

	if !hasPoolFor(manager.writePools, proxy.addr) {
		t.Fatalf("write host %s is reachable again but was never added (write pools: %d)", proxy.addr, len(manager.writePools))
	}
	// Without [database.read] the write hosts serve the reads too.
	if !hasPoolFor(manager.readPools, proxy.addr) {
		t.Fatalf("re-added write host %s does not serve reads like the other write hosts", proxy.addr)
	}
}

func hasPoolFor(pools []*DatabasePool, host string) bool {
	for _, p := range pools {
		if p.host == host {
			return true
		}
	}
	return false
}
