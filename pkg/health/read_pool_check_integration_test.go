//go:build integration

package health

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// killableProxy forwards TCP connections to target until Kill, which closes every
// forwarded connection and refuses new ones: a database host that goes down.
type killableProxy struct {
	addr  string
	mu    sync.Mutex
	dead  bool
	conns []net.Conn
}

func startKillableProxy(t *testing.T, target string) *killableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &killableProxy{addr: ln.Addr().String()}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			p.mu.Lock()
			if err != nil || p.dead {
				p.mu.Unlock()
				client.Close()
				if server != nil {
					server.Close()
				}
				continue
			}
			p.conns = append(p.conns, client, server)
			p.mu.Unlock()
			go func() { io.Copy(server, client); server.Close() }()
			go func() { io.Copy(client, server); client.Close() }()
		}
	}()
	return p
}

func (p *killableProxy) Kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dead = true
	for _, c := range p.conns {
		c.Close()
	}
}

// database_read_pool must check the pool reads are served from. With [database.read]
// configured that is the replica, so a replica that goes down must fail the check.
func TestDatabaseReadPoolCheck_SeesTheReplica(t *testing.T) {
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	replica := startKillableProxy(t, "localhost:5432")
	host, port, _ := net.SplitHostPort(replica.addr)
	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name},
		Read:  &config.DatabaseEndpointConfig{Hosts: []string{host}, Port: port, User: "postgres", Name: name},
	}
	ctx := context.Background()
	rdb, err := resilient.NewResilientDatabase(ctx, cfg, false, false)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer rdb.Close()

	hi := NewHealthIntegration(rdb)
	hi.registerStandardChecks()
	check := hi.monitor.checks["database_read_pool"]
	if check == nil {
		t.Fatal("database_read_pool check is not registered")
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := check.Check(checkCtx); err != nil {
		t.Fatalf("read pool check with the replica up: %v", err)
	}

	replica.Kill()
	checkCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	if err := check.Check(checkCtx2); err == nil {
		t.Fatal("database_read_pool reports healthy while the only read replica is down")
	}
}
