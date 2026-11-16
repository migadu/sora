//go:build integration

package common

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
	soraserver "github.com/migadu/sora/server"
)

// DBOutage is a TCP relay between one ResilientDatabase and the test PostgreSQL. While
// an outage is on, every relayed connection is dropped and new ones are closed as soon
// as they are accepted, as when PostgreSQL goes down behind a pooler, or, during a
// stall, held open and never answered, as when it hangs; the other connections to the
// test database are not affected.
type DBOutage struct {
	ln     net.Listener
	target string

	mu    sync.Mutex
	down  bool
	stall bool
	conns map[net.Conn]struct{}
}

// SetupTestDatabaseWithOutage returns a ResilientDatabase on the test database that
// connects through a relay the returned DBOutage controls.
func SetupTestDatabaseWithOutage(t *testing.T) (*resilient.ResilientDatabase, *DBOutage) {
	t.Helper()

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("database relay listen: %v", err)
	}
	o := &DBOutage{ln: ln, target: "localhost:5432", conns: make(map[net.Conn]struct{})}
	go o.serve()

	cfg := &config.DatabaseConfig{
		// The timeout logins run into while the database stalls.
		WriteTimeout: "1s",
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{ln.Addr().String()},
			User:  "postgres",
			Name:  dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, false, true)
	if err != nil {
		o.close()
		t.Fatalf("Failed to set up test database through the relay: %v", err)
	}
	t.Cleanup(func() {
		rdb.Close()
		o.close()
	})
	return rdb, o
}

// Begin makes the database unreachable.
func (o *DBOutage) Begin() { o.begin(false) }

// Stall makes the database hang: it drops the relayed connections and leaves new ones
// unanswered, so every query runs into its timeout.
func (o *DBOutage) Stall() { o.begin(true) }

func (o *DBOutage) begin(stall bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.down = true
	o.stall = stall
	for c := range o.conns {
		c.Close()
		delete(o.conns, c)
	}
}

// End makes the database reachable again, and drops the connections a stall held.
func (o *DBOutage) End() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.down = false
	o.stall = false
	for c := range o.conns {
		c.Close()
		delete(o.conns, c)
	}
}

func (o *DBOutage) serve() {
	for {
		client, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.relay(client)
	}
}

func (o *DBOutage) relay(client net.Conn) {
	if o.hold(client) {
		return
	}
	if !o.track(client) {
		client.Close()
		return
	}
	defer o.untrackAndClose(client)
	upstream, err := net.DialTimeout("tcp", o.target, 5*time.Second)
	if err != nil {
		return
	}
	if !o.track(upstream) {
		upstream.Close()
		return
	}
	defer o.untrackAndClose(upstream)

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		upstream.Close()
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	client.Close()
	<-done
}

// hold keeps c open and unanswered during a stall (End drops it); it reports whether
// it did.
func (o *DBOutage) hold(c net.Conn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.down || !o.stall {
		return false
	}
	o.conns[c] = struct{}{}
	return true
}

// track registers c so Begin can drop it; it reports false during an outage.
func (o *DBOutage) track(c net.Conn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.down {
		return false
	}
	o.conns[c] = struct{}{}
	return true
}

func (o *DBOutage) untrackAndClose(c net.Conn) {
	o.mu.Lock()
	delete(o.conns, c)
	o.mu.Unlock()
	c.Close()
}

func (o *DBOutage) close() {
	o.ln.Close()
	o.Begin()
}

// DBOutageAuthRateLimit is an auth rate limit that blocks a user from an address after
// two failed logins (Tier 1 only, no IP blocks or delays): a test that logs in more
// often than that during a database outage, and then logs in after it, fails if the
// outage was counted as failed logins.
func DBOutageAuthRateLimit() soraserver.AuthRateLimiterConfig {
	return soraserver.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          time.Minute,
	}
}
