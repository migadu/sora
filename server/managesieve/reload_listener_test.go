package managesieve

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// startListenerTestServer builds a database-free server with opts, starts it and waits
// until its listener accepts.
func startListenerTestServer(t *testing.T, opts ManageSieveServerOptions) (*ManageSieveServer, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.InsecureAuth = true
	opts.Config = &config.Config{}
	srv, err := New(ctx, "reload", "localhost", addr, &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go srv.Start(errCh)
	t.Cleanup(srv.Close)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return srv, addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkedTimeoutsOfNewConnection connects and returns what the listener's timeout
// checker enforces on that connection.
func checkedTimeoutsOfNewConnection(t *testing.T, srv *ManageSieveServer, addr string) server.CheckedTimeouts {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for r := bufio.NewReader(c); ; {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	var conn net.Conn
	srv.activeSessionsMutex.RLock()
	for sess := range srv.activeSessions {
		if sess.conn.RemoteAddr().String() == c.LocalAddr().String() {
			conn = sess.conn
		}
	}
	srv.activeSessionsMutex.RUnlock()
	if conn == nil {
		t.Fatal("no session for the connection")
	}
	checked, ok := server.ConnCheckedTimeouts(conn)
	if !ok {
		t.Fatal("no SoraConn under the session's connection")
	}
	return checked
}

// The listener's timeout checker keeps only the throughput check (the library owns the
// timeouts); a reloaded min_bytes_per_minute must reach the connections accepted after.
func TestReloadConfig_MinBytesPerMinuteReachesNewConnections(t *testing.T) {
	srv, addr := startListenerTestServer(t, ManageSieveServerOptions{})
	if cc := srv.connConfig(); cc.EnableTimeoutChecker {
		t.Fatalf("checker enabled without min_bytes_per_minute: %+v", cc)
	}

	if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "managesieve", Timeouts: &config.ServerTimeoutsConfig{MinBytesPerMinute: 1024}}); err != nil {
		t.Fatal(err)
	}
	if cc := srv.connConfig(); !cc.EnableTimeoutChecker || cc.MinBytesPerMinute != 1024 {
		t.Fatalf("after reloading min_bytes_per_minute = 1024: checker %v, min %d", cc.EnableTimeoutChecker, cc.MinBytesPerMinute)
	}

	// What the listener gave the next connection is what its checker enforces.
	checked := checkedTimeoutsOfNewConnection(t, srv, addr)
	if checked.MinBytesPerMinute != 1024 {
		t.Errorf("connection accepted after the reload: checked %+v, want min_bytes_per_minute 1024", checked)
	}
	if checked.Absolute != 0 {
		t.Errorf("connection accepted after the reload: the checker enforces a %v session limit; go-managesieve owns absolute_session_timeout", checked.Absolute)
	}
}

// With min_bytes_per_minute set, the checker is there for the throughput check alone.
// It used to enforce NewSoraConn's 30m default as a session limit too, so every
// ManageSieve session ended at 30 minutes whatever absolute_session_timeout said (#138).
func TestThroughputCheckerEnforcesNoSessionLimit(t *testing.T) {
	srv, addr := startListenerTestServer(t, ManageSieveServerOptions{AbsoluteSessionTimeout: 24 * time.Hour, MinBytesPerMinute: 512})

	checked := checkedTimeoutsOfNewConnection(t, srv, addr)
	if checked.MinBytesPerMinute != 512 {
		t.Errorf("checked %+v, want min_bytes_per_minute 512", checked)
	}
	if checked.Absolute != 0 || checked.Idle != 0 {
		t.Errorf("the checker enforces a %v session limit and a %v idle limit; go-managesieve owns both (absolute_session_timeout is 24h here)", checked.Absolute, checked.Idle)
	}
}
