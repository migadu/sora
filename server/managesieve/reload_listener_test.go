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

// The listener's timeout checker keeps only the throughput check (the library owns the
// timeouts); a reloaded min_bytes_per_minute must reach the connections accepted after.
func TestReloadConfig_MinBytesPerMinuteReachesNewConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, "reload", "localhost", addr, &resilient.ResilientDatabase{}, ManageSieveServerOptions{InsecureAuth: true, Config: &config.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	if cc := srv.connConfig(); cc.EnableTimeoutChecker {
		t.Fatalf("checker enabled without min_bytes_per_minute: %+v", cc)
	}
	errCh := make(chan error, 1)
	go srv.Start(errCh)
	t.Cleanup(srv.Close)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "managesieve", Timeouts: &config.ServerTimeoutsConfig{MinBytesPerMinute: 1024}}); err != nil {
		t.Fatal(err)
	}
	if cc := srv.connConfig(); !cc.EnableTimeoutChecker || cc.MinBytesPerMinute != 1024 {
		t.Fatalf("after reloading min_bytes_per_minute = 1024: checker %v, min %d", cc.EnableTimeoutChecker, cc.MinBytesPerMinute)
	}

	// What the listener gave the next connection is what its checker enforces.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
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
	if checked, ok := server.ConnCheckedTimeouts(conn); !ok || checked.MinBytesPerMinute != 1024 {
		t.Errorf("connection accepted after the reload: checked %+v (found %v), want min_bytes_per_minute 1024", checked, ok)
	}
}
