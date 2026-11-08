package pop3

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	serverPkg "github.com/migadu/sora/server"
)

// The listener's timeout checker keeps only the throughput check (the library owns the
// timeouts); a reloaded min_bytes_per_minute must reach the connections accepted after.
func TestReloadConfig_MinBytesPerMinuteReachesNewConnections(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Second})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
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

	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", Type: "pop3", Timeouts: &config.ServerTimeoutsConfig{MinBytesPerMinute: 1024}}); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var conn net.Conn
	s.activeSessionsMutex.RLock()
	for sess := range s.activeSessions {
		if sess.conn.RemoteAddr().String() == c.LocalAddr().String() {
			conn = sess.conn
		}
	}
	s.activeSessionsMutex.RUnlock()
	if conn == nil {
		t.Fatal("no session for the connection")
	}
	if checked, ok := serverPkg.ConnCheckedTimeouts(conn); !ok || checked.MinBytesPerMinute != 1024 {
		t.Errorf("connection accepted after the reload: checked %+v (found %v), want min_bytes_per_minute 1024", checked, ok)
	}
}
