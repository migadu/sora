package pop3

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	serverPkg "github.com/migadu/sora/server"
)

// startListenerTestServer starts s and waits until its listener accepts.
func startListenerTestServer(t *testing.T, s *POP3Server, addr string) {
	t.Helper()
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkedTimeoutsOfNewConnection connects and returns what the listener's timeout
// checker enforces on that connection.
func checkedTimeoutsOfNewConnection(t *testing.T, s *POP3Server, addr string) serverPkg.CheckedTimeouts {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
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
	checked, ok := serverPkg.ConnCheckedTimeouts(conn)
	if !ok {
		t.Fatal("no SoraConn under the session's connection")
	}
	return checked
}

// The listener's timeout checker keeps only the throughput check (the library owns the
// timeouts); a reloaded min_bytes_per_minute must reach the connections accepted after.
func TestReloadConfig_MinBytesPerMinuteReachesNewConnections(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Second})
	startListenerTestServer(t, s, addr)

	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", Type: "pop3", Timeouts: &config.ServerTimeoutsConfig{MinBytesPerMinute: 1024}}); err != nil {
		t.Fatal(err)
	}

	checked := checkedTimeoutsOfNewConnection(t, s, addr)
	if checked.MinBytesPerMinute != 1024 {
		t.Errorf("connection accepted after the reload: checked %+v, want min_bytes_per_minute 1024", checked)
	}
	if checked.Absolute != 0 {
		t.Errorf("connection accepted after the reload: the checker enforces a %v session limit; go-pop3 owns absolute_session_timeout", checked.Absolute)
	}
}

// With min_bytes_per_minute set, the checker is there for the throughput check alone.
// It used to enforce NewSoraConn's 30m default as a session limit too, so every POP3
// session ended at 30 minutes whatever absolute_session_timeout said (#138).
func TestThroughputCheckerEnforcesNoSessionLimit(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Second, AbsoluteSessionTimeout: 24 * time.Hour, MinBytesPerMinute: 512})
	startListenerTestServer(t, s, addr)

	checked := checkedTimeoutsOfNewConnection(t, s, addr)
	if checked.MinBytesPerMinute != 512 {
		t.Errorf("checked %+v, want min_bytes_per_minute 512", checked)
	}
	if checked.Absolute != 0 || checked.Idle != 0 {
		t.Errorf("the checker enforces a %v session limit and a %v idle limit; go-pop3 owns both (absolute_session_timeout is 24h here)", checked.Absolute, checked.Idle)
	}
}
