package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestConnectionTracker_MultiRCPTDoesNotLeak verifies that an LMTP proxy session
// that processes multiple RCPT TO commands (possibly for different accounts)
// does not leak connection tracker counts.
//
// Regression: historically, the LMTP proxy registered the connection for the first
// recipient's accountID, but on close() it unregistered using s.accountID which is
// overwritten on each RCPT. This leaked the first recipient forever.
func TestConnectionTracker_MultiRCPTDoesNotLeak(t *testing.T) {
	tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	// Provide a real net.Conn so InfoLog/DebugLog (used by close()) can access RemoteAddr safely.
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	sess := &Session{
		server:     &Server{connTracker: tracker},
		clientConn: clientConn,
		// Use any stable address; tracker strips port anyway.
		clientAddr:           "192.0.2.10:12345",
		ctx:                  context.Background(),
		startTime:            time.Now(),
		registeredAccountIDs: make(map[int64]struct{}),
	}

	// registerConnection() falls back to a safe default timeout if s.server.rdb is nil.

	// Simulate first RCPT -> account 1
	sess.accountID = 1
	sess.username = "user1@example.com"
	if err := sess.registerConnection(); err != nil {
		t.Fatalf("registerConnection(1) failed: %v", err)
	}

	// Simulate second RCPT -> account 2 (s.accountID overwritten)
	sess.accountID = 2
	sess.username = "user2@example.com"
	if err := sess.registerConnection(); err != nil {
		t.Fatalf("registerConnection(2) failed: %v", err)
	}

	// Closing must unregister BOTH account IDs that were registered.
	sess.close()

	if got := tracker.GetLocalConnectionCount(1); got != 0 {
		t.Fatalf("leak: expected account 1 local count=0 after close(), got %d", got)
	}
	if got := tracker.GetLocalConnectionCount(2); got != 0 {
		t.Fatalf("expected account 2 local count=0 after close(), got %d", got)
	}
}

// TestConnectionTracker_BackendReconnectDoesNotLeak verifies that a session which
// opens a second backend connection for an account it already registered (the
// first one was lost, or dropped for maintenance, and a later RCPT TO for the
// same account reconnects) still counts as one connection and leaves nothing in
// the tracker after close().
//
// Regression (#903): every reconnect registered the account again, while the
// set of registered accounts remembered it once, so close() unregistered it
// once and one count per reconnect stayed until restart.
func TestConnectionTracker_BackendReconnectDoesNotLeak(t *testing.T) {
	tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	sess := &Session{
		server:               &Server{connTracker: tracker},
		clientConn:           clientConn,
		clientAddr:           "192.0.2.10:12345",
		ctx:                  context.Background(),
		startTime:            time.Now(),
		registeredAccountIDs: make(map[int64]struct{}),
		accountID:            1,
		username:             "user@example.com",
	}

	// First RCPT TO: connect to the backend and register.
	if err := sess.registerConnection(); err != nil {
		t.Fatalf("registerConnection (first backend) failed: %v", err)
	}
	// The backend connection is lost; the next RCPT TO for the same account
	// reconnects and registers again.
	sess.loseBackend()
	if err := sess.registerConnection(); err != nil {
		t.Fatalf("registerConnection (second backend) failed: %v", err)
	}

	if got := tracker.GetLocalConnectionCount(1); got != 1 {
		t.Errorf("one LMTP session must count as one connection, got %d", got)
	}

	sess.close()

	if got := tracker.GetLocalConnectionCount(1); got != 0 {
		t.Fatalf("leak: expected account 1 local count=0 after close(), got %d", got)
	}
}

// TestConnectionTracker_BackendRestartOnTheWire drives the real command loop of
// #903: one LMTP connection delivers to user@example.com, the backend restarts
// (it drops the connection on RSET), and the client's next MAIL FROM and RCPT TO
// for the same recipient make the proxy reconnect. The session must count once
// for the account while it lasts and leave nothing in the tracker after QUIT.
func TestConnectionTracker_BackendRestartOnTheWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var connections atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			id := connections.Add(1)
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.WriteString(conn, "220 backend ready\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if id == 1 && strings.HasPrefix(strings.ToUpper(line), "RSET") {
						return // the first backend connection is lost: a restart
					}
					io.WriteString(conn, "250 OK\r\n")
				}
			}()
		}
	}()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "reconnect", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24, ConnectTimeout: time.Second,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
	t.Cleanup(tracker.Stop)
	srv.SetConnectionTracker(tracker)
	account := proxy.DeriveAccountIDFromEmail("user@example.com")

	front, accepted := net.Pipe()
	t.Cleanup(func() { front.Close() })
	sess := newSession(srv, accepted, nil)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	front.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(front)
	read := func() string {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if len(line) < 4 || line[3] != '-' {
				return strings.TrimSpace(line)
			}
		}
	}
	require := func(line, prefix string) {
		t.Helper()
		if _, err := fmt.Fprintf(front, "%s\r\n", line); err != nil {
			t.Fatal(err)
		}
		if resp := read(); !strings.HasPrefix(resp, prefix) {
			t.Fatalf("%s: %s, want %s", line, resp, prefix)
		}
	}
	if greeting := read(); !strings.HasPrefix(greeting, "220") {
		t.Fatal(greeting)
	}
	require("LHLO client.example.com", "250")
	require("MAIL FROM:<sender@example.com>", "250")
	require("RCPT TO:<user@example.com>", "250")
	require("RSET", "250") // the backend drops the connection here
	require("MAIL FROM:<sender@example.com>", "250")
	require("RCPT TO:<user@example.com>", "250") // the proxy reconnects
	if n := connections.Load(); n != 2 {
		t.Fatalf("backend connections = %d, want 2 (the second RCPT must reconnect)", n)
	}
	if got := tracker.GetLocalConnectionCount(account); got != 1 {
		t.Errorf("one LMTP connection must count once for the account, got %d", got)
	}
	require("QUIT", "221")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish after QUIT")
	}
	if got := tracker.GetLocalConnectionCount(account); got != 0 {
		t.Fatalf("leak: account count after QUIT = %d, want 0", got)
	}
}
