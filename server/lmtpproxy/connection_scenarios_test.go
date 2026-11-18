//go:build integration
// +build integration

package lmtpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// connectSession is a session that has its first recipient and is about to connect to
// the backend at addr, as handleRecipient leaves it.
func connectSession(t *testing.T, addr string, connectTimeout time.Duration) *Session {
	t.Helper()
	srv := &Server{
		name:        "test",
		hostname:    "test-host",
		connManager: newLMTPTestConnManager(t, addr, connectTimeout),
	}
	clientA, clientB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close() })
	return &Session{
		server:          srv,
		clientConn:      clientA,
		originalAddress: "user@example.com",
		ctx:             context.Background(),
	}
}

// serveOneBackend accepts one connection on a new listener and runs serve on it.
func serveOneBackend(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()
	return ln.Addr().String()
}

// TestBackendClosesConnectionCleanly and TestBackendClosesConnectionAbruptly: a
// backend that greets and then closes its connection, with a FIN or with a RST, fails
// connectToBackend at once, not at the connect timeout, and the session keeps no
// backend connection (the next recipient connects afresh, #1186).
func TestBackendClosesConnectionCleanly(t *testing.T) {
	testBackendClosesAfterGreeting(t, false)
}

func TestBackendClosesConnectionAbruptly(t *testing.T) {
	testBackendClosesAfterGreeting(t, true)
}

func testBackendClosesAfterGreeting(t *testing.T, reset bool) {
	expectGoroutinesExit(t)
	const connectTimeout = 30 * time.Second
	addr := serveOneBackend(t, func(conn net.Conn) {
		io.WriteString(conn, "220 backend.example.com LMTP Service Ready\r\n")
		if reset {
			conn.(*net.TCPConn).SetLinger(0) // Close sends RST
		}
	})
	sess := connectSession(t, addr, connectTimeout)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- sess.connectToBackend() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connectToBackend succeeded against a backend that closed after its greeting")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("connectToBackend took %v to notice the closed connection (connect timeout %v)", elapsed, connectTimeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("connectToBackend still waiting 10s after the backend closed its connection")
	}
	sess.mu.Lock()
	held := sess.backendConn != nil
	sess.mu.Unlock()
	if held {
		t.Error("the session still holds the closed backend connection")
	}
}

// TestBackendSlowButResponding: the connect timeout bounds each handshake reply, not
// the handshake as a whole. A backend that takes most of the connect timeout for its
// greeting and again for its LHLO reply is still connected to.
func TestBackendSlowButResponding(t *testing.T) {
	expectGoroutinesExit(t)
	const connectTimeout, delay = time.Second, 700 * time.Millisecond
	addr := serveOneBackend(t, func(conn net.Conn) {
		time.Sleep(delay)
		io.WriteString(conn, "220 backend.example.com LMTP Service Ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.ToUpper(line), "LHLO") {
				time.Sleep(delay)
				io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
			}
		}
	})
	sess := connectSession(t, addr, connectTimeout)

	start := time.Now()
	if err := sess.connectToBackend(); err != nil {
		t.Fatalf("connectToBackend failed against a slow but responding backend after %v: %v", time.Since(start), err)
	}
	if elapsed := time.Since(start); elapsed < 2*delay {
		t.Fatalf("precondition: the handshake took %v, less than the backend's two delays (%v)", elapsed, 2*delay)
	}
	sess.mu.Lock()
	backend := sess.backendConn
	sess.mu.Unlock()
	if backend != nil {
		backend.Close()
	}
}

// TestBackendStopsResponding: a backend that sends its greeting and then goes silent
// (it reads LHLO but never answers) must fail connectToBackend within about the
// connect timeout, which readBackendLine applies to every handshake reply. A backend
// silent from the start is TestConnectToBackendSilentBackendTimesOut.
func TestBackendStopsResponding(t *testing.T) {
	expectGoroutinesExit(t)
	const connectTimeout = 500 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	gotLHLO := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "220 backend.example.com LMTP Service Ready\r\n")
		r := bufio.NewReader(conn)
		if line, err := r.ReadString('\n'); err == nil && strings.HasPrefix(strings.ToUpper(line), "LHLO") {
			gotLHLO <- struct{}{}
		}
		io.Copy(io.Discard, r) // silent until the proxy closes
	}()

	sess := connectSession(t, ln.Addr().String(), connectTimeout)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- sess.connectToBackend() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connectToBackend succeeded against a backend that never answers LHLO")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("connectToBackend took %v; must fail within about the connect timeout %v", elapsed, connectTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connectToBackend hung on a backend that went silent after its greeting")
	}
	select {
	case <-gotLHLO:
	default:
		t.Error("precondition: the backend never received LHLO, so the silence was not after the greeting")
	}
}
