package lmtpproxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

func newLMTPTestConnManager(t *testing.T, addr string, connectTimeout time.Duration) *proxy.ConnectionManager {
	t.Helper()
	cm, err := proxy.NewConnectionManager([]string{addr}, 24, false, false, false, connectTimeout)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	return cm
}

// TestConnectToBackendSilentBackendTimesOut verifies that a backend which
// accepts TCP but never sends its LMTP greeting fails within roughly the
// connect timeout. Regression test for the LMTP proxy review (2026-07-03):
// the greeting/LHLO/STARTTLS/MAIL FROM reads in connectToBackend had no
// deadline and used unbounded ReadString, so a hung backend pinned the
// session goroutine forever (the ctx watchdog only closed the client conn).
func TestConnectToBackendSilentBackendTimesOut(t *testing.T) {
	// Backend that accepts connections but never speaks
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	var heldMu sync.Mutex
	var held []net.Conn
	defer func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, c := range held {
			c.Close()
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c) // hold, never write
			heldMu.Unlock()
		}
	}()

	srv := &Server{
		name:        "test",
		hostname:    "test-host",
		connManager: newLMTPTestConnManager(t, ln.Addr().String(), 500*time.Millisecond),
	}

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	sess := &Session{
		server:          srv,
		clientConn:      clientA,
		originalAddress: "user@example.com",
		ctx:             context.Background(),
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- sess.connectToBackend()
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("connectToBackend succeeded against a silent backend")
		}
		if elapsed > 5*time.Second {
			t.Errorf("connectToBackend took %v against a silent backend; must fail within ~connect timeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connectToBackend hung against a silent backend (before the fix this blocked forever)")
	}
}

// TestConnectToBackendBadGreetingRejected verifies that a backend answering
// with a non-220 greeting is rejected instead of the proxy proceeding with
// the LHLO handshake against a confused peer.
func TestConnectToBackendBadGreetingRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("554 no service\r\n"))
		// Keep the conn open briefly so the proxy sees the line, not a reset.
		time.Sleep(2 * time.Second)
	}()

	srv := &Server{
		name:        "test",
		hostname:    "test-host",
		connManager: newLMTPTestConnManager(t, ln.Addr().String(), time.Second),
	}

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	sess := &Session{
		server:          srv,
		clientConn:      clientA,
		originalAddress: "user@example.com",
		ctx:             context.Background(),
	}

	if err := sess.connectToBackend(); err == nil {
		t.Fatal("connectToBackend accepted a 554 greeting")
	}
}
