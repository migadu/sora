package pop3proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

func newPOP3TestConnManager(t *testing.T, addr string, connectTimeout time.Duration) *proxy.ConnectionManager {
	t.Helper()
	cm, err := proxy.NewConnectionManager([]string{addr}, 110, false, false, false, connectTimeout)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	return cm
}

// TestConnectToBackendNoGreetingTimesOut verifies that a backend which accepts
// TCP but never sends its greeting fails within roughly the connect timeout
// and is classified as a backend error. Regression test for proxy review P2
// (2026-07-03): the greeting read had no deadline and used unbounded
// ReadString, hanging authentication indefinitely.
func TestConnectToBackendNoGreetingTimesOut(t *testing.T) {
	// Backend that accepts connections but never speaks
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	var held []net.Conn
	defer func() {
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
			held = append(held, c) // hold, never write
		}
	}()

	srv := &POP3ProxyServer{
		name:        "test",
		hostname:    "test-host",
		connManager: newPOP3TestConnManager(t, ln.Addr().String(), 500*time.Millisecond),
	}

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	sess := &POP3ProxySession{
		server:     srv,
		clientConn: clientA,
		ctx:        context.Background(),
	}

	start := time.Now()
	err = sess.connectToBackend()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("connectToBackend succeeded against a silent backend")
	}
	if elapsed > 5*time.Second {
		t.Errorf("connectToBackend took %v against a silent backend; must fail within ~connect timeout (before the P2 fix it hung forever)", elapsed)
	}
	if !server.IsBackendError(err) {
		t.Errorf("silent-backend error not classified as backend error (client would see 'Authentication failed'): %v", err)
	}
}

// TestConnectToBackendDialRefusedIsBackendError verifies that dial failures
// carry the ErrBackendConnectionFailed sentinel. Regression test for proxy
// review P1 (2026-07-03): without the sentinel, IsBackendError missed them
// and the client got "-ERR Authentication failed" for a backend outage.
func TestConnectToBackendDialRefusedIsBackendError(t *testing.T) {
	// Grab a port with nothing listening: listen, note the address, close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := &POP3ProxyServer{
		name:        "test",
		hostname:    "test-host",
		connManager: newPOP3TestConnManager(t, addr, 500*time.Millisecond),
	}

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	sess := &POP3ProxySession{
		server:     srv,
		clientConn: clientA,
		ctx:        context.Background(),
	}

	err = sess.connectToBackend()
	if err == nil {
		t.Fatal("connectToBackend succeeded against a closed port")
	}
	if !server.IsBackendError(err) {
		t.Errorf("dial-refused error not classified as backend error (client would see 'Authentication failed'): %v", err)
	}
}
