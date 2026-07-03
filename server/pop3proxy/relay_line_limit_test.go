package pop3proxy

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRelayLineTooLong verifies that the post-auth relay rejects over-long
// command lines with -ERR and drops the connection. Regression test for proxy
// review P3 (2026-07-03): the relay used unbounded ReadString, letting an
// authenticated client grow memory without limit via a newline-less stream
// (RFC 1939 caps request lines at 512 octets).
func TestRelayLineTooLong(t *testing.T) {
	clientA, clientB := net.Pipe()
	backendA, backendB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	defer backendA.Close()
	defer backendB.Close()

	srv := &POP3ProxyServer{
		name:           "test",
		hostname:       "test-host",
		commandTimeout: 5 * time.Second,
	}

	sess := &POP3ProxySession{
		server:       srv,
		clientConn:   clientA,
		clientReader: bufio.NewReader(clientA),
		backendConn:  backendA,
		ctx:          context.Background(),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.filteredCopyClientToBackend()
	}()

	// A single 8 KiB line (over the 4 KiB relay bound), terminated so the
	// bounded reader's drain completes.
	go func() {
		line := append(bytes.Repeat([]byte("A"), 8192), '\r', '\n')
		_, _ = clientB.Write(line)
	}()

	_ = clientB.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := bufio.NewReader(clientB).ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read relay error response: %v", err)
	}
	if !strings.HasPrefix(resp, "-ERR Line too long") {
		t.Errorf("expected -ERR Line too long, got %q", strings.TrimSpace(resp))
	}

	select {
	case <-done:
		// Relay exited - connection dropped as required
	case <-time.After(5 * time.Second):
		t.Error("relay still running after over-long line")
	}
}
