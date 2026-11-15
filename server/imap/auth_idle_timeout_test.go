package imap

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// auth_idle_timeout closes a connection that has not authenticated after that
// long without a command. The deadline sora set once was replaced by go-imap's
// own 30 seconds before the first command, so the setting had no effect (#331).
func TestAuthIdleTimeoutClosesIdleUnauthenticatedConnection(t *testing.T) {
	srv, addr := newReloadTestServer(t, IMAPServerOptions{AuthIdleTimeout: 300 * time.Millisecond})
	serveReloadTestServer(t, srv, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if greeting, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q, %v", greeting, err)
	}

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadString('\n')
	if !errors.Is(err, io.EOF) {
		t.Fatalf("idle unauthenticated connection with auth_idle_timeout = 300ms: read %q, %v; want the server to close it", line, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("closed after %v, want about 300ms", elapsed)
	}
}
