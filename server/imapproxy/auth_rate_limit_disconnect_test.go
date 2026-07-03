package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestRateLimitedLoginDisconnects verifies that when the rate limiter blocks
// an attempt (BYE-typed error), the proxy sends the BYE and DROPS the
// connection. Regression test for proxy review M1 (2026-07-03): the handlers
// used to reply "NO Authentication failed" and keep the connection open,
// letting a blocked client hammer indefinitely. The nil lookupCache here also
// exercises the H1 fix (auth used to panic with the cache disabled).
func TestRateLimitedLoginDisconnects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connManager:    newTestConnManager(t, "127.0.0.1:1"),
		lookupCache:    nil, // disabled — exercises the H1 nil-safety fix too
		authLimiter: &fakeAuthLimiter{canErr: &server.RateLimitError{
			Reason:       "ip_blocked",
			IP:           "192.0.2.1",
			FailureCount: 99,
			BlockedUntil: time.Now().Add(time.Minute),
		}},
		insecureAuth:    true,
		maxAuthErrors:   3,
		authIdleTimeout: 5 * time.Second,
	}

	client, remote := net.Pipe()
	defer remote.Close()

	sess := newSession(srv, client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()

	reader := bufio.NewReader(remote)
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	if _, err := remote.Write([]byte("a1 LOGIN user@example.com secret\r\n")); err != nil {
		t.Fatalf("failed to send LOGIN: %v", err)
	}

	// Tagged NO first
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read LOGIN response: %v", err)
	}
	if !strings.HasPrefix(resp, "a1 NO") {
		t.Fatalf("expected tagged NO, got %q", strings.TrimSpace(resp))
	}

	// Then the BYE
	bye, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read BYE: %v", err)
	}
	if !strings.HasPrefix(bye, "* BYE") {
		t.Errorf("expected * BYE after rate-limited LOGIN, got %q", strings.TrimSpace(bye))
	}

	// And the connection must be closed (before the M1 fix the loop continued)
	select {
	case <-done:
		// handleConnection returned - connection dropped as required
	case <-time.After(5 * time.Second):
		t.Error("connection still open after rate-limited LOGIN; proxy must disconnect")
	}
}
