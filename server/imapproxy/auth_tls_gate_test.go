package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestAuthenticateRequiresTLS verifies that AUTHENTICATE PLAIN is gated on
// TLS/insecure_auth exactly like LOGIN. Regression test for proxy review L1
// (2026-07-03): the gate existed for LOGIN but was missing for AUTHENTICATE,
// so cleartext SASL PLAIN credentials were accepted where LOGIN would have
// been refused.
func TestAuthenticateRequiresTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:            "test",
		hostname:        "test-host",
		ctx:             ctx,
		cancel:          cancel,
		activeSessions:  make(map[*Session]struct{}),
		connManager:     newTestConnManager(t, "127.0.0.1:1"),
		authLimiter:     &fakeAuthLimiter{},
		insecureAuth:    false, // cleartext auth NOT permitted
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

	if _, err := remote.Write([]byte("a1 AUTHENTICATE PLAIN\r\n")); err != nil {
		t.Fatalf("failed to send AUTHENTICATE: %v", err)
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read AUTHENTICATE response: %v", err)
	}
	if !strings.HasPrefix(resp, "a1 NO [PRIVACYREQUIRED]") {
		t.Errorf("AUTHENTICATE over cleartext with insecure_auth=false: got %q, want a1 NO [PRIVACYREQUIRED] ... (before the L1 fix the proxy sent a continuation and accepted credentials)", strings.TrimSpace(resp))
	}

	remote.Close()
	<-done
}
