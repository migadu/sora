package imapproxy

import (
	"context"
	"net"
	"testing"

	"github.com/migadu/sora/server"
)

// TestCloseSkipsUnregisterWhenRejected verifies that a session whose
// connection-tracker registration was REJECTED does not unregister on close.
// Regression test for the limit-erosion half of proxy review M5 (2026-07-03):
// close() used to unconditionally call UnregisterConnection, decrementing a
// slot the rejected session never held and freeing capacity belonging to
// another session of the same account.
func TestCloseSkipsUnregisterWhenRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracker := server.NewConnectionTracker("test-imap", "", "", "instance-1", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connTracker:    tracker,
	}

	// Another session of the same account holds a registered slot.
	clientAddr := "192.0.2.1:1234"
	if err := tracker.RegisterConnection(ctx, 42, "user@example.com", "IMAP", clientAddr); err != nil {
		t.Fatalf("failed to register baseline connection: %v", err)
	}

	client, _ := net.Pipe()
	defer client.Close()

	sess := newSession(srv, client)
	sess.accountID = 42
	sess.clientAddr = clientAddr
	sess.connRejected = true // this session's registration was rejected

	sess.close()

	if count := tracker.GetConnectionCount(42); count != 1 {
		t.Errorf("connection count = %d after rejected session close, want 1 (slot of the OTHER session must survive)", count)
	}

	// Cleanup baseline registration
	_ = tracker.UnregisterConnection(ctx, 42, "IMAP", clientAddr)
}
