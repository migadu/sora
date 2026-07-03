package managesieveproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestMSCloseSkipsUnregisterWhenRejected verifies that a session whose
// connection-tracker registration was REJECTED does not unregister on close.
// Regression test for the limit-erosion half of proxy review MS4 (2026-07-03):
// close() used to unconditionally call UnregisterConnection, decrementing a
// slot the rejected session never held and freeing capacity belonging to
// another session of the same account.
func TestMSCloseSkipsUnregisterWhenRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracker := server.NewConnectionTracker("test-managesieve", "", "", "instance-1", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		connTracker:    tracker,
		activeSessions: make(map[*Session]struct{}),
	}

	// Another session of the same account holds a registered slot.
	clientAddr := "192.0.2.1:1234"
	if err := tracker.RegisterConnection(ctx, 42, "user@example.com", "ManageSieve", clientAddr); err != nil {
		t.Fatalf("failed to register baseline connection: %v", err)
	}

	clientA, clientB := net.Pipe()
	defer clientB.Close()

	sess := &Session{
		server:       srv,
		clientConn:   clientA,
		ctx:          ctx,
		accountID:    42,
		clientAddr:   clientAddr,
		startTime:    time.Now(),
		connRejected: true, // this session's registration was rejected
	}

	sess.close()

	if count := tracker.GetConnectionCount(42); count != 1 {
		t.Errorf("connection count = %d after rejected session close, want 1 (slot of the OTHER session must survive)", count)
	}

	_ = tracker.UnregisterConnection(ctx, 42, "ManageSieve", clientAddr)
}
