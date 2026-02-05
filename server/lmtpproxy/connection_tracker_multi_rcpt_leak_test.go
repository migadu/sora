package lmtpproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
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
