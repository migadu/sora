package lmtpproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestCloseDoesNotUnregisterUnregisteredAccount verifies that close() only
// unregisters connections this session actually registered. Regression test
// for the LMTP proxy review (2026-07-03): close() had a fallback that
// unregistered s.accountID when registeredAccountIDs was empty. handleRecipient
// sets s.accountID even when registerConnection was never called (e.g. the
// backend connect failed), so the fallback decremented connection counts
// belonging to the user's OTHER live sessions, eroding per-user limits.
func TestCloseDoesNotUnregisterUnregisteredAccount(t *testing.T) {
	tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	const accountID = int64(42)
	const clientIP = "192.0.2.10"

	// Baseline: another live session of the same user, from the same client IP,
	// registered directly on the tracker.
	ctx := context.Background()
	if err := tracker.RegisterConnection(ctx, accountID, "user@example.com", "LMTP", clientIP+":1111"); err != nil {
		t.Fatalf("failed to register baseline connection: %v", err)
	}
	if got := tracker.GetLocalConnectionCount(accountID); got != 1 {
		t.Fatalf("expected baseline count 1, got %d", got)
	}

	// A session whose recipient lookup succeeded (accountID set) but whose
	// backend connect failed, so registerConnection was never called.
	clientConn, _ := net.Pipe()
	defer clientConn.Close()
	sess := &Session{
		server:               &Server{connTracker: tracker},
		clientConn:           clientConn,
		clientAddr:           clientIP + ":2222",
		accountID:            accountID,
		ctx:                  context.Background(),
		startTime:            time.Now(),
		registeredAccountIDs: make(map[int64]struct{}), // nothing registered
	}

	sess.close()

	if got := tracker.GetLocalConnectionCount(accountID); got != 1 {
		t.Fatalf("close() eroded the connection count: expected 1 (baseline session still live), got %d", got)
	}
}
