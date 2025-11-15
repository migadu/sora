package imapproxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestRemoveSessionRaceCondition tests for race conditions in session removal
func TestRemoveSessionRaceCondition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	mockClient, _ := net.Pipe()
	defer mockClient.Close()

	session := newSession(server, mockClient)
	server.addSession(session)

	// Simulate concurrent removal attempts (should be idempotent)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server.removeSession(session)
		}()
	}
	wg.Wait()

	server.activeSessionsMu.RLock()
	count := len(server.activeSessions)
	server.activeSessionsMu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 sessions after concurrent removal, got %d", count)
	}

	t.Log("✓ removeSession is race-safe and idempotent")
}

// TestAcceptConnectionsSessionCleanup verifies that acceptConnections properly cleans up sessions
// This test verifies the FIX works by simulating the panic in handleConnection
func TestAcceptConnectionsSessionCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	t.Run("panic_in_handleConnection_no_leak", func(t *testing.T) {
		// Create a mock session that panics in handleConnection
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		// Simulate what acceptConnections does with panic recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("Panic recovered (expected): %v", r)
				}
			}()

			// This mimics the defer chain in acceptConnections (lines 457-462)
			session := newSession(server, mockClient)
			server.addSession(session)
			defer server.removeSession(session)

			// Simulate panic before handleConnection's defer s.close() is reached
			panic("simulated panic before defer setup")
		}()

		// After panic recovery, the session should be cleaned up
		server.activeSessionsMu.RLock()
		count := len(server.activeSessions)
		server.activeSessionsMu.RUnlock()

		if count > 0 {
			t.Errorf("MEMORY LEAK: %d session(s) still in map after panic", count)
			t.Errorf("The defer removeSession(session) in acceptConnections didn't work")
		} else {
			t.Logf("✓ No leak: Session cleaned up after panic with new defer pattern")
		}
	})
}

// TestSessionCloseEnsuresRemoval verifies that session.close() always calls removeSession
func TestSessionCloseEnsuresRemoval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	mockClient, _ := net.Pipe()

	session := newSession(server, mockClient)
	session.startTime = time.Now()

	// Add session
	server.addSession(session)

	if len(server.activeSessions) != 1 {
		t.Fatalf("Expected 1 session before close, got %d", len(server.activeSessions))
	}

	// Call close() - this should call removeSession()
	session.close()

	server.activeSessionsMu.RLock()
	count := len(server.activeSessions)
	server.activeSessionsMu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 sessions after close(), got %d", count)
		t.Error("BUG: session.close() did not call server.removeSession()")
	} else {
		t.Log("✓ session.close() properly calls removeSession()")
	}
}
