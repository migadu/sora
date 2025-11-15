package imapproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestConnectionTrackerCleanup verifies that connections are properly unregistered
// from the connection tracker even when errors occur.
func TestConnectionTrackerCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a mock connection tracker
	tracker := server.NewConnectionTracker("test-imap", "instance-1", nil, 0, 0, 1000)
	defer tracker.Stop()

	// Create a minimal server instance with connection tracker
	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connTracker:    tracker,
	}

	t.Run("normal_flow_registers_and_unregisters", func(t *testing.T) {
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 123
		session.username = "test@example.com"
		session.startTime = time.Now()

		// Register connection
		clientAddr := "127.0.0.1:12345"
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Verify it's registered
		count := tracker.GetConnectionCount(session.accountID)
		if count != 1 {
			t.Errorf("Expected 1 connection, got %d", count)
		}

		// Unregister (simulating close())
		err = tracker.UnregisterConnection(ctx, session.accountID, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to unregister connection: %v", err)
		}

		// Verify it's unregistered
		count = tracker.GetConnectionCount(session.accountID)
		if count != 0 {
			t.Errorf("Expected 0 connections after unregister, got %d", count)
		}
	})

	t.Run("async_unregister_failure_silently_ignored", func(t *testing.T) {
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 456
		session.username = "test2@example.com"
		session.startTime = time.Now()

		clientAddr := "127.0.0.1:12346"

		// Register connection
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Verify it's registered
		count := tracker.GetConnectionCount(session.accountID)
		if count != 1 {
			t.Errorf("Expected 1 connection, got %d", count)
		}

		// Simulate close() with a cancelled context (async unregister with short timeout)
		// This simulates the scenario where unregister fails due to context cancellation
		cancelledCtx, cancelFunc := context.WithCancel(context.Background())
		cancelFunc() // Cancel immediately

		// This should fail silently (as per the code in close())
		err = tracker.UnregisterConnection(cancelledCtx, session.accountID, "IMAP", clientAddr)
		// Error is expected but ignored in production code

		// Connection might still be registered if the unregister failed
		count = tracker.GetConnectionCount(session.accountID)

		if count > 0 {
			t.Logf("⚠️  Connection still registered after failed async unregister: count=%d", count)
			t.Logf("This is expected behavior - unregister errors are logged but don't block cleanup")
			t.Logf("The connection will be cleaned up by the periodic cleanup routine")
		}

		// Clean up manually for this test
		validCtx := context.Background()
		tracker.UnregisterConnection(validCtx, session.accountID, "IMAP", clientAddr)
	})

	t.Run("no_leak_when_registerConnection_fails", func(t *testing.T) {
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 789
		session.username = "test3@example.com"
		session.startTime = time.Now()

		clientAddr := "127.0.0.1:12347"

		// Register connection
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Simulate scenario where postAuthenticationSetup() registers connection
		// but then fails before startProxy() is called

		// In this case, close() should still be called (via defer in handleConnection)
		// and should unregister the connection

		count := tracker.GetConnectionCount(session.accountID)
		if count != 1 {
			t.Errorf("Expected 1 connection before cleanup, got %d", count)
		}

		// Simulate close() being called
		session.close()

		// Give async unregister time to complete
		time.Sleep(100 * time.Millisecond)

		// Verify connection was unregistered
		count = tracker.GetConnectionCount(session.accountID)
		if count != 0 {
			t.Errorf("MEMORY LEAK: Connection not unregistered after close(), count=%d", count)
			t.Errorf("Expected: 0 connections")
			t.Errorf("Actual: %d connections", count)
		} else {
			t.Logf("✓ No leak: Connection properly unregistered via close()")
		}
	})

	t.Run("multiple_register_before_unregister", func(t *testing.T) {
		// This tests the scenario where registerConnection() might be called
		// multiple times due to reconnections, but unregister only happens once

		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 999
		session.username = "test4@example.com"
		session.startTime = time.Now()

		clientAddr := "127.0.0.1:12348"

		// Register connection twice (simulating a bug or race condition)
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection (1st time): %v", err)
		}

		err = tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection (2nd time): %v", err)
		}

		// Count should be 2 (double registered)
		count := tracker.GetConnectionCount(session.accountID)
		if count != 2 {
			t.Errorf("Expected 2 connections after double register, got %d", count)
		}

		// Unregister once (simulating close())
		err = tracker.UnregisterConnection(ctx, session.accountID, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to unregister connection: %v", err)
		}

		// Count should be 1 (one left)
		count = tracker.GetConnectionCount(session.accountID)
		if count != 1 {
			t.Errorf("Expected 1 connection after single unregister, got %d", count)
		}

		// This is a leak scenario - the second registration is never unregistered
		if count > 0 {
			t.Logf("⚠️  POTENTIAL LEAK: Double registration with single unregister leaves count=%d", count)
			t.Logf("This could happen if registerConnection() is called multiple times")
			t.Logf("but close() only calls UnregisterConnection() once")
		}

		// Clean up
		tracker.UnregisterConnection(ctx, session.accountID, "IMAP", clientAddr)
	})
}

// TestConnectionTrackerAsyncUnregisterReliability tests the reliability of async unregister
func TestConnectionTrackerAsyncUnregisterReliability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a mock connection tracker
	tracker := server.NewConnectionTracker("test-imap", "instance-1", nil, 0, 0, 1000)
	defer tracker.Stop()

	// Create a minimal server instance with connection tracker
	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connTracker:    tracker,
	}

	t.Run("async_unregister_with_server_shutdown", func(t *testing.T) {
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 777
		session.username = "shutdown@example.com"
		session.startTime = time.Now()

		clientAddr := "127.0.0.1:55555"

		// Register connection
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Verify registered
		countBefore := tracker.GetConnectionCount(session.accountID)
		if countBefore != 1 {
			t.Errorf("Expected 1 connection, got %d", countBefore)
		}

		// Simulate server shutdown (cancel main context)
		// The close() method uses a NEW background context, so this shouldn't affect unregister
		cancel()

		// Call close() - should still unregister despite server shutdown
		session.close()

		// Give async unregister time to complete
		time.Sleep(300 * time.Millisecond)

		// Verify unregistered
		countAfter := tracker.GetConnectionCount(session.accountID)
		if countAfter != 0 {
			t.Errorf("LEAK DETECTED: Connection not unregistered after server shutdown")
			t.Errorf("Expected: 0 connections")
			t.Errorf("Actual: %d connections", countAfter)
			t.Errorf("The async unregister should use background context, not session context")
		} else {
			t.Logf("✓ Async unregister works even during server shutdown")
		}
	})

	t.Run("rapid_close_calls_are_idempotent", func(t *testing.T) {
		mockClient, _ := net.Pipe()
		defer mockClient.Close()

		session := newSession(server, mockClient)
		session.accountID = 888
		session.username = "rapid@example.com"
		session.startTime = time.Now()

		clientAddr := "127.0.0.1:56666"

		// Register connection
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Call close() multiple times (simulating race condition)
		// This should not cause multiple unregisters or panics
		for i := 0; i < 5; i++ {
			session.close()
		}

		// Give async unregister time to complete
		time.Sleep(300 * time.Millisecond)

		// Verify only unregistered once
		countAfter := tracker.GetConnectionCount(session.accountID)
		if countAfter < 0 {
			t.Errorf("BUG: Negative connection count: %d", countAfter)
		} else if countAfter == 0 {
			t.Logf("✓ Multiple close() calls are safe and idempotent")
		} else {
			t.Errorf("LEAK: Expected 0 connections, got %d", countAfter)
		}
	})
}

// TestConnectionTrackerWithRealSession tests connection tracking with actual session lifecycle
func TestConnectionTrackerWithRealSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a mock connection tracker
	tracker := server.NewConnectionTracker("test-imap", "instance-1", nil, 0, 0, 1000)
	defer tracker.Stop()

	// Create a minimal server instance with connection tracker
	server := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		connTracker:    tracker,
	}

	t.Run("session_lifecycle_cleanup", func(t *testing.T) {
		mockClient, _ := net.Pipe()

		session := newSession(server, mockClient)
		session.accountID = 555
		session.username = "lifecycle@example.com"
		session.startTime = time.Now()

		// Register connection (simulating postAuthenticationSetup)
		clientAddr := "127.0.0.1:54321"
		err := tracker.RegisterConnection(ctx, session.accountID, session.username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Verify registered
		countBefore := tracker.GetConnectionCount(session.accountID)
		if countBefore != 1 {
			t.Errorf("Expected 1 connection after register, got %d", countBefore)
		}

		// Simulate session close (this is what handleConnection's defer does)
		session.close()

		// Give async unregister time to complete
		time.Sleep(200 * time.Millisecond)

		// Verify unregistered
		countAfter := tracker.GetConnectionCount(session.accountID)
		if countAfter != 0 {
			t.Errorf("LEAK DETECTED: Expected 0 connections after close(), got %d", countAfter)
			t.Errorf("The async unregister in close() may have failed")
		} else {
			t.Logf("✓ Session lifecycle cleanup works correctly")
		}
	})
}
