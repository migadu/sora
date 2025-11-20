//go:build integration

package lmtp

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
)

// TestLMTPBackendConnectionLimiterCounters tests that connection limiter counters
// are correctly incremented and decremented throughout the connection lifecycle.
// This test verifies the fix for the connection limiter leak bug where counters
// were stuck at maximum values because releaseConn() was only in goroutine defer
// and never executed when goroutines hung.
func TestLMTPBackendConnectionLimiterCounters(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Get the limiter to verify counter state
	server, ok := backendServer.Server.(*lmtp.LMTPServerBackend)
	if !ok {
		t.Fatalf("Failed to cast to LMTP server")
	}
	limiter := server.GetLimiter()
	if limiter == nil {
		t.Fatalf("Connection limiter is nil")
	}

	t.Log("=== Testing LMTP Backend Connection Limiter Counters ===")

	// Test 1: Verify initial state
	t.Log("\n--- Test 1: Initial state ---")
	stats := limiter.GetStats()
	if stats.TotalConnections != 0 {
		t.Errorf("Initial total connections should be 0, got %d", stats.TotalConnections)
	}
	t.Logf("✓ Initial total connections: %d", stats.TotalConnections)

	// Test 2: Single connection increment and decrement
	t.Log("\n--- Test 2: Single connection lifecycle ---")
	conn1, err := net.Dial("tcp", backendServer.Address)
	if err != nil {
		t.Fatalf("First connection failed: %v", err)
	}
	// Read greeting to keep connection alive
	buf := make([]byte, 1024)
	_, _ = conn1.Read(buf)
	time.Sleep(100 * time.Millisecond) // Allow counter to update

	stats = limiter.GetStats()
	if stats.TotalConnections != 1 {
		t.Errorf("After 1 connection, total should be 1, got %d", stats.TotalConnections)
	}
	t.Logf("✓ After connection: total=%d", stats.TotalConnections)

	// Close connection and verify decrement
	conn1.Close()
	time.Sleep(100 * time.Millisecond) // Allow cleanup to execute

	stats = limiter.GetStats()
	if stats.TotalConnections != 0 {
		t.Errorf("After closing 1 connection, total should be 0, got %d", stats.TotalConnections)
	}
	t.Logf("✓ After close: total=%d", stats.TotalConnections)

	// Test 3: Multiple connections increment and decrement
	t.Log("\n--- Test 3: Multiple connections lifecycle ---")
	var conns []net.Conn

	// Open 3 connections
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", backendServer.Address)
		if err != nil {
			t.Fatalf("Connection %d failed: %v", i+1, err)
		}
		// Read greeting to keep connection alive
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conns = append(conns, conn)
		time.Sleep(50 * time.Millisecond)
	}

	stats = limiter.GetStats()
	if stats.TotalConnections != 3 {
		t.Errorf("After 3 connections, total should be 3, got %d", stats.TotalConnections)
	}
	t.Logf("✓ After 3 connections: total=%d", stats.TotalConnections)

	// Close 2 connections, keep 1 open
	conns[0].Close()
	conns[1].Close()
	time.Sleep(100 * time.Millisecond)

	stats = limiter.GetStats()
	if stats.TotalConnections != 1 {
		t.Errorf("After closing 2 connections, total should be 1, got %d", stats.TotalConnections)
	}
	t.Logf("✓ After closing 2: total=%d", stats.TotalConnections)

	// Close the last connection
	conns[2].Close()
	time.Sleep(100 * time.Millisecond)

	stats = limiter.GetStats()
	if stats.TotalConnections != 0 {
		t.Errorf("After closing all connections, total should be 0, got %d", stats.TotalConnections)
	}
	t.Logf("✓ After closing all: total=%d", stats.TotalConnections)

	// Test 4: Per-IP counter tracking
	t.Log("\n--- Test 4: Per-IP counter tracking ---")
	conn2, err := net.Dial("tcp", backendServer.Address)
	if err != nil {
		t.Fatalf("Connection failed: %v", err)
	}
	// Read greeting to keep connection alive
	buf = make([]byte, 1024)
	_, _ = conn2.Read(buf)
	time.Sleep(100 * time.Millisecond)

	stats = limiter.GetStats()
	// Find the 127.0.0.1 entry in IPConnections
	localhostCount := int64(0)
	for ip, count := range stats.IPConnections {
		t.Logf("IP %s has %d connections", ip, count)
		if ip == "127.0.0.1" {
			localhostCount = count
		}
	}

	// Note: LMTP typically doesn't use per-IP limits (maxPerIP=0)
	// The limiter may be total-only
	t.Logf("✓ Per-IP count for localhost: %d (LMTP typically uses total-only limits)", localhostCount)

	conn2.Close()
	time.Sleep(100 * time.Millisecond)

	stats = limiter.GetStats()
	localhostCount = 0
	for ip, count := range stats.IPConnections {
		if ip == "127.0.0.1" {
			localhostCount = count
		}
	}

	if localhostCount != 0 {
		t.Errorf("Per-IP count after close should be 0, got %d", localhostCount)
	}
	t.Logf("✓ Per-IP count after close: %d", localhostCount)

	// Test 5: Verify no negative counters (regression test for double-release bug)
	t.Log("\n--- Test 5: No negative counters (regression test) ---")
	// Open and close connection multiple times rapidly
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", backendServer.Address)
		if err != nil {
			t.Fatalf("Rapid connection %d failed: %v", i+1, err)
		}
		// Read greeting to keep connection alive
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		time.Sleep(20 * time.Millisecond)
		conn.Close()
		time.Sleep(20 * time.Millisecond)

		stats = limiter.GetStats()
		if stats.TotalConnections < 0 {
			t.Errorf("Negative counter detected: total=%d (iteration %d)", stats.TotalConnections, i+1)
		}
	}
	time.Sleep(200 * time.Millisecond) // Allow all cleanup to complete

	stats = limiter.GetStats()
	if stats.TotalConnections < 0 {
		t.Errorf("Final negative counter detected: total=%d", stats.TotalConnections)
	}
	if stats.TotalConnections != 0 {
		t.Errorf("Final total should be 0, got %d", stats.TotalConnections)
	}
	t.Logf("✓ No negative counters detected, final total=%d", stats.TotalConnections)

	t.Log("\n=== All counter verification tests passed ===")
}
