//go:build integration

package pop3proxy

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyConnectionLimiterCounters tests that connection limiter counters
// are correctly incremented and decremented throughout the connection lifecycle.
// This test verifies the fix for the connection limiter leak bug where counters
// were stuck at maximum values because releaseConn() was only in goroutine defer
// and never executed when goroutines hung.
func TestPOP3ProxyConnectionLimiterCounters(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, _ := common.SetupPOP3Server(t)
	defer backendServer.Close()

	// Set up POP3 proxy with specific limits for testing
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupPOP3ProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 10, 3, []string{}) // maxTotal=10, maxPerIP=3
	defer proxyServer.Close()

	// Get the limiter to verify counter state
	proxy, ok := proxyServer.Server.(*pop3proxy.POP3ProxyServer)
	if !ok {
		t.Fatalf("Failed to cast to POP3 proxy server")
	}
	limiter := proxy.GetLimiter()
	if limiter == nil {
		t.Fatalf("Connection limiter is nil")
	}

	t.Log("=== Testing POP3 Proxy Connection Limiter Counters ===")
	t.Logf("Config: maxTotal=10, maxPerIP=3")

	// Test 1: Verify initial state
	t.Log("\n--- Test 1: Initial state ---")
	stats := limiter.GetStats()
	if stats.TotalConnections != 0 {
		t.Errorf("Initial total connections should be 0, got %d", stats.TotalConnections)
	}
	t.Logf("✓ Initial total connections: %d", stats.TotalConnections)

	// Test 2: Single connection increment and decrement
	t.Log("\n--- Test 2: Single connection lifecycle ---")
	conn1, err := net.Dial("tcp", proxyAddress)
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
		conn, err := net.Dial("tcp", proxyAddress)
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
	conn2, err := net.Dial("tcp", proxyAddress)
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

	if localhostCount != 1 {
		t.Errorf("Per-IP count for localhost should be 1, got %d", localhostCount)
	}
	t.Logf("✓ Per-IP count for localhost: %d", localhostCount)

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
		conn, err := net.Dial("tcp", proxyAddress)
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

// TestPOP3ProxyConnectionLimiterEnforcement tests that connection limits are properly enforced
func TestPOP3ProxyConnectionLimiterEnforcement(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, _ := common.SetupPOP3Server(t)
	defer backendServer.Close()

	// Set up POP3 proxy with very restrictive limits
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupPOP3ProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 5, 2, []string{}) // maxTotal=5, maxPerIP=2
	defer proxyServer.Close()

	proxy, ok := proxyServer.Server.(*pop3proxy.POP3ProxyServer)
	if !ok {
		t.Fatalf("Failed to cast to POP3 proxy server")
	}
	limiter := proxy.GetLimiter()

	t.Log("=== Testing POP3 Proxy Connection Limiter Enforcement ===")
	t.Logf("Config: maxTotal=5, maxPerIP=2")

	// Test 1: Per-IP limit enforcement
	t.Log("\n--- Test 1: Per-IP limit enforcement ---")
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	defer conn1.Close()
	// Read greeting to keep connection alive
	buf := make([]byte, 1024)
	_, _ = conn1.Read(buf)

	conn2, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Second connection should succeed: %v", err)
	}
	defer conn2.Close()
	// Read greeting to keep connection alive
	buf = make([]byte, 1024)
	_, _ = conn2.Read(buf)

	time.Sleep(100 * time.Millisecond)

	stats := limiter.GetStats()
	if stats.TotalConnections != 2 {
		t.Errorf("Expected 2 connections, got %d", stats.TotalConnections)
	}
	t.Logf("✓ Two connections accepted: total=%d", stats.TotalConnections)

	// Third connection should be rejected (exceeds maxPerIP=2)
	conn3, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Logf("✓ Third connection correctly rejected during dial: %v", err)
	} else {
		defer conn3.Close()
		// Give proxy time to close it
		time.Sleep(200 * time.Millisecond)

		// Try to read - should fail if closed
		conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn3.Read(buffer)
		if err != nil || n == 0 {
			t.Logf("✓ Third connection was closed by limiter")
		} else {
			t.Errorf("❌ Third connection should have been rejected (maxPerIP=2)")
		}
	}

	// Verify counter is still correct (not incremented for rejected connection)
	time.Sleep(100 * time.Millisecond)
	stats = limiter.GetStats()
	if stats.TotalConnections > 2 {
		t.Errorf("Counter should not exceed 2, got %d", stats.TotalConnections)
	}
	t.Logf("✓ Counter after rejection: total=%d", stats.TotalConnections)

	t.Log("\n=== All enforcement tests passed ===")
}
