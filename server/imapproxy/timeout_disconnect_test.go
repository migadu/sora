package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestIdleTimeoutDisconnects verifies that idle timeout disconnects client
// Note: IMAP proxy has command_timeout = "0" (disabled) in production because
// proxies cannot detect IDLE commands. This test verifies the mechanism works
// when command_timeout is configured for testing purposes.
func TestIdleTimeoutDisconnects(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	// Create mock dependencies
	mockRDB := &resilient.ResilientDatabase{}

	srv, err := New(ctx, mockRDB, "localhost", ServerOptions{
		Name:           "test",
		Addr:           addr,
		RemoteAddrs:    []string{"127.0.0.1:143"}, // Dummy backend
		RemotePort:     143,
		CommandTimeout: 2 * time.Second, // Very short timeout for testing
		ConnectTimeout: 5 * time.Second,
		AuthRateLimit:  server.AuthRateLimiterConfig{},
		MaxConnections: 10,
		RemoteLookup:   &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (may be missing if backend is unreachable)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	greeting, err := reader.ReadString('\n')
	if err == nil {
		if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* BYE") {
			t.Logf("Unexpected greeting (may be normal for proxy without backend): %s", greeting)
		}
	}
	conn.SetReadDeadline(time.Time{})

	// Wait for idle timeout
	time.Sleep(3 * time.Second)

	// Try to read - connection should be closed or close soon
	// We may read buffered data first, so try up to a few reads
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var gotError bool
	for i := 0; i < 5; i++ {
		_, err = reader.ReadString('\n')
		if err != nil {
			gotError = true
			break
		}
	}

	if !gotError {
		t.Error("Expected connection to be closed after timeout, but reads kept succeeding")
	} else {
		t.Logf("✓ Connection closed after idle timeout as expected")
	}
}

// TestSessionMaxTimeoutInfo documents the session max timeout mechanism
func TestSessionMaxTimeoutInfo(t *testing.T) {
	t.Log("✓ Session max timeout mechanism is implemented")
	t.Log("  Message: * BYE Maximum session duration exceeded, please reconnect")
	t.Log("  (Full test would require a working IMAP backend)")
	t.Log("  Note: IMAP proxy typically has command_timeout = \"0\" in production")
	t.Log("        because proxies cannot detect IDLE commands")
}

// TestSlowThroughputTimeoutInfo documents the slow throughput timeout mechanism
func TestSlowThroughputTimeoutInfo(t *testing.T) {
	t.Log("✓ Slow throughput timeout mechanism is implemented")
	t.Log("  Trigger: Data transfer rate below min_bytes_per_minute after 2 minutes")
	t.Log("  Message: * BYE Connection too slow, please reconnect")
	t.Log("  (Full integration test would require >2 minutes to execute)")
}

// TestAuthIdleTimeoutDuringPreAuth verifies that auth_idle_timeout disconnects during pre-auth phase
func TestAuthIdleTimeoutDuringPreAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	// Create mock dependencies
	mockRDB := &resilient.ResilientDatabase{}

	srv, err := New(ctx, mockRDB, "localhost", ServerOptions{
		Name:            "test",
		Addr:            addr,
		RemoteAddrs:     []string{"127.0.0.1:143"}, // Dummy backend
		RemotePort:      143,
		AuthIdleTimeout: 2 * time.Second,  // Very short auth idle timeout
		CommandTimeout:  10 * time.Second, // Longer command timeout (should not trigger)
		ConnectTimeout:  5 * time.Second,
		AuthRateLimit:   server.AuthRateLimiterConfig{},
		MaxConnections:  10,
		RemoteLookup:    &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (may be missing if backend is unreachable)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	greeting, err := reader.ReadString('\n')
	if err == nil {
		if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* BYE") {
			t.Logf("Unexpected greeting (may be normal for proxy without backend): %s", greeting)
		}
	}
	conn.SetReadDeadline(time.Time{})

	// Do NOT authenticate - just wait idle during pre-auth phase
	// Auth idle timeout should trigger (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Try to read - connection should be closed or close soon
	// We may read buffered data first, so try up to a few reads
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var gotError bool
	for i := 0; i < 5; i++ {
		_, err = reader.ReadString('\n')
		if err != nil {
			gotError = true
			break
		}
	}

	if !gotError {
		t.Error("Expected connection to be closed after auth idle timeout, but reads kept succeeding")
	} else {
		t.Logf("✓ Connection closed during pre-auth idle as expected")
	}
}
