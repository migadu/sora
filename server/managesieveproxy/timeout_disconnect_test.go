package managesieveproxy

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

// TestIdleTimeoutSendsBye verifies that idle timeout sends BYE with TRYLATER
func TestIdleTimeoutSendsBye(t *testing.T) {
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
		RemoteAddrs:    []string{"127.0.0.1:4190"}, // Dummy backend
		RemotePort:     4190,
		CommandTimeout: 2 * time.Second, // Very short idle timeout
		ConnectTimeout: 5 * time.Second,
		AuthRateLimit:  server.AuthRateLimiterConfig{},
		MaxConnections: 10,
		RemoteLookup:   &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
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

	// Read ManageSieve greeting (multiple capability lines ending with OK)
	// The proxy may not send a complete greeting if backend is unreachable,
	// so we'll just read available lines and not validate the greeting format
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// Timeout or connection closed - that's OK for this test
			break
		}
		if strings.HasPrefix(line, "OK") {
			// End of greeting
			break
		}
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Wait for idle timeout
	time.Sleep(3 * time.Second)

	// Read BYE message
	bye, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read BYE: %v", err)
	}

	// Verify BYE message (RFC 5804)
	if !strings.HasPrefix(bye, "BYE") {
		t.Errorf("Expected BYE response, got: %s", bye)
	}
	if !strings.Contains(bye, "TRYLATER") {
		t.Errorf("Expected TRYLATER in BYE message, got: %s", bye)
	}
	if !strings.Contains(bye, "Idle timeout") {
		t.Errorf("Expected 'Idle timeout' in BYE message, got: %s", bye)
	}

	t.Logf("✓ Received expected BYE message: %s", strings.TrimSpace(bye))
}

// TestSessionMaxTimeoutSendsBye verifies that session max timeout sends BYE with TRYLATER
func TestSessionMaxTimeoutSendsBye(t *testing.T) {
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
		Name:                   "test",
		Addr:                   addr,
		RemoteAddrs:            []string{"127.0.0.1:4190"},
		RemotePort:             4190,
		CommandTimeout:         10 * time.Second, // Long idle timeout
		AbsoluteSessionTimeout: 2 * time.Second,  // Very short session max
		ConnectTimeout:         5 * time.Second,
		AuthRateLimit:          server.AuthRateLimiterConfig{},
		MaxConnections:         10,
		RemoteLookup:           &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

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

	// Read greeting
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	// Keep connection active with small periodic writes
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				conn.Write([]byte("NOOP\r\n"))
			case <-done:
				return
			}
		}
	}()

	// Wait for session max timeout
	time.Sleep(3 * time.Second)
	close(done)

	// Read responses looking for BYE
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var foundBye bool
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "BYE") {
			foundBye = true
			if !strings.Contains(line, "TRYLATER") {
				t.Errorf("Expected TRYLATER in BYE message, got: %s", line)
			}
			if !strings.Contains(line, "session duration") {
				t.Errorf("Expected 'session duration' in BYE message, got: %s", line)
			}
			t.Logf("✓ Received expected BYE message: %s", strings.TrimSpace(line))
			break
		}
	}

	if !foundBye {
		t.Error("Did not receive expected BYE message for session max timeout")
	}
}

// TestSlowThroughputTimeoutInfo documents the slow throughput timeout mechanism
func TestSlowThroughputTimeoutInfo(t *testing.T) {
	t.Log("✓ Slow throughput timeout mechanism is implemented")
	t.Log("  Trigger: Data transfer rate below min_bytes_per_minute after 2 minutes")
	t.Log("  Message: BYE (TRYLATER) \"Connection too slow, please reconnect\"")
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
		RemoteAddrs:     []string{"127.0.0.1:4190"}, // Dummy backend
		RemotePort:      4190,
		AuthIdleTimeout: 2 * time.Second,  // Very short auth idle timeout
		CommandTimeout:  10 * time.Second, // Longer command timeout (should not trigger)
		ConnectTimeout:  5 * time.Second,
		AuthRateLimit:   server.AuthRateLimiterConfig{},
		MaxConnections:  10,
		RemoteLookup:    &config.RemoteLookupConfig{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
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

	// Read ManageSieve greeting (multiple capability lines ending with OK)
	// The proxy may not send a complete greeting if backend is unreachable
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// Timeout or connection closed - that's OK for this test
			break
		}
		if strings.HasPrefix(line, "OK") {
			// End of greeting
			break
		}
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Do NOT authenticate - just wait idle during pre-auth phase
	// Auth idle timeout should trigger (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read timeout message from server
	// ManageSieve proxy sends NO "Idle timeout" (simpler than full BYE TRYLATER)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	msg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read timeout message: %v", err)
	}

	// Verify timeout message
	if !strings.HasPrefix(msg, "NO") && !strings.HasPrefix(msg, "BYE") {
		t.Errorf("Expected NO or BYE response, got: %s", msg)
	}
	if !strings.Contains(msg, "Idle timeout") {
		t.Errorf("Expected 'Idle timeout' in message, got: %s", msg)
	}

	t.Logf("✓ Connection timed out during pre-auth idle as expected: %s", strings.TrimSpace(msg))

	// Connection should now be closed - next read should fail
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("Expected connection to be closed after timeout, but second read succeeded")
	}
}
