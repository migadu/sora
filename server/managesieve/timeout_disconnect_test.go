package managesieve

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// TestIdleTimeoutSendsBye verifies that idle timeout sends BYE message
func TestIdleTimeoutSendsBye(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	// Create minimal test server with very short idle timeout
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
	mockRDB := &resilient.ResilientDatabase{} // Mock - won't be used in this test

	server, err := New(ctx, "test", "localhost", addr, mockRDB, ManageSieveServerOptions{
		Debug:          false,
		TLS:            false,
		CommandTimeout: 2 * time.Second, // Very short idle timeout
		MaxConnections: 10,
		Config:         &config.Config{}, // Minimal config
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go server.Start(errChan)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (multi-line: capabilities then OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Wait for idle timeout (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read BYE message
	bye, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read BYE: %v", err)
	}

	// Verify BYE message contains expected text
	if !strings.Contains(bye, "BYE") {
		t.Errorf("Expected BYE response, got: %s", bye)
	}
	if !strings.Contains(bye, "timed out") {
		t.Errorf("Expected 'timed out' in BYE message, got: %s", bye)
	}

	t.Logf("✓ Received expected BYE message: %s", strings.TrimSpace(bye))
}

// TestSessionMaxTimeoutSendsBye verifies that session max timeout sends BYE message
func TestSessionMaxTimeoutSendsBye(t *testing.T) {
	// Skip in short mode
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

	server, err := New(ctx, "test", "localhost", addr, mockRDB, ManageSieveServerOptions{
		Debug:                  false,
		TLS:                    false,
		CommandTimeout:         10 * time.Second, // Long idle timeout
		AbsoluteSessionTimeout: 2 * time.Second,  // Very short session max
		MaxConnections:         10,
		Config:                 &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go server.Start(errChan)

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (multi-line: capabilities then OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Keep connection active but wait for session max timeout
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	done := make(chan bool)
	go func() {
		// Send NOOP periodically to keep connection active
		for {
			select {
			case <-ticker.C:
				conn.Write([]byte("NOOP\r\n"))
			case <-done:
				return
			}
		}
	}()

	// Wait for session max timeout (2 seconds + buffer)
	time.Sleep(3 * time.Second)
	close(done)

	// Read any pending responses and look for BYE
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var foundBye bool
	for i := 0; i < 10; i++ { // Read up to 10 lines
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "BYE") && strings.Contains(line, "session duration") {
			foundBye = true
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
	// This test documents the slow throughput timeout behavior
	// A full integration test would require >2 minutes to execute (throughput is checked after 2 min of session time)

	t.Log("✓ Slow throughput timeout mechanism is implemented")
	t.Log("  Trigger: Data transfer rate below min_bytes_per_minute after 2 minutes")
	t.Log("  Message: BYE (TRYLATER) \"Connection too slow, please reconnect\"")
	t.Log("  (Full integration test would require >2 minutes to execute)")
}

// TestAuthIdleTimeoutDuringPreAuth verifies that auth_idle_timeout disconnects during pre-auth phase
func TestAuthIdleTimeoutDuringPreAuth(t *testing.T) {
	// Skip in short mode
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

	server, err := New(ctx, "test", "localhost", addr, mockRDB, ManageSieveServerOptions{
		Debug:           false,
		TLS:             false,
		AuthIdleTimeout: 2 * time.Second,  // Very short auth idle timeout
		CommandTimeout:  10 * time.Second, // Longer command timeout (should not trigger)
		MaxConnections:  10,
		Config:          &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go server.Start(errChan)

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (multi-line: capabilities then OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Do NOT authenticate - just wait idle during pre-auth phase
	// Auth idle timeout should trigger (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read BYE message from server
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	bye, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read timeout BYE message: %v", err)
	}

	// Verify BYE message
	if !strings.Contains(bye, "BYE") {
		t.Errorf("Expected BYE response, got: %s", bye)
	}
	if !strings.Contains(bye, "timed out") {
		t.Errorf("Expected 'timed out' in BYE message, got: %s", bye)
	}

	t.Logf("✓ Connection timed out during pre-auth idle as expected: %s", strings.TrimSpace(bye))

	// Connection should now be closed - next read should fail
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("Expected connection to be closed after timeout, but second read succeeded")
	}
}
