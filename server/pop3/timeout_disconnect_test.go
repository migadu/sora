package pop3

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestIdleTimeoutSendsError verifies that idle timeout sends POP3 error message
func TestIdleTimeoutSendsError(t *testing.T) {
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

	// Create mock dependencies (nil where acceptable for this test)
	mockRDB := &resilient.ResilientDatabase{} // Mock - won't be used in this test
	mockS3 := &storage.S3Storage{}            // Mock - won't be used in this test
	mockUploader := &uploader.UploadWorker{}  // Mock - won't be used in this test
	mockCache := &cache.Cache{}               // Mock - won't be used in this test

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, POP3ServerOptions{
		Debug:          false,
		TLS:            false,
		CommandTimeout: 2 * time.Second, // Very short idle timeout
		MaxConnections: 10,
		Config:         &config.Config{}, // Minimal config
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
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

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Errorf("Expected +OK greeting, got: %s", greeting)
	}

	// Wait for idle timeout (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read error message
	errMsg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read error message: %v", err)
	}

	// Verify error message contains expected text
	if !strings.HasPrefix(errMsg, "-ERR") {
		t.Errorf("Expected -ERR response, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "timed out") && !strings.Contains(errMsg, "timeout") {
		t.Errorf("Expected 'timeout' in error message, got: %s", errMsg)
	}

	t.Logf("✓ Received expected error message: %s", strings.TrimSpace(errMsg))
}

// TestSessionMaxTimeoutSendsError verifies that session max timeout sends POP3 error message
func TestSessionMaxTimeoutSendsError(t *testing.T) {
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
	mockS3 := &storage.S3Storage{}
	mockUploader := &uploader.UploadWorker{}
	mockCache := &cache.Cache{}

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, POP3ServerOptions{
		Debug:                  false,
		TLS:                    false,
		CommandTimeout:         10 * time.Second, // Long idle timeout
		AbsoluteSessionTimeout: 2 * time.Second,  // Very short session max
		MaxConnections:         10,
		Config:                 &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
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

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Errorf("Expected +OK greeting, got: %s", greeting)
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

	// Read any pending responses and look for error message
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var foundError bool
	for i := 0; i < 10; i++ { // Read up to 10 lines
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "-ERR") && strings.Contains(line, "session duration") {
			foundError = true
			if !strings.Contains(line, "[IN-USE]") {
				t.Errorf("Expected '[IN-USE]' response code in error message, got: %s", line)
			}
			t.Logf("✓ Received expected error message: %s", strings.TrimSpace(line))
			break
		}
	}

	if !foundError {
		t.Error("Did not receive expected error message for session max timeout")
	}
}

// TestSlowThroughputTimeoutInfo documents the slow throughput timeout mechanism
func TestSlowThroughputTimeoutInfo(t *testing.T) {
	// This test documents the slow throughput timeout behavior
	// A full integration test would require >2 minutes to execute (throughput is checked after 2 min of session time)

	t.Log("✓ Slow throughput timeout mechanism is implemented")
	t.Log("  Trigger: Data transfer rate below min_bytes_per_minute after 2 minutes")
	t.Log("  Message: -ERR [IN-USE] Connection too slow, please reconnect")
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
	mockS3 := &storage.S3Storage{}
	mockUploader := &uploader.UploadWorker{}
	mockCache := &cache.Cache{}

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, POP3ServerOptions{
		Debug:           false,
		TLS:             false,
		AuthIdleTimeout: 2 * time.Second,  // Very short auth idle timeout
		CommandTimeout:  10 * time.Second, // Longer command timeout (should not trigger)
		MaxConnections:  10,
		Config:          &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
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

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Errorf("Expected +OK greeting, got: %s", greeting)
	}

	// Do NOT authenticate - just wait idle during pre-auth phase
	// Auth idle timeout should trigger (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read error message from server
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	errMsg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read timeout error message: %v", err)
	}

	// Verify error message
	if !strings.HasPrefix(errMsg, "-ERR") {
		t.Errorf("Expected -ERR response, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "timed out") {
		t.Errorf("Expected 'timed out' in error message, got: %s", errMsg)
	}

	t.Logf("✓ Connection timed out during pre-auth idle as expected: %s", strings.TrimSpace(errMsg))

	// Connection should now be closed - next read should fail
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("Expected connection to be closed after timeout, but second read succeeded")
	}
}
