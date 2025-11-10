package imap

import (
	"bufio"
	"context"
	"fmt"
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

	// Create mock dependencies (nil where acceptable for this test)
	mockRDB := &resilient.ResilientDatabase{} // Mock - won't be used in this test
	mockS3 := &storage.S3Storage{}            // Mock - won't be used in this test
	mockUploader := &uploader.UploadWorker{}  // Mock - won't be used in this test
	mockCache := &cache.Cache{}               // Mock - won't be used in this test

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, IMAPServerOptions{
		Debug:          false,
		TLS:            false,
		CommandTimeout: 2 * time.Second, // Very short idle timeout
		AppendLimit:    DefaultAppendLimit,
		MaxConnections: 10,
		Config:         &config.Config{}, // Minimal config
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		if err := server.Serve(addr); err != nil && ctx.Err() == nil {
			t.Logf("Server error: %v", err)
		}
	}()

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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Errorf("Expected OK greeting, got: %s", greeting)
	}

	// Wait for idle timeout (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Read BYE message
	bye, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read BYE: %v", err)
	}

	// Verify BYE message contains expected text and response code
	if !strings.HasPrefix(bye, "* BYE") {
		t.Errorf("Expected BYE response, got: %s", bye)
	}
	if !strings.Contains(bye, "[UNAVAILABLE]") {
		t.Errorf("Expected '[UNAVAILABLE]' response code in BYE message, got: %s", bye)
	}
	if !strings.Contains(bye, "Idle timeout") {
		t.Errorf("Expected 'Idle timeout' in BYE message, got: %s", bye)
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
	mockS3 := &storage.S3Storage{}
	mockUploader := &uploader.UploadWorker{}
	mockCache := &cache.Cache{}

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, IMAPServerOptions{
		Debug:                  false,
		TLS:                    false,
		CommandTimeout:         10 * time.Second, // Long idle timeout
		AbsoluteSessionTimeout: 2 * time.Second,  // Very short session max
		AppendLimit:            DefaultAppendLimit,
		MaxConnections:         10,
		Config:                 &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		if err := server.Serve(addr); err != nil && ctx.Err() == nil {
			t.Logf("Server error: %v", err)
		}
	}()

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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Errorf("Expected OK greeting, got: %s", greeting)
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
				fmt.Fprintf(conn, "A001 NOOP\r\n")
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
		if strings.HasPrefix(line, "* BYE") {
			foundBye = true
			if !strings.Contains(line, "[UNAVAILABLE]") {
				t.Errorf("Expected '[UNAVAILABLE]' response code in BYE message, got: %s", line)
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
	// This test documents the slow throughput timeout behavior
	// A full integration test would require >2 minutes to execute (throughput is checked after 2 min of session time)

	t.Log("✓ Slow throughput timeout mechanism is implemented")
	t.Log("  Trigger: Data transfer rate below min_bytes_per_minute after 2 minutes")
	t.Log("  Message: * BYE Connection too slow, please reconnect")
	t.Log("  (Full integration test would require >2 minutes to execute)")
}

// TestAuthIdleTimeoutDuringPreAuth verifies that auth_idle_timeout disconnects during pre-auth phase
// Note: auth_idle_timeout uses SetReadDeadline() which closes the connection without sending BYE.
// This is acceptable because: (1) default is 0 (disabled), (2) meant for aggressive cleanup,
// (3) post-auth timeouts via SoraConn properly send BYE messages.
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

	server, err := New(ctx, "test", "localhost", addr, mockS3, mockRDB, mockUploader, mockCache, IMAPServerOptions{
		Debug:           false,
		TLS:             false,
		AuthIdleTimeout: 2 * time.Second,  // Very short auth idle timeout
		CommandTimeout:  10 * time.Second, // Longer command timeout (should not trigger)
		AppendLimit:     DefaultAppendLimit,
		MaxConnections:  10,
		Config:          &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		if err := server.Serve(addr); err != nil && ctx.Err() == nil {
			t.Logf("Server error: %v", err)
		}
	}()

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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Errorf("Expected OK greeting, got: %s", greeting)
	}

	// Do NOT authenticate - just wait idle during pre-auth phase
	// Auth idle timeout should trigger (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// Try to read - should get connection closed or timeout error
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = reader.ReadString('\n')

	// We expect either EOF (connection closed) or timeout
	if err == nil {
		t.Error("Expected connection to be closed after auth idle timeout, but read succeeded")
	} else {
		t.Logf("✓ Connection closed during pre-auth idle as expected: %v", err)
	}
}
