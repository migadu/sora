//go:build integration

package pop3_connection_limits

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupPOP3ServerWithConnectionLimits creates a POP3 server with specific connection limits
func setupPOP3ServerWithConnectionLimits(t *testing.T, maxTotal, maxPerIP int) (*pop3.POP3Server, string) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)

	// Get a random port and bind to all interfaces
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on a random port: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-pop3-connection-limits-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create POP3 server with connection limits
	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			MaxConnections:      maxTotal,
			MaxConnectionsPerIP: maxPerIP,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	// Start server in background with error channel
	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Check for immediate startup errors
	select {
	case err := <-errChan:
		t.Fatalf("POP3 server failed to start: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Server started successfully
	}

	t.Cleanup(func() {
		server.Close()
		os.RemoveAll(tempDir)
	})

	return server, address
}

func TestPOP3ConnectionLimiterTotal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with 2 total connections
	server, address := setupPOP3ServerWithConnectionLimits(t, 2, 10)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// First connection should succeed
	conn1, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish first connection: %v", err)
	}
	connections = append(connections, conn1)

	// Second connection should succeed
	conn2, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	connections = append(connections, conn2)

	// Third connection should fail due to total connection limit
	conn3, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		// TCP connection failed - this is valid (connection was rejected at network level)
		t.Logf("Third connection rejected at network level (expected): %v", err)
		return
	}

	// TCP connection succeeded, check if it's immediately closed
	connections = append(connections, conn3)

	conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
	buffer := make([]byte, 100)
	n, err := conn3.Read(buffer)

	// Connection should be closed by server or we get timeout/EOF
	if err == nil && n > 0 {
		response := string(buffer[:n])
		t.Fatalf("Expected connection to be rejected, but got response: %s", strings.TrimSpace(response))
	}

	// Any error (timeout, connection reset, EOF) indicates rejection as expected
	t.Logf("Third connection properly handled (rejected): %v", err)
}

func TestPOP3ConnectionLimiterPerIP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Note: This test documents that localhost (127.0.0.1) is treated as a trusted network
	// and bypasses per-IP connection limits. This is the correct behavior.

	// Set up server with high total but 2 per IP
	server, address := setupPOP3ServerWithConnectionLimits(t, 10, 2)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// First connection should succeed
	conn1, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish first connection: %v", err)
	}
	connections = append(connections, conn1)

	// Second connection should succeed
	conn2, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	connections = append(connections, conn2)

	// Third connection from localhost should succeed because localhost is a trusted network
	// and trusted networks bypass per-IP limits
	conn3, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish third connection from localhost: %v", err)
	}
	connections = append(connections, conn3)

	// Read the welcome banner to confirm the connection is working
	conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
	buffer := make([]byte, 100)
	n, err := conn3.Read(buffer)

	// Connection should work fine from trusted networks (localhost)
	if err != nil || n == 0 {
		t.Fatalf("Expected connection to work from trusted network (localhost), but got error: %v", err)
	}

	response := string(buffer[:n])
	if !strings.Contains(response, "+OK") {
		t.Fatalf("Expected POP3 welcome banner, but got: %s", strings.TrimSpace(response))
	}

	t.Logf("Third connection from localhost succeeded as expected (trusted network): %s", strings.TrimSpace(response))
}
