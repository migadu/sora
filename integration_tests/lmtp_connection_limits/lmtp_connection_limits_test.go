//go:build integration

package lmtp_connection_limits

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupLMTPServerWithConnectionLimits creates an LMTP server with specific connection limits
func setupLMTPServerWithConnectionLimits(t *testing.T, maxTotal, maxPerIP int) (*lmtp.LMTPServerBackend, string) {
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
	tempDir, err := os.MkdirTemp("", "sora-test-lmtp-connection-limits-*")
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

	// Create LMTP server with connection limits
	server, err := lmtp.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		lmtp.LMTPServerOptions{
			MaxConnections:      maxTotal,
			MaxConnectionsPerIP: maxPerIP,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}

	// Start server in background with error channel
	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Check for immediate startup errors
	select {
	case err := <-errChan:
		t.Fatalf("LMTP server failed to start: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Server started successfully
	}

	t.Cleanup(func() {
		server.Close()
		os.RemoveAll(tempDir)
	})

	return server, address
}

func TestLMTPConnectionLimiterTotal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with 2 total connections
	server, address := setupLMTPServerWithConnectionLimits(t, 2, 10)
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
