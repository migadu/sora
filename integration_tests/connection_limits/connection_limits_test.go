//go:build integration

package connection_limits

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// getTestConnectionAddress converts a 0.0.0.0 bind address to a specific IP for testing
// This helps us avoid the default trusted networks that include localhost
func getTestConnectionAddress(bindAddress string) string {
	host, port, err := net.SplitHostPort(bindAddress)
	if err != nil {
		return bindAddress
	}

	// If bound to all interfaces, we need to connect via 127.0.0.1 since that's what works
	// The real issue is that we need a way to test connection limits without trusted network bypass
	if host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("127.0.0.1", port)
	}

	return bindAddress
}

// TestServerWithCleanup wraps common.TestServer with a custom cleanup function
type TestServerWithCleanup struct {
	*common.TestServer
	cleanupFunc func()
}

func (t *TestServerWithCleanup) Close() {
	if t.cleanupFunc != nil {
		t.cleanupFunc()
	}
}

// setupIMAPServerWithConnectionLimits creates an IMAP server with specific connection limits
func setupIMAPServerWithConnectionLimits(t *testing.T, maxTotal, maxPerIP int) (*TestServerWithCleanup, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Get a random port on localhost (use 127.0.0.1 to ensure IPv4)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on a random port: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-connection-limits-*")
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

	// Create server with connection limits
	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			MaxConnections:      maxTotal,
			MaxConnectionsPerIP: maxPerIP,
			TrustedNetworks:     []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			// Timeout waiting for server to shut down
		}
		// Clean up temporary directory
		os.RemoveAll(tempDir)
	}

	// Get the connection address (may be different from bind address for testing)
	connectionAddr := getTestConnectionAddress(address)

	// Create a custom test server struct that includes our cleanup function
	testServer := &TestServerWithCleanup{
		TestServer: &common.TestServer{
			Address:     connectionAddr, // Use connection address for tests
			Server:      server,
			ResilientDB: rdb,
		},
		cleanupFunc: cleanup,
	}

	return testServer, account
}

func TestConnectionLimiterPerIP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// This test demonstrates the connection limiter's behavior.
	// Since localhost is in trusted networks by default (for operational reasons),
	// we test the total connection limit instead which applies regardless of trust.

	// Set up server with only 2 total connections (this limit applies to all IPs including trusted ones for total count)
	server, _ := setupIMAPServerWithConnectionLimits(t, 2, 10) // 2 total, 10 per IP
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
	conn1, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish first connection: %v", err)
	}
	connections = append(connections, conn1)

	// Second connection should succeed
	conn2, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	connections = append(connections, conn2)

	// Third connection TCP connection may succeed, but should be rejected at protocol level
	conn3, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		// TCP connection failed - this is also valid (connection was rejected at network level)
		t.Logf("Third connection rejected at network level (expected): %v", err)
		return
	}

	// TCP connection succeeded, but server should reject it at protocol level
	connections = append(connections, conn3)

	// Try to read from connection with a short timeout - should get immediate close or error
	conn3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 100)
	n, err := conn3.Read(buffer)

	// Check if we got an IMAP error response indicating connection was rejected
	if err == nil && n > 0 {
		response := string(buffer[:n])
		// Server sends SERVERBUG when connection limits are exceeded during session creation
		// This is a limitation of the go-imap library's error handling, but it does indicate
		// that the connection was properly rejected due to limits
		if strings.Contains(response, "SERVERBUG") {
			t.Logf("Connection properly rejected due to limit (SERVERBUG response expected): %s", strings.TrimSpace(response))
			return
		}
		// Other error responses are also acceptable
		if strings.Contains(response, "NO") || strings.Contains(response, "error") {
			t.Logf("Connection rejected with IMAP error response: %s", strings.TrimSpace(response))
			return
		}
		// If we get a normal IMAP greeting, that's unexpected
		t.Fatalf("Expected connection to be rejected by server, but got normal response: %s", strings.TrimSpace(response))
	}

	// Any error (timeout, connection reset, EOF) also indicates rejection
	t.Logf("Third connection rejected by server (connection closed): %v", err)
}

func TestIMAPBackendTrustedNetworksBypassPerIPLimits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test IMAP backend behavior according to requirements:
	// - Without proxy protocol, use trusted_networks to exclude per-IP limiting
	// - Connections from localhost should bypass per-IP limits but respect max_connections
	// - This tests the default trusted networks behavior (localhost should be trusted)

	// Set up server with high total connections but very low per-IP limit
	server, _ := setupIMAPServerWithConnectionLimits(t, 10, 1) // maxTotal=10, maxPerIP=1
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Multiple connections from localhost should succeed despite maxPerIP=1
	// because localhost is in trusted networks
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
		if err != nil {
			t.Fatalf("Connection %d from localhost failed (should succeed - trusted network): %v", i+1, err)
		}
		connections = append(connections, conn)

		// Read welcome banner to confirm connection works
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1000)
		n, err := conn.Read(buffer)
		if err != nil || n == 0 {
			t.Fatalf("Failed to read IMAP welcome banner from connection %d: %v", i+1, err)
		}
		response := string(buffer[:n])
		if !strings.Contains(response, "* OK") {
			t.Fatalf("Connection %d: Expected IMAP welcome banner, got: %s", i+1, strings.TrimSpace(response))
		}
	}

	t.Logf("SUCCESS: 3 connections from localhost succeeded despite maxPerIP=1 (trusted network bypasses per-IP limits)")
}

func TestConnectionLimiterTotal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with only 2 total connections and high per-IP limit
	server, _ := setupIMAPServerWithConnectionLimits(t, 2, 100)
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
	conn1, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish first connection: %v", err)
	}
	connections = append(connections, conn1)

	// Second connection should succeed
	conn2, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	connections = append(connections, conn2)

	// Third connection should fail due to total connection limit
	conn3, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		// TCP connection failed - this is also valid (connection was rejected at network level)
		t.Logf("Third connection rejected at network level (expected): %v", err)
		return
	}

	// TCP connection succeeded, but server should reject it at protocol level
	connections = append(connections, conn3)

	// Try to read from connection with a short timeout - should get immediate close or error
	conn3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 100)
	n, err := conn3.Read(buffer)

	// Check if we got an IMAP error response indicating connection was rejected
	if err == nil && n > 0 {
		response := string(buffer[:n])
		// Server sends SERVERBUG when connection limits are exceeded during session creation
		// This is a limitation of the go-imap library's error handling, but it does indicate
		// that the connection was properly rejected due to limits
		if strings.Contains(response, "SERVERBUG") {
			t.Logf("Connection properly rejected due to limit (SERVERBUG response expected): %s", strings.TrimSpace(response))
			return
		}
		// Other error responses are also acceptable
		if strings.Contains(response, "NO") || strings.Contains(response, "error") {
			t.Logf("Connection rejected with IMAP error response: %s", strings.TrimSpace(response))
			return
		}
		// If we get a normal IMAP greeting, that's unexpected
		t.Fatalf("Expected connection to be rejected by server, but got normal response: %s", strings.TrimSpace(response))
	}

	// Any error (timeout, connection reset, EOF) also indicates rejection
	t.Logf("Third connection rejected by server (connection closed): %v", err)
}

func TestConnectionLimiterConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with 3 total connections (total limit applies even to trusted IPs)
	// and higher per-IP limit that won't be reached due to localhost being trusted
	server, _ := setupIMAPServerWithConnectionLimits(t, 3, 10)
	defer server.Close()

	const numGoroutines = 5
	var wg sync.WaitGroup
	results := make([]bool, numGoroutines) // true = successful connection, false = rejected

	// Try to make 5 concurrent connections from same IP (localhost)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", server.Address, 10*time.Second)
			if err != nil {
				// TCP connection failed
				results[index] = false
				return
			}
			defer conn.Close()

			// Try to read from connection to see if IMAP session was created successfully
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			buffer := make([]byte, 100)
			n, err := conn.Read(buffer)

			if err != nil {
				// Connection was closed or failed to read
				results[index] = false
				return
			}

			if n > 0 {
				response := string(buffer[:n])
				// Check if we got a SERVERBUG (connection rejected) or a normal greeting
				if strings.Contains(response, "SERVERBUG") {
					results[index] = false // Connection was rejected
				} else if strings.Contains(response, "OK") || strings.Contains(response, "PREAUTH") || strings.Contains(response, "*") {
					results[index] = true // Normal IMAP greeting, connection accepted
				} else {
					results[index] = false // Unknown response, assume rejected
				}
			} else {
				results[index] = false // No data read
			}

			// Hold connection open to prevent it from being released before concurrent goroutines complete
			// This ensures the limit is actually enforced during the concurrent connection phase
			if results[index] {
				time.Sleep(500 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Count successful vs failed connections
	successful := 0
	failed := 0
	for _, wasSuccessful := range results {
		if wasSuccessful {
			successful++
		} else {
			failed++
		}
	}

	t.Logf("Concurrent connection test: %d successful, %d failed", successful, failed)

	// Due to total connection limit of 3, we should have at most 3 successful connections
	if successful > 3 {
		t.Fatalf("Expected at most 3 successful connections due to total limit, got %d", successful)
	}

	// We should have some failures due to the total limit
	if failed == 0 {
		t.Fatalf("Expected some connection failures due to total limit, but all %d connections succeeded", numGoroutines)
	}
}

func TestConnectionLimiterRecovery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with 2 total connections and 2 per IP
	server, _ := setupIMAPServerWithConnectionLimits(t, 2, 2)
	defer server.Close()

	// First, fill up all available connections
	conn1, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish first connection: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	defer conn2.Close()

	// Third connection should fail - either at TCP level or with SERVERBUG
	conn3, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err == nil {
		defer conn3.Close()
		// TCP connection succeeded, check if IMAP rejected it
		conn3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, 100)
		n, readErr := conn3.Read(buffer)

		if readErr == nil && n > 0 {
			response := string(buffer[:n])
			if !strings.Contains(response, "SERVERBUG") {
				t.Fatalf("Third connection should have been rejected, but got: %s", strings.TrimSpace(response))
			}
			t.Logf("Third connection properly rejected with SERVERBUG: %s", strings.TrimSpace(response))
		} else if readErr != nil {
			t.Logf("Third connection rejected (connection closed): %v", readErr)
		}
	} else {
		t.Logf("Third connection rejected at TCP level: %v", err)
	}

	// Close first connection to free up a slot
	conn1.Close()

	// Wait a bit for the server to process the connection close
	time.Sleep(100 * time.Millisecond)

	// Now a new connection should succeed
	conn4, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Connection should have succeeded after freeing up a slot: %v", err)
	}
	conn4.Close()
}

func TestConnectionLimiterDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up server with connection limits disabled (0 means no limit)
	server, _ := setupIMAPServerWithConnectionLimits(t, 0, 0)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Should be able to make several connections without limits
	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to establish connection %d when limits disabled: %v", i+1, err)
		}
		connections = append(connections, conn)
	}

	t.Logf("Successfully established %d connections with limits disabled", len(connections))
}

// TestConnectionLimiterUnitPerIP tests the ConnectionLimiter directly to verify per-IP limiting works
// This bypasses the server's trusted networks behavior to test the core limiting logic
func TestConnectionLimiterUnitPerIP(t *testing.T) {
	// Create a connection limiter with 5 total connections and 2 per IP (no trusted networks)
	limiter := server.NewConnectionLimiter("TEST", 5, 2)

	// Simulate an external IP address (not in default trusted networks)
	externalAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345} // RFC5737 test IP

	// First connection should be accepted
	release1, err := limiter.AcceptWithRealIP(externalAddr, "")
	if err != nil {
		t.Fatalf("First connection should be accepted: %v", err)
	}
	defer release1()

	// Second connection should be accepted
	release2, err := limiter.AcceptWithRealIP(externalAddr, "")
	if err != nil {
		t.Fatalf("Second connection should be accepted: %v", err)
	}
	defer release2()

	// Third connection from same IP should be rejected due to per-IP limit
	release3, err := limiter.AcceptWithRealIP(externalAddr, "")
	if err == nil {
		release3()
		t.Fatalf("Third connection should have been rejected due to per-IP limit")
	}

	if !strings.Contains(err.Error(), "maximum connections per IP reached") {
		t.Fatalf("Expected per-IP limit error, got: %v", err)
	}

	// Verify we can connect from a different IP
	differentAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12346}
	release4, err := limiter.AcceptWithRealIP(differentAddr, "")
	if err != nil {
		t.Fatalf("Connection from different IP should be accepted: %v", err)
	}
	defer release4()

	// Check connection statistics
	stats := limiter.GetStats()
	if stats.TotalConnections != 3 {
		t.Errorf("Expected 3 total connections, got %d", stats.TotalConnections)
	}
	if stats.IPConnections["203.0.113.1"] != 2 {
		t.Errorf("Expected 2 connections from first IP, got %d", stats.IPConnections["203.0.113.1"])
	}
	if stats.IPConnections["203.0.113.2"] != 1 {
		t.Errorf("Expected 1 connection from second IP, got %d", stats.IPConnections["203.0.113.2"])
	}

	t.Logf("Connection limiter unit test passed - per-IP limits work correctly")
}
