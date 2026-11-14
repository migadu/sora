//go:build integration

package proxy_connection_limits

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// generateProxyV1Header generates a PROXY protocol v1 header
func generateProxyV1Header(clientIP string, clientPort int, serverIP string, serverPort int) string {
	// PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n
	return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", clientIP, serverIP, clientPort, serverPort)
}

// setupIMAPServerWithProxyProtocol creates an IMAP server with PROXY protocol and connection limits
func setupIMAPServerWithProxyProtocol(t *testing.T, maxTotal, maxPerIP int, trustedNetworks []string) (*imap.IMAPServer, string) {
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
	tempDir, err := os.MkdirTemp("", "sora-test-proxy-connection-limits-*")
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
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with PROXY protocol and connection limits
	imapServer, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth:         true, // Allow PLAIN auth (no TLS in tests)
			MaxConnections:       maxTotal,
			MaxConnectionsPerIP:  maxPerIP,
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      trustedNetworks,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background with error channel
	errChan := make(chan error, 1)
	go func() {
		if err := imapServer.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Check for immediate startup errors
	select {
	case err := <-errChan:
		t.Fatalf("IMAP server failed to start: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Server started successfully
	}

	t.Cleanup(func() {
		imapServer.Close()
		os.RemoveAll(tempDir)
	})

	return imapServer, address
}

// connectWithProxyHeader establishes a connection and sends a PROXY protocol header
func connectWithProxyHeader(t *testing.T, address, clientIP string, clientPort int) net.Conn {
	t.Helper()

	// Connect to server
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}

	// Parse server address to get server IP and port
	serverHost, serverPortStr, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to parse server address: %v", err)
	}

	serverPort := 0
	if _, err := fmt.Sscanf(serverPortStr, "%d", &serverPort); err != nil {
		conn.Close()
		t.Fatalf("Failed to parse server port: %v", err)
	}

	// Send PROXY protocol header
	proxyHeader := generateProxyV1Header(clientIP, clientPort, serverHost, serverPort)
	_, err = conn.Write([]byte(proxyHeader))
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to send PROXY header: %v", err)
	}

	return conn
}

func TestProxyProtocolConnectionLimitsRealClientIP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test scenario:
	// - Server allows 10 total connections, 2 per IP
	// - Connections come from a trusted PROXY peer (localhost)
	// - Real client IPs are 192.168.1.100 (should hit per-IP limit after 2 connections)
	// - PROXY protocol should use real client IP for per-IP limiting (#539)

	trustedNetworks := []string{"127.0.0.0/8"} // localhost is trusted for PROXY protocol
	server, address := setupIMAPServerWithProxyProtocol(t, 10, 2, trustedNetworks)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// First connection from real client 192.168.1.100 should succeed
	conn1 := connectWithProxyHeader(t, address, "192.168.1.100", 12345)
	connections = append(connections, conn1)

	// Read welcome banner to confirm connection works
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1000)
	n, err := conn1.Read(buffer)
	if err != nil || n == 0 {
		t.Fatalf("Failed to read IMAP welcome banner from first connection: %v", err)
	}
	response := string(buffer[:n])
	if !strings.Contains(response, "* OK") {
		t.Fatalf("Expected IMAP welcome banner, got: %s", strings.TrimSpace(response))
	}

	// Second connection from same real client IP should succeed
	conn2 := connectWithProxyHeader(t, address, "192.168.1.100", 12346)
	connections = append(connections, conn2)

	// Read welcome banner to confirm second connection works
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn2.Read(buffer)
	if err != nil || n == 0 {
		t.Fatalf("Failed to read IMAP welcome banner from second connection: %v", err)
	}

	// Third connection from same real client IP should be rejected due to per-IP limit
	conn3, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Logf("Third connection rejected at network level (expected): %v", err)
		return
	}
	connections = append(connections, conn3)

	// Send PROXY header for third connection
	serverHost, serverPortStr, _ := net.SplitHostPort(address)
	serverPort := 0
	fmt.Sscanf(serverPortStr, "%d", &serverPort)
	proxyHeader := generateProxyV1Header("192.168.1.100", 12347, serverHost, serverPort)
	_, err = conn3.Write([]byte(proxyHeader))
	if err != nil {
		t.Logf("Failed to send PROXY header on third connection (connection likely closed): %v", err)
		return
	}

	// Read from the third connection: the refusal is answered with a BYE greeting, so
	// the PROXY peer can tell it from a dead backend (#703)
	conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = conn3.Read(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:n]), "* BYE ") {
		t.Fatalf("third connection from the same real client IP: %q, %v; want max_connections_per_ip = 2 to refuse it with a BYE greeting", string(buffer[:n]), err)
	}

	t.Logf("Third connection from same real client IP properly refused: %s", strings.TrimSpace(string(buffer[:n])))
}

func TestProxyProtocolConnectionLimitsDifferentClientIPs(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test scenario:
	// - Server allows 10 total connections, 2 per IP
	// - All connections come from localhost (trusted proxy)
	// - Real client IPs are different (192.168.1.100, 192.168.1.101)
	// - Each real client IP should be allowed up to 2 connections

	trustedNetworks := []string{"127.0.0.0/8"} // localhost is trusted
	server, address := setupIMAPServerWithProxyProtocol(t, 10, 2, trustedNetworks)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Two connections from first real client IP
	conn1 := connectWithProxyHeader(t, address, "192.168.1.100", 12345)
	connections = append(connections, conn1)

	conn2 := connectWithProxyHeader(t, address, "192.168.1.100", 12346)
	connections = append(connections, conn2)

	// Two connections from second real client IP should also work
	conn3 := connectWithProxyHeader(t, address, "192.168.1.101", 12345)
	connections = append(connections, conn3)

	conn4 := connectWithProxyHeader(t, address, "192.168.1.101", 12346)
	connections = append(connections, conn4)

	// Verify all connections work by reading welcome banners
	for i, conn := range connections {
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

	t.Logf("Successfully established 4 connections from 2 different real client IPs through proxy")
}

func TestProxyProtocolTrustedNetworkBypassesPerIPLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test scenario:
	// - Server allows 10 total connections, 2 per IP
	// - Proxy (localhost) is in trusted networks, and so is the client it names
	// - A client in trusted networks bypasses per-IP limits

	trustedNetworks := []string{"127.0.0.0/8", "10.0.0.0/24"} // localhost and the client are trusted
	server, address := setupIMAPServerWithProxyProtocol(t, 10, 2, trustedNetworks)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Multiple connections from the same trusted client should all succeed
	// even though they exceed per-IP limit
	for i := 0; i < 5; i++ {
		conn := connectWithProxyHeader(t, address, "10.0.0.7", 12345+i)
		connections = append(connections, conn)

		// Verify connection works
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

	t.Logf("Successfully established 5 connections from a trusted client behind the trusted proxy, bypassing per-IP limits")
}

func TestProxyProtocolDifferentRealClientIPsAllowed(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test scenario:
	// - PROXY protocol trusts localhost for header parsing
	// - Connection limiting counts the real client each header names, not localhost
	// - Connections have different real client IPs via PROXY headers
	// - Each real client IP should be allowed up to the per-IP limit

	trustedNetworks := []string{"127.0.0.0/8"} // localhost trusted for PROXY protocol
	server, address := setupIMAPServerWithProxyProtocol(t, 10, 2, trustedNetworks)
	defer server.Close()

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Test different real client IPs should each get their own per-IP limit
	clientIPs := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}

	for _, clientIP := range clientIPs {
		// Two connections per client IP should succeed
		for j := 0; j < 2; j++ {
			conn := connectWithProxyHeader(t, address, clientIP, 12345+j)
			connections = append(connections, conn)

			// Verify connection works
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 1000)
			n, err := conn.Read(buffer)
			if err != nil || n == 0 {
				t.Fatalf("Failed to read IMAP welcome banner from client %s connection %d: %v", clientIP, j+1, err)
			}
			response := string(buffer[:n])
			if !strings.Contains(response, "* OK") {
				t.Fatalf("Client %s connection %d: Expected IMAP welcome banner, got: %s", clientIP, j+1, strings.TrimSpace(response))
			}
		}
		t.Logf("Successfully established 2 connections from real client IP %s", clientIP)
	}

	t.Logf("Successfully established 6 total connections from 3 different real client IPs (2 each)")
}
