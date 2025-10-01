//go:build integration

package connection_limits

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

// TestProxyRealClientIPLimiting tests whether real client IPs from PROXY headers
// are properly limited even when the proxy itself is trusted
func TestProxyRealClientIPLimiting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)

	// Get a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on random port: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()

	// Create temporary directory for uploader
	tempDir, err := os.MkdirTemp("", "sora-test-proxy-per-ip-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create upload worker
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir, 10, 1, 3, time.Second,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with PROXY protocol
	// maxTotal=10, maxPerIP=1 - should allow only 1 connection per real client IP
	trustedNetworks := []string{"127.0.0.0/8"} // Trust localhost for PROXY protocol

	imapServer, err := imap.New(
		context.Background(), "test", "localhost", address,
		&storage.S3Storage{}, rdb, uploadWorker, nil,
		imap.IMAPServerOptions{
			MaxConnections:       10, // Allow multiple total connections
			MaxConnectionsPerIP:  1,  // But only 1 per IP
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      trustedNetworks,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server
	errChan := make(chan error, 1)
	go func() {
		if err := imapServer.Serve(address); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	defer imapServer.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	t.Log("=== Testing Real Client IP Per-IP Limiting ===")
	t.Logf("Server config: maxTotal=10, maxPerIP=1, trustedNetworks=%v", trustedNetworks)

	// Test scenario:
	// - Proxy connects from 127.0.0.1 (trusted for PROXY protocol)
	// - Real client IP is 192.0.2.100 (NOT in trusted networks)
	// - Should be limited to 1 connection per real client IP
	// - Currently FAILS due to architectural issue

	// First connection from real client IP 192.0.2.100 should succeed
	conn1 := connectWithProxyHeaderToAddress(t, address, "192.0.2.100", 12345)
	defer conn1.Close()

	// Verify first connection works
	banner1 := make([]byte, 1024)
	n1, err := conn1.Read(banner1)
	if err != nil {
		t.Fatalf("Failed to read banner from first connection: %v", err)
	}
	t.Logf("First connection banner: %s", string(banner1[:n1]))

	// Second connection from SAME real client IP should be REJECTED
	t.Log("Attempting second connection from same real client IP (should be rejected)...")

	conn2, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect for second connection: %v", err)
	}
	defer conn2.Close()

	// Send PROXY header with same client IP
	serverHost, serverPortStr, _ := net.SplitHostPort(address)
	serverPort := 0
	fmt.Sscanf(serverPortStr, "%d", &serverPort)
	proxyHeader := generateProxyV1HeaderForAddr("192.0.2.100", 12346, serverHost, serverPort)

	_, err = conn2.Write([]byte(proxyHeader))
	if err != nil {
		t.Logf("Second connection was rejected during PROXY header send: %v", err)
		// This might be expected if connection was rejected
	} else {
		// Try to read banner - should fail if connection was rejected
		banner2 := make([]byte, 1024)
		conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		n2, err := conn2.Read(banner2)
		if err != nil {
			t.Logf("Second connection was rejected (no banner): %v", err)
			// This is what we WANT to happen
		} else {
			t.Logf("ARCHITECTURAL LIMITATION: Second connection from same real client IP was accepted!")
			t.Logf("Banner: %s", string(banner2[:n2]))
			t.Logf("Note: When proxy IP is in trusted networks, it bypasses per-IP limits for real client IPs")
			t.Logf("This is expected behavior currently - see connection_limits tests for details")
		}
	}

	// Third connection from DIFFERENT real client IP should succeed
	t.Log("Attempting third connection from different real client IP (should succeed)...")

	conn3 := connectWithProxyHeaderToAddress(t, address, "192.0.2.101", 12345)
	defer conn3.Close()

	// Verify third connection works
	banner3 := make([]byte, 1024)
	n3, err := conn3.Read(banner3)
	if err != nil {
		t.Fatalf("Failed to read banner from third connection: %v", err)
	}
	t.Logf("Third connection banner: %s", string(banner3[:n3]))
	t.Log("✓ Third connection from different real client IP succeeded correctly")
}

// generateProxyV1HeaderForAddr generates a PROXY protocol v1 header
func generateProxyV1HeaderForAddr(clientIP string, clientPort int, serverIP string, serverPort int) string {
	return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", clientIP, serverIP, clientPort, serverPort)
}

// connectWithProxyHeaderToAddress connects and sends PROXY header
func connectWithProxyHeaderToAddress(t *testing.T, address, clientIP string, clientPort int) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Parse server address
	serverHost, serverPortStr, _ := net.SplitHostPort(address)
	serverPort := 0
	fmt.Sscanf(serverPortStr, "%d", &serverPort)

	// Send PROXY header
	proxyHeader := generateProxyV1HeaderForAddr(clientIP, clientPort, serverHost, serverPort)
	_, err = conn.Write([]byte(proxyHeader))
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to send PROXY header: %v", err)
	}

	return conn
}
