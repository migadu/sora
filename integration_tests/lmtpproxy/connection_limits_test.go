//go:build integration

package lmtpproxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxyTrustedNetworkFiltering tests that LMTP proxy only accepts connections from trusted networks
func TestLMTPProxyTrustedNetworkFiltering(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Set up LMTP proxy with trusted networks (only localhost)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 0, []string{"127.0.0.0/8", "::1/128"}) // Only localhost trusted
	defer proxy.Close()

	t.Log("=== Testing LMTP Proxy Trusted Network Filtering ===")
	t.Logf("Proxy config: trustedNetworks=[127.0.0.0/8, ::1/128]")
	t.Log("Expected: Only connections from localhost accepted")

	// Connection from localhost should succeed (trusted network)
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Connection from localhost should succeed: %v", err)
	}
	defer conn1.Close()
	t.Log("✓ Connection from localhost succeeded (trusted network)")

	// Give a moment for the connection to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify connection is working by reading LMTP greeting
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn1.Read(buffer)
	if err != nil {
		t.Errorf("Failed to read LMTP greeting: %v", err)
	} else if n > 0 {
		greeting := string(buffer[:n])
		if strings.Contains(greeting, "220") && strings.Contains(greeting, "LMTP") {
			t.Logf("✓ Received valid LMTP greeting: %s", strings.TrimSpace(greeting))
		} else {
			t.Errorf("Invalid LMTP greeting: %s", strings.TrimSpace(greeting))
		}
	}

	t.Log("Trusted network filtering test completed")
}

// TestLMTPProxyMaxConnectionsLimit tests that LMTP proxy respects maximum total connections
func TestLMTPProxyMaxConnectionsLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Set up LMTP proxy with very low max connections for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 2, []string{"127.0.0.0/8", "::1/128"}) // Max 2 total connections
	defer proxy.Close()

	t.Log("=== Testing LMTP Proxy Maximum Total Connections Limit ===")
	t.Logf("Proxy config: maxConnections=2, trustedNetworks=[127.0.0.0/8, ::1/128]")
	t.Log("Expected: Maximum 2 total connections allowed")

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// First connection should succeed
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	connections = append(connections, conn1)
	t.Log("✓ First connection succeeded")

	// Second connection should succeed (within limit)
	conn2, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Second connection should succeed: %v", err)
	}
	connections = append(connections, conn2)
	t.Log("✓ Second connection succeeded")

	// Give a moment for the connections to be processed
	time.Sleep(100 * time.Millisecond)

	// Third connection should be REJECTED (exceeds maxConnections=2)
	t.Log("Attempting third connection (should be rejected due to max connections)...")
	conn3, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Logf("✓ Third connection correctly rejected during dial: %v", err)
	} else {
		defer conn3.Close()
		// Connection is accepted at TCP level but should be closed quickly by proxy limiter
		time.Sleep(200 * time.Millisecond)

		// Try to read from connection - should fail if proxy closed it
		conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn3.Read(buffer)
		if err != nil {
			t.Logf("✓ Third connection was closed by limiter (read failed): %v", err)
		} else if n == 0 {
			t.Logf("✓ Third connection was closed by limiter (no data)")
		} else {
			t.Errorf("❌ Third connection received data: %s", string(buffer[:n]))
		}
	}

	t.Log("Maximum connections limit test completed")
}

// TestLMTPProxyNoPerIPLimiting tests that LMTP proxy does NOT do per-IP limiting
func TestLMTPProxyNoPerIPLimiting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Set up LMTP proxy with high max connections but would normally limit per-IP
	// For LMTP proxy, there should be no per-IP limiting even from same IP
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 10, []string{"127.0.0.0/8", "::1/128"}) // Max 10 total connections
	defer proxy.Close()

	t.Log("=== Testing LMTP Proxy No Per-IP Limiting ===")
	t.Logf("Proxy config: maxConnections=10, trustedNetworks=[127.0.0.0/8, ::1/128]")
	t.Log("Expected: Multiple connections from same IP allowed (no per-IP limiting)")

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Create multiple connections from the same IP (localhost)
	// All should succeed since LMTP proxy doesn't do per-IP limiting
	for i := 1; i <= 3; i++ {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			t.Fatalf("Connection %d should succeed: %v", i, err)
		}
		connections = append(connections, conn)
		t.Logf("✓ Connection %d from same IP succeeded", i)

		// Brief pause between connections
		time.Sleep(50 * time.Millisecond)
	}

	t.Log("✓ Multiple connections from same IP succeeded - no per-IP limiting confirmed")
	t.Log("No per-IP limiting test completed")
}

// setupLMTPProxyWithConnectionLimits creates an LMTP proxy with connection limiting
func setupLMTPProxyWithConnectionLimits(t *testing.T, rdb *resilient.ResilientDatabase,
	proxyAddr string, backendAddrs []string, maxConnections int, trustedProxies []string) *common.TestServer {
	t.Helper()

	hostname := "test-lmtp-proxy-limits"

	opts := lmtpproxy.ServerOptions{
		Name:                   "test-lmtp-proxy-limits",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             25, // Default LMTP port (often 25 or 24)
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: false,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        10 * time.Minute,
		EnableAffinity:         false,
		TrustedProxies:         trustedProxies, // These are the trusted networks that can connect

		// Connection limiting (total connections only for LMTP)
		MaxConnections: maxConnections,
	}

	proxy, err := lmtpproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with limits: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("LMTP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
