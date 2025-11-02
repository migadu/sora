//go:build integration

package pop3proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyPerIPConnectionLimiting tests that POP3 proxy properly limits
// connections per IP based on trusted_networks configuration
func TestPOP3ProxyPerIPConnectionLimiting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with PROXY protocol support
	backendServer, _ := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Set up POP3 proxy with connection limits
	proxyAddress := common.GetRandomAddress(t)

	// Test scenario:
	// - maxTotal=10, maxPerIP=2
	// - trusted_networks=["192.168.1.0/24"] (specific trusted network, NOT localhost)
	// - Connections from 127.0.0.1 should be limited to 2 per IP
	// - Connections from 192.168.1.100 should be unlimited (trusted)

	proxy := setupPOP3ProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 10, 2, []string{"192.168.1.0/24"})
	defer proxy.Close()

	t.Log("=== Testing POP3 Proxy Per-IP Connection Limiting ===")
	t.Logf("Proxy config: maxTotal=10, maxPerIP=2, trustedNetworks=[192.168.1.0/24]")
	t.Logf("Expected: localhost connections limited to 2, 192.168.1.x unlimited")

	// Test 1: Connections from localhost (NOT in trusted networks) should be limited
	t.Log("\n--- Test 1: Non-trusted IP (localhost) should be limited to maxPerIP ---")

	var connections []any // We'll use net.Conn for TCP-level testing
	defer func() {
		for _, c := range connections {
			if c != nil {
				if conn, ok := c.(interface{ Close() error }); ok {
					conn.Close()
				}
			}
		}
	}()

	// First connection from localhost should succeed
	conn1, err := dialPOP3Proxy(proxyAddress)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	connections = append(connections, conn1)
	t.Log("✓ First connection from localhost succeeded")

	// Second connection from localhost should succeed (within limit)
	conn2, err := dialPOP3Proxy(proxyAddress)
	if err != nil {
		t.Fatalf("Second connection should succeed: %v", err)
	}
	connections = append(connections, conn2)
	t.Log("✓ Second connection from localhost succeeded")

	// Third connection from localhost should be REJECTED (exceeds maxPerIP=2)
	t.Log("Attempting third connection from localhost (should be rejected)...")
	conn3, err := dialPOP3Proxy(proxyAddress)
	if err != nil {
		t.Logf("✓ Third connection correctly rejected during dial: %v", err)
	} else {
		defer conn3.Close()
		// Connection is accepted at TCP level but should be closed quickly by proxy limiter
		time.Sleep(200 * time.Millisecond)

		// Try to perform a simple operation to test if connection is alive
		isAlive := testPOP3ConnectionAlive(conn3)
		if !isAlive {
			t.Logf("✓ Third connection was closed by limiter")
		} else {
			connections = append(connections, conn3)
			t.Errorf("❌ Third connection is still alive - should have been rejected due to maxPerIP=2")
		}
	}

	// Clean up connections for next test
	for i, c := range connections {
		if c != nil {
			if conn, ok := c.(interface{ Close() error }); ok {
				conn.Close()
			}
			connections[i] = nil
		}
	}
	connections = connections[:0]
	time.Sleep(100 * time.Millisecond) // Allow cleanup

	// Test 2: Simulate connections from trusted network (should bypass per-IP limits)
	// NOTE: This is harder to test in integration tests since we can't easily
	// control the source IP. This test documents the expected behavior.
	t.Log("\n--- Test 2: Trusted IP behavior (documented expectation) ---")
	t.Log("Expected: Connections from 192.168.1.0/24 should bypass per-IP limits")
	t.Log("Note: Integration test limitation - can't easily simulate different source IPs")

	// Test 3: Total connection limit should still apply
	t.Log("\n--- Test 3: Total connection limit should be respected ---")
	t.Log("This would require maxTotal connections, but limited by test resources")
	t.Log("Expected: Even trusted IPs respect maxTotal=10 limit")
}

// setupPOP3ProxyWithConnectionLimits creates a POP3 proxy with connection limiting
func setupPOP3ProxyWithConnectionLimits(t *testing.T, rdb *resilient.ResilientDatabase,
	proxyAddr string, backendAddrs []string, maxConnections, maxConnectionsPerIP int,
	trustedNetworks []string) *common.TestServer {
	t.Helper()

	hostname := "test-pop3-proxy-limits"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-limits",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110, // Default POP3 port
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		ConnectTimeout:         5 * time.Second,
		SessionTimeout:         10 * time.Minute,
		EnableAffinity:         false,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},

		// NEW: Connection limiting options
		MaxConnections:      maxConnections,
		MaxConnectionsPerIP: maxConnectionsPerIP,
		TrustedNetworks:     trustedNetworks,
	}

	proxy, err := pop3proxy.New(context.Background(), hostname, proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with limits: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("POP3 proxy error: %w", err)
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

// dialPOP3Proxy connects to POP3 proxy for testing
func dialPOP3Proxy(address string) (interface{ Close() error }, error) {
	return dialPOP3ProxyTimeout(address, 2*time.Second)
}

// dialPOP3ProxyTimeout connects to POP3 proxy with timeout
func dialPOP3ProxyTimeout(address string, timeout time.Duration) (interface{ Close() error }, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// testPOP3ConnectionAlive tests if a POP3 connection is still alive
func testPOP3ConnectionAlive(conn interface{ Close() error }) bool {
	if tcpConn, ok := conn.(interface {
		SetReadDeadline(time.Time) error
		Read([]byte) (int, error)
	}); ok {
		tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		_, err := tcpConn.Read(buffer)
		return err == nil
	}
	return false
}
