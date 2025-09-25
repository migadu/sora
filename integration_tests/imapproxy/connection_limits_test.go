//go:build integration

package imapproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyPerIPConnectionLimiting tests that IMAP proxy properly limits
// connections per IP based on trusted_networks configuration
func TestIMAPProxyPerIPConnectionLimiting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with PROXY protocol support
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy with connection limits
	proxyAddress := common.GetRandomAddress(t)
	
	// Test scenario:
	// - maxTotal=10, maxPerIP=2 
	// - trusted_networks=["192.168.1.0/24"] (specific trusted network, NOT localhost)
	// - Connections from 127.0.0.1 should be limited to 2 per IP
	// - Connections from 192.168.1.100 should be unlimited (trusted)
	
	proxy := setupIMAPProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress, 
		[]string{backendServer.Address}, 10, 2, []string{"192.168.1.0/24"})
	defer proxy.Close()

	t.Log("=== Testing IMAP Proxy Per-IP Connection Limiting ===")
	t.Logf("Proxy config: maxTotal=10, maxPerIP=2, trustedNetworks=[192.168.1.0/24]")
	t.Logf("Expected: localhost connections limited to 2, 192.168.1.x unlimited")

	// Test 1: Connections from localhost (NOT in trusted networks) should be limited
	t.Log("\n--- Test 1: Non-trusted IP (localhost) should be limited to maxPerIP ---")
	
	var connections []*imapclient.Client
	defer func() {
		for _, c := range connections {
			if c != nil {
				c.Close()
			}
		}
	}()

	// First connection from localhost should succeed
	conn1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	connections = append(connections, conn1)
	t.Log("✓ First connection from localhost succeeded")

	// Second connection from localhost should succeed (within limit)
	conn2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Second connection should succeed: %v", err)
	}
	connections = append(connections, conn2)
	t.Log("✓ Second connection from localhost succeeded")

	// Third connection from localhost should be REJECTED (exceeds maxPerIP=2)
	t.Log("Attempting third connection from localhost (should be rejected)...")
	conn3, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Logf("✓ Third connection correctly rejected during dial: %v", err)
	} else {
		defer conn3.Close()
		// Connection is accepted at TCP level but should be closed quickly by proxy limiter
		time.Sleep(200 * time.Millisecond)
		
		// Try to perform a simple operation like LIST to test if connection is alive
		listCmd := conn3.List("", "*", nil)
		_, err := listCmd.Collect()
		if err != nil {
			t.Logf("✓ Third connection was closed by limiter (LIST failed): %v", err)
		} else {
			connections = append(connections, conn3)
			t.Errorf("❌ Third connection accepted LIST command - should have been rejected due to maxPerIP=2")
		}
	}

	// Clean up connections for next test
	for i, c := range connections {
		if c != nil {
			c.Close()
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

// TestIMAPProxyConnectionLimitingBasic tests basic connection limiting functionality
func TestIMAPProxyConnectionLimitingBasic(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with PROXY protocol support
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy with very restrictive limits for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 3, 1, []string{}) // No trusted networks
	defer proxy.Close()

	t.Log("=== Testing Basic IMAP Proxy Connection Limiting ===")
	t.Logf("Proxy config: maxTotal=3, maxPerIP=1, trustedNetworks=[]")

	var connections []*imapclient.Client
	defer func() {
		for _, c := range connections {
			if c != nil {
				c.Close()
			}
		}
	}()

	// First connection should succeed
	conn1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	connections = append(connections, conn1)
	
	// Try to authenticate to verify the connection works end-to-end
	if err := conn1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Failed to authenticate first connection: %v", err)
	}
	t.Log("✓ First connection succeeded and authenticated")

	// Second connection from same IP should be rejected (maxPerIP=1)
	t.Log("Attempting second connection from same IP (should be rejected)...")
	conn2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Logf("✓ Second connection correctly rejected during dial: %v", err)
	} else {
		defer conn2.Close()
		// Connection is accepted at TCP level but should be closed quickly by proxy limiter
		time.Sleep(200 * time.Millisecond)
		
		// Try to perform a simple operation like LIST to test if connection is alive
		listCmd := conn2.List("", "*", nil)
		_, err := listCmd.Collect()
		if err != nil {
			t.Logf("✓ Second connection was closed by limiter (LIST failed): %v", err)
		} else {
			connections = append(connections, conn2)
			t.Errorf("❌ Second connection accepted LIST command - should have been rejected due to maxPerIP=1")
		}
	}
}

// setupIMAPProxyWithConnectionLimits creates an IMAP proxy with connection limiting
func setupIMAPProxyWithConnectionLimits(t *testing.T, rdb *resilient.ResilientDatabase, 
	proxyAddr string, backendAddrs []string, maxConnections, maxConnectionsPerIP int, 
	trustedNetworks []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-limits"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-limits",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         5 * time.Second,
		SessionTimeout:         10 * time.Minute,
		EnableAffinity:         false,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		
		// NEW: Connection limiting options (to be implemented)
		MaxConnections:      maxConnections,
		MaxConnectionsPerIP: maxConnectionsPerIP,
		TrustedNetworks:     trustedNetworks,
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with limits: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && 
		   !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
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