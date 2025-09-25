//go:build integration

package pop3proxy

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxySimpleConnectionLimit tests basic connection limiting without authentication
func TestPOP3ProxySimpleConnectionLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, _ := common.SetupPOP3Server(t)
	defer backendServer.Close()

	// Set up POP3 proxy with maxPerIP=1 (very restrictive for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithConnectionLimits(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, 5, 1, []string{}) // No trusted networks
	defer proxy.Close()

	t.Log("=== Testing Simple POP3 Proxy Connection Limiting ===")
	t.Logf("Proxy config: maxTotal=5, maxPerIP=1, trustedNetworks=[]")
	t.Log("Testing TCP connections only (no POP3 authentication)")

	// First connection should succeed
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	defer conn1.Close()
	t.Log("✓ First connection succeeded")

	// Give a moment for the connection to be processed
	time.Sleep(100 * time.Millisecond)

	// Second connection from same IP should be REJECTED (maxPerIP=1)
	t.Log("Attempting second connection from same IP (should be rejected)...")
	conn2, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Logf("✓ Second connection correctly rejected during dial: %v", err)
	} else {
		defer conn2.Close()
		// Connection is accepted at TCP level but should be closed quickly by proxy limiter
		time.Sleep(200 * time.Millisecond)

		// Try to read from connection - should fail if proxy closed it
		conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn2.Read(buffer)
		if err != nil {
			t.Logf("✓ Second connection was closed by limiter (read failed): %v", err)
		} else if n == 0 {
			t.Logf("✓ Second connection was closed by limiter (no data)")
		} else {
			t.Errorf("❌ Second connection received data: %s", string(buffer[:n]))
		}
	}

	t.Log("Connection limiting test completed")
}
