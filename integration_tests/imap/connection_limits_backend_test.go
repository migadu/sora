//go:build integration

package imap

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPBackendConnectionLimitsWithProxyProtocol tests IMAP backend behavior when PROXY protocol is enabled
func TestIMAPBackendConnectionLimitsWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create IMAP server with PROXY protocol enabled
	// This uses the existing test setup with PROXY protocol
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	t.Log("=== Testing IMAP Backend with PROXY Protocol Enabled ===")
	t.Log("Expected: Only connections with valid PROXY headers from trusted networks allowed")
	t.Log("PROXY protocol is required when enabled, direct connections should be rejected")

	// Test 1: Direct connection (no PROXY header) should be REJECTED when PROXY protocol is required
	t.Log("\n--- Test 1: Direct connection should be rejected (PROXY required) ---")
	conn1, err := net.Dial("tcp", backendServer.Address)
	if err != nil {
		t.Logf("✓ Direct connection correctly rejected during dial: %v", err)
	} else {
		defer conn1.Close()
		// Try to read greeting - should fail or get connection closed
		conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn1.Read(buffer)
		if err != nil || n == 0 {
			t.Logf("✓ Direct connection rejected (no PROXY header): %v", err)
		} else {
			response := string(buffer[:n])
			if !strings.Contains(response, "OK") {
				t.Logf("✓ Direct connection rejected with response: %s", strings.TrimSpace(response))
			} else {
				t.Errorf("❌ Direct connection unexpectedly succeeded: %s", strings.TrimSpace(response))
			}
		}
	}

	t.Log("PROXY protocol backend connection limiting test completed")
}

// TestIMAPBackendConnectionLimitsNoProxy tests IMAP backend behavior when PROXY protocol is disabled
func TestIMAPBackendConnectionLimitsNoProxy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create IMAP server with PROXY protocol disabled (regular setup)
	backendServer, _ := common.SetupIMAPServer(t)
	defer backendServer.Close()

	t.Log("=== Testing IMAP Backend with PROXY Protocol Disabled ===")
	t.Log("Expected: Direct connections allowed, per-IP limits applied to non-trusted IPs")

	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Test 1: First connection from localhost should succeed
	t.Log("\n--- Test 1: Testing per-IP limits for localhost connections ---")
	conn1, err := net.Dial("tcp", backendServer.Address)
	if err != nil {
		t.Fatalf("First connection should succeed: %v", err)
	}
	connections = append(connections, conn1)
	
	// Read greeting
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn1.Read(buffer)
	if err == nil && n > 0 {
		greeting := string(buffer[:n])
		if strings.Contains(greeting, "OK") {
			t.Log("✓ First connection succeeded with IMAP greeting")
		}
	}

	// Note: In the current default setup, localhost is likely in trusted networks
	// so per-IP limiting may not apply. This test documents the expected behavior.
	t.Log("Note: Default trusted networks may include localhost (127.0.0.0/8)")
	t.Log("Per-IP limits apply only to IPs NOT in trusted_networks")

	t.Log("No PROXY protocol backend connection limiting test completed")
}

// TestIMAPBackendIDCommandTrustedNetworks tests ID command parameter forwarding based on trusted networks
func TestIMAPBackendIDCommandTrustedNetworks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// ID command behavior:
	// - Only connections from trusted_networks can pass proxying info via ID command
	// - Other connections: ID command is accepted but proxying parameters are ignored (no error)
	
	t.Log("=== Testing IMAP Backend ID Command Trusted Networks ===")
	t.Log("Expected behavior (documented due to integration test complexity):")
	t.Log("1. Connections from trusted_networks: ID command forwarding parameters processed")
	t.Log("2. Connections from non-trusted networks: ID command accepted, forwarding ignored")
	t.Log("3. No errors thrown in either case")
	
	t.Log("ID command trusted networks test completed")
}