//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/managesieveproxy"
)

// TestProxyProtocolIncoming tests that ManageSieve proxy can receive PROXY protocol headers
// This simulates HAProxy → Sora Proxy → Sora Backend
func TestProxyProtocolIncoming(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with PROXY protocol enabled
	backendServer, account := setupManageSieveBackendWithPROXY(t)
	defer backendServer.Close()

	// Set up ManageSieve proxy with PROXY protocol enabled for BOTH incoming and outgoing connections
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithPROXYIncoming(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("without_proxy_header", func(t *testing.T) {
		// Connection without PROXY header - should fail because proxy_protocol=true (required mode)
		conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Set read deadline to prevent test hanging
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Try to read greeting - should fail or timeout because proxy expects PROXY header
		greeting, err := reader.ReadString('\n')
		if err != nil {
			// Expected: connection should be closed or timeout waiting for PROXY header
			t.Logf("Expected failure: connection closed without PROXY header: %v", err)
			return
		}

		// If we got a greeting, something is wrong (PROXY protocol not enforced)
		t.Fatalf("Unexpected: received greeting without PROXY header (PROXY protocol not enforced): %s", greeting)
	})

	t.Run("with_proxy_header", func(t *testing.T) {
		// Connection with PROXY header - should work and forward the real client IP to backend
		conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send PROXY v2 header with real client IP
		realClientIP := "203.0.113.42"
		realClientPort := 54321
		serverIP := "127.0.0.1"
		serverPort := conn.LocalAddr().(*net.TCPAddr).Port

		header, err := server.GenerateProxyV2Header(realClientIP, realClientPort, serverIP, serverPort, "TCP4")
		if err != nil {
			t.Fatalf("Failed to generate PROXY header: %v", err)
		}

		_, err = conn.Write(header)
		if err != nil {
			t.Fatalf("Failed to send PROXY header: %v", err)
		}

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Try to read greeting (capabilities followed by OK)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var greetingLines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read greeting after PROXY header: %v", err)
			}
			greetingLines = append(greetingLines, line)
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "OK") {
				break
			}
		}

		t.Logf("Greeting after PROXY header: %v", greetingLines)
		lastLine := strings.TrimSpace(greetingLines[len(greetingLines)-1])
		if !strings.HasPrefix(lastLine, "OK") {
			t.Fatalf("Invalid greeting after PROXY header: %s", lastLine)
		}

		// Try to authenticate using PLAIN mechanism
		authString := "\x00" + account.Email + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))
		authCmd := fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)

		writer.WriteString(authCmd)
		writer.Flush()

		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
		}
		t.Logf("AUTHENTICATE response: %s", strings.TrimSpace(resp))

		// Should succeed with PROXY protocol support
		if !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Fatalf("Expected successful AUTHENTICATE with PROXY protocol, got: %s", resp)
		}

		// Cleanup - send LOGOUT
		writer.WriteString("LOGOUT\r\n")
		writer.Flush()

		// Read LOGOUT response
		logoutResp, err := reader.ReadString('\n')
		if err == nil {
			t.Logf("LOGOUT response: %s", strings.TrimSpace(logoutResp))
		}

		t.Log("SUCCESS: PROXY protocol incoming support is working for ManageSieve!")
		// TODO: Add verification that backend saw real client IP (203.0.113.42)
		// This could be done by checking logs or adding a test endpoint
	})
}

// setupManageSieveBackendWithPROXY creates a ManageSieve backend server with PROXY protocol enabled
func setupManageSieveBackendWithPROXY(t *testing.T) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Import necessary package
	managesieveServer, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:         true,
			MasterUsername:       "master_admin",
			MasterPassword:       "master_secret_789",
			MasterSASLUsername:   "master_sasl",
			MasterSASLPassword:   "master_sasl_secret",
			ProxyProtocol:        true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout: "5s",                               // Timeout for PROXY headers
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			SupportedExtensions:  []string{"fileinto", "vacation", "envelope", "variables"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server with PROXY support: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		managesieveServer.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     address,
		Server:      managesieveServer,
		ResilientDB: rdb,
	}

	testServer.SetCleanup(func() {
		managesieveServer.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("ManageSieve server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer, account
}

// setupManageSieveProxyWithPROXYIncoming creates ManageSieve proxy with PROXY protocol enabled on both sides
func setupManageSieveProxyWithPROXYIncoming(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-protocol-both"
	masterSASLUsername := "master_sasl"
	masterSASLPassword := "master_sasl_secret"

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-proxy-protocol-both",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             4190,
		MasterSASLUsername:     masterSASLUsername,
		MasterSASLPassword:     masterSASLPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		InsecureAuth:           true, // Allow authentication over non-TLS for testing
		RemoteUseProxyProtocol: true, // Enable PROXY protocol to backend
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		CommandTimeout:         5 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies:       []string{"127.0.0.0/8", "::1/128"},
		TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Required for PROXY protocol validation
		ProxyProtocol:        true,                               // Enable PROXY protocol for incoming connections
		ProxyProtocolTimeout: "5s",                               // Timeout for reading PROXY headers
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("ManageSieve proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}

	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("ManageSieve proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer
}
