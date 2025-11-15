//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestProxyProtocolIncoming tests that Sora proxy can receive PROXY protocol headers
// This simulates HAProxy → Sora Proxy → Sora Backend
func TestProxyProtocolIncoming(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with PROXY protocol enabled
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy with PROXY protocol enabled for BOTH incoming and outgoing connections
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithIncomingAndOutgoingPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
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
		// Connection with PROXY header - currently will fail because proxy doesn't read it
		// After implementation, this should work and forward the real client IP to backend
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

		// Try to read greeting
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting after PROXY header: %v", err)
		}

		t.Logf("Greeting after PROXY header: %s", greeting)
		if !strings.Contains(greeting, "OK") {
			t.Fatalf("Invalid greeting after PROXY header: %s", greeting)
		}

		// Try to login
		loginCmd := fmt.Sprintf("a001 LOGIN %s %s\r\n", account.Email, account.Password)
		writer.WriteString(loginCmd)
		writer.Flush()

		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LOGIN response: %v", err)
		}
		t.Logf("LOGIN response: %s", resp)

		// Should succeed with PROXY protocol support
		if !strings.Contains(resp, "OK") {
			t.Fatalf("Expected successful LOGIN with PROXY protocol, got: %s", resp)
		}

		// Cleanup
		writer.WriteString("a002 LOGOUT\r\n")
		writer.Flush()

		// Read LOGOUT responses
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			t.Logf("LOGOUT response: %s", line)
			if strings.Contains(line, "a002 OK") {
				break
			}
		}

		t.Log("SUCCESS: PROXY protocol incoming support is working!")
		// TODO: Add verification that backend saw real client IP (203.0.113.42)
		// This could be done by checking logs or adding a test endpoint
	})
}

// setupIMAPProxyWithIncomingAndOutgoingPROXY creates IMAP proxy with PROXY protocol enabled on both sides
func setupIMAPProxyWithIncomingAndOutgoingPROXY(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-protocol-both"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-protocol-both",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,  // Enable PROXY protocol to backend
		RemoteUseIDCommand:     false, // Disable ID command (using PROXY instead)
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies:       []string{"127.0.0.0/8", "::1/128"},
		TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		ProxyProtocol:        true, // Enable PROXY protocol for incoming connections
		ProxyProtocolTimeout: "5s", // Timeout for reading PROXY headers
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
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
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer
}
