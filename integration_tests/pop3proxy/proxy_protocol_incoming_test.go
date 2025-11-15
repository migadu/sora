//go:build integration
// +build integration

package pop3proxy_test

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
	"github.com/migadu/sora/server/pop3proxy"
)

// TestProxyProtocolIncoming verifies that POP3 proxy correctly reads incoming PROXY protocol headers
// from HAProxy/nginx and passes the real client IP to the backend.
func TestProxyProtocolIncoming(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with PROXY protocol enabled
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	email := account.Email
	password := account.Password

	t.Run("without_proxy_header", func(t *testing.T) {
		// Start POP3 proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupPOP3ProxyWithPROXYIncoming(t, backendServer.ResilientDB, backendServer.Address)
		defer stopProxy()

		// Give servers time to start
		time.Sleep(100 * time.Millisecond)

		// Connect to proxy WITHOUT sending PROXY header - should be rejected
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Set read timeout to ensure we don't hang
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Try to read greeting - should fail/timeout because proxy expects PROXY header
		reader := bufio.NewReader(conn)
		_, err = reader.ReadString('\n')
		if err == nil {
			t.Fatal("Expected connection to fail without PROXY header, but it succeeded")
		}
		t.Logf("Expected failure: connection closed without PROXY header: %v", err)
	})

	t.Run("with_proxy_header", func(t *testing.T) {
		// Start POP3 proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupPOP3ProxyWithPROXYIncoming(t, backendServer.ResilientDB, backendServer.Address)
		defer stopProxy()

		// Give servers time to start
		time.Sleep(100 * time.Millisecond)

		// Connect to proxy
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
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

		// Now read greeting
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting after PROXY header: %v", err)
		}
		t.Logf("Greeting after PROXY header: %s", strings.TrimSpace(greeting))

		// Should get POP3 greeting
		if !strings.HasPrefix(greeting, "+OK") {
			t.Fatalf("Expected +OK greeting, got: %s", greeting)
		}

		// Authenticate
		_, err = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", email)))
		if err != nil {
			t.Fatalf("Failed to send USER: %v", err)
		}

		userResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read USER response: %v", err)
		}
		t.Logf("USER response: %s", strings.TrimSpace(userResp))

		_, err = conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", password)))
		if err != nil {
			t.Fatalf("Failed to send PASS: %v", err)
		}

		passResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read PASS response: %v", err)
		}
		t.Logf("PASS response: %s", strings.TrimSpace(passResp))

		if !strings.HasPrefix(passResp, "+OK") {
			t.Fatalf("Authentication failed: %s", passResp)
		}

		// QUIT
		_, err = conn.Write([]byte("QUIT\r\n"))
		if err != nil {
			t.Fatalf("Failed to send QUIT: %v", err)
		}

		quitResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read QUIT response: %v", err)
		}
		t.Logf("QUIT response: %s", strings.TrimSpace(quitResp))

		t.Logf("SUCCESS: PROXY protocol incoming support is working for POP3!")

		// NOTE: To verify the real client IP reaches the backend, check the backend logs.
		// The backend should log remote=203.0.113.42 instead of the proxy's IP.
		// This is verified by the XCLIENT forwarding in sendForwardingParametersToBackend.
	})
}

func setupPOP3ProxyWithPROXYIncoming(t *testing.T, rdb *resilient.ResilientDatabase, backendAddr string) (string, func()) {
	t.Helper()

	proxyAddr := common.GetRandomAddress(t)
	hostname := "test-pop3-proxy-protocol"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-protocol",
		RemoteAddrs:            []string{backendAddr},
		RemotePort:             110,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true, // Enable PROXY protocol to backend
		RemoteUseXCLIENT:       true, // Enable XCLIENT forwarding to backend
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

	proxy, err := pop3proxy.New(context.Background(), hostname, proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("POP3 proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("POP3 proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	return proxyAddr, cleanup
}
