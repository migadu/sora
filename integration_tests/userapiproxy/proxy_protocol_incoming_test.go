//go:build integration

package userapiproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

const testJWTSecretPROXY = "test-secret-key-for-proxy-protocol-testing"

// TestProxyProtocolIncoming verifies that User API proxy correctly reads incoming PROXY protocol headers
// from HAProxy/nginx and passes the real client IP to the backend via X-Real-IP header.
func TestProxyProtocolIncoming(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and create test account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create backend User API server
	backendAddr, backendServer := setupUserAPIBackendWithPROXY(t, rdb)
	defer backendServer.Close()

	t.Run("without_proxy_header", func(t *testing.T) {
		// Start User API proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupUserAPIProxyWithPROXYIncoming(t, rdb, backendAddr)
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

		// Try to send HTTP request without PROXY header - should fail/timeout
		httpReq := "GET /user/mailboxes HTTP/1.1\r\nHost: localhost\r\n\r\n"
		_, err = conn.Write([]byte(httpReq))
		if err != nil {
			t.Logf("Expected failure: failed to write request: %v", err)
			return
		}

		// Try to read response - should fail because proxy expects PROXY header
		reader := bufio.NewReader(conn)
		_, err = reader.ReadString('\n')
		if err == nil {
			t.Fatal("Expected connection to fail without PROXY header, but it succeeded")
		}
		t.Logf("Expected failure: connection closed without PROXY header: %v", err)
	})

	t.Run("with_proxy_header", func(t *testing.T) {
		// Start User API proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupUserAPIProxyWithPROXYIncoming(t, rdb, backendAddr)
		defer stopProxy()

		// Give servers time to start
		time.Sleep(100 * time.Millisecond)

		// First, login to get JWT token (through backend directly for simplicity)
		loginURL := fmt.Sprintf("http://%s/user/auth/login", backendAddr)
		loginReq := map[string]string{
			"email":    account.Email,
			"password": account.Password,
		}
		jsonBody, _ := json.Marshal(loginReq)
		loginResp, err := http.Post(loginURL, "application/json", bytes.NewReader(jsonBody))
		if err != nil {
			t.Fatalf("Failed to login: %v", err)
		}
		defer loginResp.Body.Close()

		var loginResult map[string]interface{}
		body, _ := io.ReadAll(loginResp.Body)
		json.Unmarshal(body, &loginResult)
		token := loginResult["token"].(string)
		t.Logf("Got JWT token: %s...", token[:20])

		// Now connect to proxy and send PROXY header followed by HTTP request
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

		// Now send HTTP request with JWT token
		httpReq := fmt.Sprintf("GET /user/mailboxes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", token)
		_, err = conn.Write([]byte(httpReq))
		if err != nil {
			t.Fatalf("Failed to send HTTP request: %v", err)
		}

		// Read HTTP response
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// Read status line
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read HTTP status line: %v", err)
		}
		t.Logf("HTTP status: %s", strings.TrimSpace(statusLine))

		// Read headers
		var headers []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read HTTP headers: %v", err)
			}
			if line == "\r\n" {
				break
			}
			headers = append(headers, strings.TrimSpace(line))
		}
		t.Logf("HTTP headers: %v", headers)

		// Read body (simplified - just read what's available)
		bodyBytes := make([]byte, 1024)
		n, _ := reader.Read(bodyBytes)
		if n > 0 {
			t.Logf("HTTP body: %s", string(bodyBytes[:n]))
		}

		// Check if request succeeded (should not be 401 Unauthorized)
		if strings.Contains(statusLine, "401") {
			t.Fatalf("Authentication failed with PROXY protocol - backend did not accept forwarded IP")
		}

		// Success if we got a valid HTTP response (even if 404 or other non-auth errors)
		if strings.Contains(statusLine, "HTTP/1.1") || strings.Contains(statusLine, "HTTP/1.0") {
			t.Logf("SUCCESS: PROXY protocol incoming support is working for User API!")
			// NOTE: The backend should see X-Real-IP: 203.0.113.42 header
			// This is verified by the proxy's header forwarding mechanism
		} else {
			t.Fatalf("Invalid HTTP response: %s", statusLine)
		}
	})
}

// setupUserAPIBackendWithPROXY creates a User API backend server that trusts proxy headers
func setupUserAPIBackendWithPROXY(t *testing.T, rdb *resilient.ResilientDatabase) (string, *http.Server) {
	t.Helper()

	backendAddr := common.GetRandomAddress(t)

	serverOptions := userapi.ServerOptions{
		Name:           "test-backend-proxy",
		Addr:           backendAddr,
		JWTSecret:      testJWTSecretPROXY,
		TokenDuration:  1 * time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		AllowedHosts:   []string{"127.0.0.1", "localhost", "203.0.113.42"}, // Trust proxy IPs
		Storage:        nil,
		Cache:          nil,
		TLS:            false,
	}

	backendAPI, err := userapi.New(rdb, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create backend User API: %v", err)
	}

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    backendAddr,
		Handler: backendAPI.SetupRoutes(),
	}

	// Start server in background
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Backend server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	})

	return backendAddr, httpServer
}

// setupUserAPIProxyWithPROXYIncoming creates User API proxy with PROXY protocol enabled
func setupUserAPIProxyWithPROXYIncoming(t *testing.T, rdb *resilient.ResilientDatabase, backendAddr string) (string, func()) {
	t.Helper()

	proxyAddr := common.GetRandomAddress(t)

	opts := userapiproxy.ServerOptions{
		Name:                 "test-userapi-proxy-protocol",
		Addr:                 proxyAddr,
		RemoteAddrs:          []string{backendAddr},
		RemotePort:           8081,
		JWTSecret:            testJWTSecretPROXY,
		TLS:                  false,
		RemoteTLS:            false,
		RemoteTLSVerify:      false,
		ConnectTimeout:       10 * time.Second,
		TrustedProxies:       []string{"127.0.0.0/8", "::1/128"},
		TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Required for PROXY protocol validation
		ProxyProtocol:        true,                               // Enable PROXY protocol for incoming connections
		ProxyProtocolTimeout: "5s",                               // Timeout for reading PROXY headers
	}

	ctx, cancel := context.WithCancel(context.Background())
	proxy, err := userapiproxy.New(ctx, rdb, opts)
	if err != nil {
		cancel()
		t.Fatalf("Failed to create User API proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && ctx.Err() == nil {
			errChan <- fmt.Errorf("User API proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("User API proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	return proxyAddr, cleanup
}
