//go:build integration

package userapiproxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

// setupE2ETest helper spins up fresh instances of backend and proxy servers
func setupE2ETest(t *testing.T, rdb *resilient.ResilientDatabase, allowedHosts []string) (string, func()) {
	t.Helper()

	// 1. Setup backend User API server with:
	//    - ProxyProtocol: true
	//    - ProxyProtocolTrustedProxies: []string{"127.0.0.1"} (trusts proxy connections)
	//    - AllowedHosts: allowedHosts
	backendAddr := common.GetRandomAddress(t)
	backendOpts := userapi.ServerOptions{
		Name:                        "test-backend-e2e",
		Addr:                        backendAddr,
		JWTSecret:                   testJWTSecretPROXY,
		TokenDuration:               1 * time.Hour,
		TokenIssuer:                 "test-issuer",
		AllowedOrigins:              []string{"*"},
		AllowedHosts:                allowedHosts,
		Storage:                     nil,
		Cache:                       nil,
		TLS:                         false,
		ProxyProtocol:               true,
		ProxyProtocolTimeout:        "2s",
		ProxyProtocolTrustedProxies: []string{"127.0.0.1", "::1"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	backendErrChan := make(chan error, 1)
	backendServer := userapi.Start(ctx, rdb, backendOpts, backendErrChan)
	if backendServer == nil {
		cancel()
		t.Fatalf("Failed to start backend User API")
	}

	// 2. Setup proxy User API server with:
	//    - ProxyProtocol: true (enable incoming PROXY protocol)
	//    - RemoteUseProxyProtocol: true (enable writing PROXY protocol to backend)
	proxyAddr := common.GetRandomAddress(t)
	proxyOpts := userapiproxy.ServerOptions{
		Name:                   "test-proxy-e2e",
		Addr:                   proxyAddr,
		RemoteAddrs:            []string{backendAddr},
		RemotePort:             8081,
		JWTSecret:              testJWTSecretPROXY,
		TLS:                    false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		ConnectTimeout:         10 * time.Second,
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
		TrustedNetworks:        []string{"127.0.0.0/8", "::1/128"},
		ProxyProtocol:          true, // Enable incoming PROXY protocol on the proxy
		ProxyProtocolTimeout:   "2s",
		RemoteUseProxyProtocol: true, // Enable outgoing PROXY protocol from proxy to backend
	}

	proxy, err := userapiproxy.New(ctx, rdb, proxyOpts)
	if err != nil {
		cancel()
		t.Fatalf("Failed to create User API proxy: %v", err)
	}

	proxyErrChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && ctx.Err() == nil {
			proxyErrChan <- err
		}
	}()

	// Give servers time to start
	time.Sleep(150 * time.Millisecond)

	cleanup := func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	}

	return proxyAddr, cleanup
}

func TestProxyProtocolEndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and create test account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	realClientIP := "203.0.113.42"

	// Helper to make a request through the proxy, optionally injecting an incoming PROXY protocol header
	makeProxyRequest := func(t *testing.T, proxyAddr string, useProxyHeader bool, clientIP string, method, path string, body []byte, token string) (*http.Response, string, error) {
		t.Helper()

		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return nil, "", fmt.Errorf("failed to dial proxy: %w", err)
		}
		defer conn.Close()

		if useProxyHeader {
			localAddr := conn.LocalAddr().(*net.TCPAddr)
			header, err := server.GenerateProxyV2Header(clientIP, 54321, "127.0.0.1", localAddr.Port, "TCP4")
			if err != nil {
				return nil, "", fmt.Errorf("failed to generate PROXY header: %w", err)
			}
			if _, err := conn.Write(header); err != nil {
				return nil, "", fmt.Errorf("failed to write PROXY header: %w", err)
			}
		}

		// Write HTTP request
		reqStr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n", method, path, len(body))
		if token != "" {
			reqStr += fmt.Sprintf("Authorization: Bearer %s\r\n", token)
		}
		reqStr += "Content-Type: application/json\r\n\r\n"
		if _, err := conn.Write([]byte(reqStr)); err != nil {
			return nil, "", fmt.Errorf("failed to write request line/headers: %w", err)
		}
		if len(body) > 0 {
			if _, err := conn.Write(body); err != nil {
				return nil, "", fmt.Errorf("failed to write request body: %w", err)
			}
		}

		// Read response
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read response: %w", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read response body: %w", err)
		}
		resp.Body.Close()

		return resp, string(respBody), nil
	}

	t.Run("authorized_client_ip_succeeds", func(t *testing.T) {
		proxyAddr, cleanup := setupE2ETest(t, rdb, []string{realClientIP})
		defer cleanup()

		// Log in using the authorized IP
		loginReq := map[string]string{
			"email":    account.Email,
			"password": account.Password,
		}
		loginJSON, _ := json.Marshal(loginReq)

		resp, body, err := makeProxyRequest(t, proxyAddr, true, realClientIP, "POST", "/user/auth/login", loginJSON, "")
		if err != nil {
			t.Fatalf("Login request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected login to succeed (200), got %d. Body: %s", resp.StatusCode, body)
		}

		var loginResult map[string]any
		json.Unmarshal([]byte(body), &loginResult)
		token, ok := loginResult["token"].(string)
		if !ok || token == "" {
			t.Fatalf("No valid token in login response: %s", body)
		}

		// Now make an authenticated request to list mailboxes using the token and the authorized IP
		resp, body, err = makeProxyRequest(t, proxyAddr, true, realClientIP, "GET", "/user/mailboxes", nil, token)
		if err != nil {
			t.Fatalf("Mailboxes request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected mailboxes request to succeed (200), got %d. Body: %s", resp.StatusCode, body)
		}

		t.Log("✓ End-to-end PROXY protocol connection with allowed IP succeeded!")
	})

	t.Run("unauthorized_client_ip_gets_forbidden", func(t *testing.T) {
		proxyAddr, cleanup := setupE2ETest(t, rdb, []string{realClientIP})
		defer cleanup()

		// Try to login with an unauthorized IP (e.g., "198.51.100.1")
		unauthorizedIP := "198.51.100.1"
		loginReq := map[string]string{
			"email":    account.Email,
			"password": account.Password,
		}
		loginJSON, _ := json.Marshal(loginReq)

		resp, body, err := makeProxyRequest(t, proxyAddr, true, unauthorizedIP, "POST", "/user/auth/login", loginJSON, "")
		if err != nil {
			t.Fatalf("Login request failed: %v", err)
		}

		// The backend's AllowedHosts contains ONLY 203.0.113.42, so 198.51.100.1 must be rejected with 403 Forbidden.
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected 403 Forbidden for unauthorized client IP, got %d. Body: %s", resp.StatusCode, body)
		}

		t.Log("✓ End-to-end PROXY protocol connection with unauthorized IP was correctly rejected with 403 Forbidden!")
	})

	t.Run("no_proxy_header_rejected_by_proxy", func(t *testing.T) {
		proxyAddr, cleanup := setupE2ETest(t, rdb, []string{realClientIP})
		defer cleanup()

		// When connecting to the proxy without PROXY protocol header, the proxy has ProxyProtocol: true enabled.
		// So the proxy itself must reject the connection immediately or fail to parse.
		_, _, err := makeProxyRequest(t, proxyAddr, false, "", "POST", "/user/auth/login", nil, "")
		if err == nil {
			t.Fatal("Expected request without PROXY header to be rejected/fail, but it succeeded")
		}
		t.Logf("✓ Request without PROXY header correctly failed: %v", err)
	})
}
