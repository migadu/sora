//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyContextCancellationDuringAuth tests that context cancellation
// during authentication (server shutdown) returns service unavailable instead of
// Authentication failed, preventing clients from being incorrectly told
// their password is wrong and avoiding rate limiting penalties.
func TestPOP3ProxyContextCancellationDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server with PROXY protocol support
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	// Don't defer proxy.Close() - we'll close it manually during auth

	// First, verify normal login works through proxy
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}

	reader1 := bufio.NewReader(conn1)
	// Read greeting
	greeting, err := reader1.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}

	// Send USER
	fmt.Fprintf(conn1, "USER %s\r\n", account.Email)
	resp, _ := reader1.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER failed: %s", resp)
	}

	// Send PASS
	fmt.Fprintf(conn1, "PASS %s\r\n", account.Password)
	resp, _ = reader1.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS failed: %s", resp)
	}
	t.Log("✓ Initial login through proxy successful")

	// Send QUIT
	fmt.Fprintf(conn1, "QUIT\r\n")
	conn1.Close()

	// Now test authentication during server shutdown
	conn2, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy for shutdown test: %v", err)
	}
	defer conn2.Close()

	reader2 := bufio.NewReader(conn2)
	// Read greeting
	greeting, err = reader2.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	// Send USER
	fmt.Fprintf(conn2, "USER %s\r\n", account.Email)
	resp, _ = reader2.ReadString('\n')

	// Send PASS in a goroutine and close proxy immediately
	loginErrChan := make(chan error, 1)
	loginRespChan := make(chan string, 1)
	go func() {
		fmt.Fprintf(conn2, "PASS %s\r\n", account.Password)
		resp, err := reader2.ReadString('\n')
		if err != nil {
			loginErrChan <- err
		} else {
			loginRespChan <- resp
		}
	}()

	// Close the proxy immediately (racing with authentication)
	time.Sleep(1 * time.Millisecond)
	proxy.Close()
	t.Log("✓ Proxy closed during/immediately after authentication")

	// Wait for login to complete
	select {
	case resp := <-loginRespChan:
		t.Logf("Login response: %s", strings.TrimSpace(resp))
		if strings.HasPrefix(resp, "+OK") {
			t.Log("⚠ Login succeeded before shutdown (timing race) - this is acceptable")
			return
		}
		// Check that the error contains "unavailable", not "Authentication failed"
		if strings.Contains(resp, "unavailable") || strings.Contains(resp, "shutting down") {
			t.Logf("✓ Correctly received unavailable response")
		} else if strings.Contains(resp, "Authentication failed") {
			t.Errorf("FAIL: Received 'Authentication failed' instead of unavailable during shutdown")
			t.Errorf("This will cause clients to prompt for password and penalize rate limiting")
			t.Errorf("Response was: %s", resp)
		} else {
			t.Logf("⚠ Unexpected response: %s", resp)
		}
	case err := <-loginErrChan:
		// Connection might be closed before the response is sent - this is acceptable
		t.Logf("✓ Connection closed before response (acceptable during shutdown): %v", err)
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for authentication response")
	}
}

// TestPOP3ProxyContextCancellationDuringDBAuth tests context cancellation
// specifically during database authentication by using concurrent connections.
func TestPOP3ProxyContextCancellationDuringDBAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server with PROXY protocol support
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// First verify normal login works
	conn1, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}

	reader1 := bufio.NewReader(conn1)
	greeting, _ := reader1.ReadString('\n')
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting")
	}

	fmt.Fprintf(conn1, "USER %s\r\n", account.Email)
	reader1.ReadString('\n')
	fmt.Fprintf(conn1, "PASS %s\r\n", account.Password)
	resp, _ := reader1.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("Initial login failed: %s", resp)
	}
	t.Log("✓ Initial login successful")
	fmt.Fprintf(conn1, "QUIT\r\n")
	conn1.Close()

	// Now simulate multiple rapid connections during shutdown
	const numConnections = 5
	type result struct {
		idx      int
		response string
		err      error
	}
	resultChan := make(chan result, numConnections)

	// Close proxy after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		proxy.Close()
		t.Log("✓ Proxy closed")
	}()

	// Attempt multiple logins concurrently
	for i := 0; i < numConnections; i++ {
		go func(idx int) {
			conn, err := net.Dial("tcp", proxyAddress)
			if err != nil {
				resultChan <- result{idx: idx, err: err}
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			// Read greeting
			_, err = reader.ReadString('\n')
			if err != nil {
				resultChan <- result{idx: idx, err: err}
				return
			}

			// Stagger the login attempts slightly
			time.Sleep(time.Duration(idx*5) * time.Millisecond)

			// Send USER
			fmt.Fprintf(conn, "USER %s\r\n", account.Email)
			resp, err := reader.ReadString('\n')
			if err != nil {
				resultChan <- result{idx: idx, err: err}
				return
			}

			// Send PASS
			fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
			resp, err = reader.ReadString('\n')
			if err != nil {
				resultChan <- result{idx: idx, err: err}
				return
			}

			resultChan <- result{idx: idx, response: resp}
		}(i)
	}

	// Collect results
	authFailedCount := 0
	unavailableCount := 0
	successCount := 0
	connectionErrorCount := 0

	for i := 0; i < numConnections; i++ {
		res := <-resultChan
		if res.err != nil {
			errStr := res.err.Error()
			if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
				connectionErrorCount++
				t.Logf("Connection %d: Connection error (acceptable): %v", res.idx, res.err)
			} else {
				t.Logf("Connection %d: Other error: %v", res.idx, res.err)
			}
		} else if strings.HasPrefix(res.response, "+OK") {
			successCount++
			t.Logf("Connection %d: ✓ Login succeeded", res.idx)
		} else if strings.Contains(res.response, "Authentication failed") {
			authFailedCount++
			t.Errorf("Connection %d: Got 'Authentication failed' during shutdown: %s", res.idx, strings.TrimSpace(res.response))
		} else if strings.Contains(res.response, "unavailable") || strings.Contains(res.response, "shutting down") {
			unavailableCount++
			t.Logf("Connection %d: ✓ Got unavailable: %s", res.idx, strings.TrimSpace(res.response))
		} else {
			t.Logf("Connection %d: Other response: %s", res.idx, strings.TrimSpace(res.response))
		}
	}

	t.Logf("Results: Success=%d, Unavailable=%d, ConnectionError=%d, AuthenticationFailed=%d",
		successCount, unavailableCount, connectionErrorCount, authFailedCount)

	// The critical check: we should NEVER get "Authentication failed" during shutdown
	if authFailedCount > 0 {
		t.Errorf("FAIL: %d connections received 'Authentication failed' during shutdown", authFailedCount)
		t.Errorf("This causes clients to prompt for password and penalizes rate limiting")
	} else {
		t.Log("✓ No 'Authentication failed' responses during shutdown")
	}
}

// TestPOP3ProxyNormalAuthFailureStillWorks verifies that legitimate auth failures
// still return "Authentication failed" (not unavailable), ensuring our fix doesn't
// break normal error handling.
func TestPOP3ProxyNormalAuthFailureStillWorks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server with PROXY protocol support
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test wrong password
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	// Read greeting
	greeting, _ := reader.ReadString('\n')
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting")
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	resp, _ := reader.ReadString('\n')

	// Send PASS with wrong password
	fmt.Fprintf(conn, "PASS %s\r\n", "wrong_password")
	resp, _ = reader.ReadString('\n')

	if strings.HasPrefix(resp, "+OK") {
		t.Fatal("Expected login to fail with wrong password")
	}

	if !strings.Contains(resp, "Authentication failed") && !strings.Contains(resp, "failed") {
		t.Errorf("Expected 'Authentication failed' for wrong password, got: %s", strings.TrimSpace(resp))
	} else {
		t.Logf("✓ Wrong password correctly returns authentication failed: %s", strings.TrimSpace(resp))
	}

	// Test non-existent user
	conn2, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn2.Close()

	reader2 := bufio.NewReader(conn2)
	_, _ = reader2.ReadString('\n') // Read greeting

	fmt.Fprintf(conn2, "USER %s\r\n", "nonexistent@example.com")
	resp, _ = reader2.ReadString('\n')

	fmt.Fprintf(conn2, "PASS %s\r\n", "password")
	resp, _ = reader2.ReadString('\n')

	if strings.HasPrefix(resp, "+OK") {
		t.Fatal("Expected login to fail for non-existent user")
	}

	if !strings.Contains(resp, "Authentication failed") && !strings.Contains(resp, "failed") {
		t.Errorf("Expected 'Authentication failed' for non-existent user, got: %s", strings.TrimSpace(resp))
	} else {
		t.Logf("✓ Non-existent user correctly returns authentication failed: %s", strings.TrimSpace(resp))
	}
}

// TestPOP3ProxyRemoteLookupContextCancellation tests that context cancellation during remotelookup
// (e.g., server shutdown) returns temporary unavailability instead of authentication failed.
func TestPOP3ProxyRemoteLookupContextCancellation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that blocks for a long time
	remotelookupBlockChan := make(chan struct{})
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the channel is closed or request context is cancelled
		select {
		case <-remotelookupBlockChan:
			// Channel closed - return success
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"account_id": 1,
				"backend":    backendServer.Address,
			})
		case <-r.Context().Done():
			// Request context cancelled (proxy shutting down)
			t.Log("✓ RemoteLookup request context cancelled (expected during shutdown)")
			return
		}
	}))
	defer remotelookupServer.Close()
	defer close(remotelookupBlockChan)

	// Set up POP3 proxy with remotelookup enabled and fallback disabled
	// This ensures we're testing the remotelookup code path
	proxyAddress := common.GetRandomAddress(t)

	hostname := "test-proxy-remotelookup-cancel"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-proxy-remotelookup-cancel",
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             110,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:      true,
			URL:          remotelookupServer.URL + "/$email",
			Timeout:      "30s", // Long timeout - we'll cancel before this
			FallbackToDB: false, // Disable fallback to ensure remotelookup path is tested
		},
	}

	proxy, err := pop3proxy.New(context.Background(), hostname, proxyAddress, backendServer.ResilientDB, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}

	// Start USER/PASS authentication in a goroutine (this will block on remotelookup)
	authErrChan := make(chan error, 1)
	go func() {
		// Send USER command
		if _, err := conn.Write([]byte(fmt.Sprintf("USER %s\r\n", account.Email))); err != nil {
			authErrChan <- fmt.Errorf("failed to send USER: %w", err)
			return
		}

		resp, err := reader.ReadString('\n')
		if err != nil {
			authErrChan <- fmt.Errorf("failed to read USER response: %w", err)
			return
		}
		if !strings.HasPrefix(resp, "+OK") {
			authErrChan <- fmt.Errorf("USER failed: %s", resp)
			return
		}

		// Send PASS command (this will trigger remotelookup)
		if _, err := conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", account.Password))); err != nil {
			authErrChan <- fmt.Errorf("failed to send PASS: %w", err)
			return
		}

		resp, err = reader.ReadString('\n')
		if err != nil {
			authErrChan <- fmt.Errorf("failed to read PASS response: %w", err)
			return
		}

		// Store the response for verification
		if strings.HasPrefix(resp, "+OK") {
			authErrChan <- nil // Success
		} else {
			authErrChan <- fmt.Errorf("auth response: %s", strings.TrimSpace(resp))
		}
	}()

	// Wait a moment to ensure the auth request reaches remotelookup
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy (this will cancel the remotelookup context)
	t.Log("Shutting down proxy during remotelookup...")
	proxy.Stop()

	// Wait for auth to complete
	select {
	case authErr := <-authErrChan:
		if authErr == nil {
			t.Fatal("Expected auth to fail during shutdown, but it succeeded")
		}

		errStr := authErr.Error()
		t.Logf("Auth error: %v", authErr)

		// Check that we got temporary unavailability (not "Authentication failed")
		if strings.Contains(errStr, "SYS/TEMP") || strings.Contains(errStr, "temporarily unavailable") {
			t.Logf("✓ Correctly received temporary unavailability during remotelookup context cancellation")
		} else if strings.Contains(errStr, "Authentication failed") || strings.Contains(errStr, "AUTH") {
			t.Errorf("FAIL: Received 'Authentication failed' instead of temporary unavailability during shutdown")
			t.Errorf("This will cause clients to prompt for password and penalize rate limiting")
		} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
			t.Logf("✓ Connection closed before response (acceptable during shutdown)")
		} else {
			t.Logf("⚠ Unexpected error (but not 'Authentication failed'): %v", authErr)
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for auth response")
	}

	t.Log("✓ Test completed")
}
