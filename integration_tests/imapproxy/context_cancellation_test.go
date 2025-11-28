//go:build integration

package imapproxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyContextCancellationDuringAuth tests that context cancellation
// during authentication (server shutdown) returns UNAVAILABLE instead of
// Authentication failed, preventing clients from being incorrectly told
// their password is wrong and avoiding rate limiting penalties.
func TestIMAPProxyContextCancellationDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	// Don't defer proxy.Close() - we'll close it manually during auth

	// First, verify normal login works through proxy
	c1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Initial login through proxy failed: %v", err)
	}
	t.Log("✓ Initial login through proxy successful")
	c1.Logout()

	// Now test authentication during server shutdown
	c2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy for shutdown test: %v", err)
	}
	defer c2.Logout()

	// Start login in a goroutine
	loginErrChan := make(chan error, 1)
	go func() {
		loginErrChan <- c2.Login(account.Email, account.Password).Wait()
	}()

	// Close the proxy immediately (racing with authentication)
	time.Sleep(1 * time.Millisecond)
	proxy.Close()
	t.Log("✓ Proxy closed during/immediately after authentication")

	// Wait for login to complete
	loginErr := <-loginErrChan

	// The login may succeed (if it completed before shutdown) or fail
	// If it fails, we want to verify it's not "Authentication failed"
	if loginErr == nil {
		t.Log("⚠ Login succeeded before shutdown (timing race) - this is acceptable")
		return
	}

	t.Logf("Login error: %v", loginErr)

	// Check that the error contains UNAVAILABLE, not Authentication failed
	errStr := loginErr.Error()
	if strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "shutting down") {
		t.Logf("✓ Correctly received UNAVAILABLE response")
	} else if strings.Contains(errStr, "Authentication failed") {
		t.Errorf("FAIL: Received 'Authentication failed' instead of UNAVAILABLE during shutdown")
		t.Errorf("This will cause clients to prompt for password and penalize rate limiting")
		t.Errorf("Error was: %v", loginErr)
	} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
		// Connection might be closed before the response is sent - this is acceptable
		t.Logf("✓ Connection closed before response (acceptable during shutdown)")
	} else {
		t.Logf("⚠ Unexpected error type (but not 'Authentication failed'): %v", loginErr)
	}
}

// TestIMAPProxyContextCancellationDuringDBAuth tests context cancellation
// specifically during database authentication by using concurrent connections.
func TestIMAPProxyContextCancellationDuringDBAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// First verify normal login works
	c1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Initial login failed: %v", err)
	}
	t.Log("✓ Initial login successful")
	c1.Logout()

	// Now simulate multiple rapid connections during shutdown
	const numConnections = 5
	errChan := make(chan error, numConnections)

	// Close proxy after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		proxy.Close()
		t.Log("✓ Proxy closed")
	}()

	// Attempt multiple logins concurrently
	for i := 0; i < numConnections; i++ {
		go func(idx int) {
			c, err := imapclient.DialInsecure(proxyAddress, nil)
			if err != nil {
				errChan <- err
				return
			}
			defer c.Logout()

			// Stagger the login attempts slightly
			time.Sleep(time.Duration(idx*5) * time.Millisecond)
			err = c.Login(account.Email, account.Password).Wait()
			errChan <- err
		}(i)
	}

	// Collect results
	authFailedCount := 0
	unavailableCount := 0
	successCount := 0
	connectionErrorCount := 0

	for i := 0; i < numConnections; i++ {
		err := <-errChan
		if err == nil {
			successCount++
		} else {
			errStr := err.Error()
			switch {
			case strings.Contains(errStr, "Authentication failed"):
				authFailedCount++
				t.Errorf("Connection %d: Got 'Authentication failed' during shutdown: %v", i, err)
			case strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "shutting down"):
				unavailableCount++
				t.Logf("Connection %d: ✓ Got UNAVAILABLE: %v", i, err)
			case strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF"):
				connectionErrorCount++
				t.Logf("Connection %d: Connection error (acceptable): %v", i, err)
			default:
				t.Logf("Connection %d: Other error: %v", i, err)
			}
		}
	}

	t.Logf("Results: Success=%d, UNAVAILABLE=%d, ConnectionError=%d, AuthenticationFailed=%d",
		successCount, unavailableCount, connectionErrorCount, authFailedCount)

	// The critical check: we should NEVER get "Authentication failed" during shutdown
	if authFailedCount > 0 {
		t.Errorf("FAIL: %d connections received 'Authentication failed' during shutdown", authFailedCount)
		t.Errorf("This causes clients to prompt for password and penalizes rate limiting")
	} else {
		t.Log("✓ No 'Authentication failed' responses during shutdown")
	}
}

// TestIMAPProxyNormalAuthFailureStillWorks verifies that legitimate auth failures
// still return "Authentication failed" (not UNAVAILABLE), ensuring our fix doesn't
// break normal error handling.
func TestIMAPProxyNormalAuthFailureStillWorks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Test wrong password
	err = c.Login(account.Email, "wrong_password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with wrong password")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "Authentication failed") && !strings.Contains(errStr, "failed") {
		t.Errorf("Expected 'Authentication failed' for wrong password, got: %v", err)
	} else {
		t.Logf("✓ Wrong password correctly returns authentication failed: %v", err)
	}

	// Test non-existent user
	c2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c2.Logout()

	err = c2.Login("nonexistent@example.com", "password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail for non-existent user")
	}

	errStr = err.Error()
	if !strings.Contains(errStr, "Authentication failed") && !strings.Contains(errStr, "failed") {
		t.Errorf("Expected 'Authentication failed' for non-existent user, got: %v", err)
	} else {
		t.Logf("✓ Non-existent user correctly returns authentication failed: %v", err)
	}
}

// TestIMAPProxyRemoteLookupContextCancellation tests that context cancellation during remotelookup
// (e.g., server shutdown) returns UNAVAILABLE instead of authentication failed.
func TestIMAPProxyRemoteLookupContextCancellation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
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

	// Set up IMAP proxy with remotelookup enabled and fallback disabled
	// This ensures we're testing the remotelookup code path
	proxyAddress := common.GetRandomAddress(t)

	hostname := "test-proxy-remotelookup-cancel"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-remotelookup-cancel",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
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
			Enabled:          true,
			URL:              remotelookupServer.URL + "/$email",
			Timeout:          "30s", // Long timeout - we'll cancel before this
			LookupLocalUsers: false, // Disable fallback to ensure remotelookup path is tested
		},
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Start login in a goroutine (this will block on remotelookup)
	loginErrChan := make(chan error, 1)
	go func() {
		loginErrChan <- c.Login(account.Email, account.Password).Wait()
	}()

	// Wait a moment to ensure the login request reaches remotelookup
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy (this will cancel the remotelookup context)
	t.Log("Shutting down proxy during remotelookup...")
	proxy.Stop()

	// Wait for login to complete
	select {
	case loginErr := <-loginErrChan:
		if loginErr == nil {
			t.Fatal("Expected login to fail during shutdown, but it succeeded")
		}

		errStr := loginErr.Error()
		t.Logf("Login error: %v", loginErr)

		// Check that we got UNAVAILABLE (not "Authentication failed")
		if strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "shutting down") {
			t.Logf("✓ Correctly received UNAVAILABLE response during remotelookup context cancellation")
		} else if strings.Contains(errStr, "Authentication failed") {
			t.Errorf("FAIL: Received 'Authentication failed' instead of UNAVAILABLE during shutdown")
			t.Errorf("This will cause clients to prompt for password and penalize rate limiting")
		} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
			t.Logf("✓ Connection closed before response (acceptable during shutdown)")
		} else {
			t.Logf("⚠ Unexpected error (but not 'Authentication failed'): %v", loginErr)
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for login response")
	}

	t.Log("✓ Test completed")
}
