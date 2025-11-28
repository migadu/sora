//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
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
	"github.com/migadu/sora/server/managesieveproxy"
)

// TestManageSieveProxyRemoteLookupContextCancellation tests that context cancellation during remotelookup
// (e.g., server shutdown) returns temporary unavailability instead of authentication failed.
func TestManageSieveProxyRemoteLookupContextCancellation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServer(t)
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

	// Set up ManageSieve proxy with remotelookup enabled and fallback disabled
	// This ensures we're testing the remotelookup code path
	proxyAddress := common.GetRandomAddress(t)

	hostname := "test-proxy-remotelookup-cancel"

	opts := managesieveproxy.ServerOptions{
		Name:               "test-proxy-remotelookup-cancel",
		Addr:               proxyAddress,
		RemoteAddrs:        []string{backendServer.Address},
		RemotePort:         4190,
		MasterSASLUsername: "master_sasl",
		MasterSASLPassword: "master_sasl_secret",
		TLS:                false,
		TLSVerify:          false,
		RemoteTLS:          false,
		RemoteTLSVerify:    false,
		InsecureAuth:       true,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		EnableAffinity:     true,
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

	proxy, err := managesieveproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.Contains(greeting, "OK") && !strings.Contains(greeting, "IMPLEMENTATION") {
		t.Fatalf("Expected OK greeting, got: %s", greeting)
	}

	// Keep reading until we get all capability lines
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read capability: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break // End of capabilities
		}
	}

	// Prepare base64-encoded PLAIN auth credentials
	// PLAIN auth format: \0username\0password
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	// Start AUTHENTICATE in a goroutine (this will trigger remotelookup)
	authErrChan := make(chan error, 1)
	go func() {
		// Send AUTHENTICATE PLAIN command with base64-encoded credentials
		// ManageSieve sends everything in one command, not using continuation
		authCmd := fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)
		t.Log("Sending AUTHENTICATE PLAIN command with credentials...")
		if _, err := conn.Write([]byte(authCmd)); err != nil {
			authErrChan <- fmt.Errorf("failed to send AUTHENTICATE: %w", err)
			return
		}

		// Read auth response
		t.Log("Reading AUTHENTICATE response...")
		resp, err := reader.ReadString('\n')
		if err != nil {
			authErrChan <- fmt.Errorf("failed to read AUTHENTICATE response: %w", err)
			return
		}
		t.Logf("Got AUTHENTICATE response: %q", resp)

		// Check response
		if strings.HasPrefix(resp, "OK") {
			authErrChan <- nil // Success
		} else {
			authErrChan <- fmt.Errorf("auth response: %s", strings.TrimSpace(resp))
		}
	}()

	// Wait longer to ensure the auth request reaches remotelookup and blocks there
	time.Sleep(300 * time.Millisecond)

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

		// Check that we got temporary unavailability (not "Authentication failed" or just "NO")
		if strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "TRYLATER") || strings.Contains(errStr, "shutting down") {
			t.Logf("✓ Correctly received temporary unavailability during remotelookup context cancellation")
		} else if strings.Contains(errStr, "Authentication failed") || strings.Contains(errStr, "NO \"Authentication") {
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
