//go:build integration

package lmtpproxy_test

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
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxyRemoteLookupContextCancellation tests that context cancellation during remotelookup
// (e.g., server shutdown) returns a temporary error instead of permanent user unknown.
func TestLMTPProxyRemoteLookupContextCancellation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
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

	// Set up LMTP proxy with remotelookup enabled and fallback disabled
	proxyAddress := common.GetRandomAddress(t)
	rdb := common.SetupTestDatabase(t)

	opts := lmtpproxy.ServerOptions{
		Name:                   "test-lmtp-proxy-remotelookup-cancel",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             25,
		RemoteUseProxyProtocol: true,
		RemoteUseXCLIENT:       false,
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupServer.URL + "/$email",
			Timeout:          "30s", // Long timeout - we'll cancel before this
			LookupLocalUsers: false, // Disable fallback to ensure remotelookup path is tested
		},
	}

	proxy, err := lmtpproxy.New(context.Background(), rdb, "localhost", opts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial LMTP proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("Expected 220 greeting, got: %s", greeting)
	}

	// Send LHLO
	writer.WriteString("LHLO client.example.com\r\n")
	writer.Flush()

	// Read LHLO responses until we get 250 (end of capabilities)
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		if strings.HasPrefix(resp, "250 ") {
			break // End of LHLO responses
		}
	}

	// Send MAIL FROM
	writer.WriteString(fmt.Sprintf("MAIL FROM:<%s>\r\n", "sender@example.com"))
	writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// Start RCPT TO in a goroutine (this will trigger remotelookup)
	rcptErrChan := make(chan error, 1)
	rcptRespChan := make(chan string, 1)
	go func() {
		// Send RCPT TO command (this will trigger remotelookup routing)
		cmd := fmt.Sprintf("RCPT TO:<%s>\r\n", account.Email)
		t.Log("Sending RCPT TO command...")
		if _, err := writer.WriteString(cmd); err != nil {
			rcptErrChan <- fmt.Errorf("failed to send RCPT TO: %w", err)
			return
		}
		if err := writer.Flush(); err != nil {
			rcptErrChan <- fmt.Errorf("failed to flush RCPT TO: %w", err)
			return
		}

		// Read RCPT TO response
		t.Log("Reading RCPT TO response...")
		resp, err := reader.ReadString('\n')
		if err != nil {
			rcptErrChan <- fmt.Errorf("failed to read RCPT TO response: %w", err)
			return
		}
		t.Logf("Got RCPT TO response: %q", resp)

		rcptRespChan <- resp
		rcptErrChan <- nil
	}()

	// Wait a moment to ensure the RCPT TO request reaches remotelookup
	time.Sleep(300 * time.Millisecond)

	// Now shutdown the proxy (this will cancel the remotelookup context)
	t.Log("Shutting down proxy during remotelookup...")
	proxy.Stop()

	// Wait for RCPT TO to complete
	select {
	case err := <-rcptErrChan:
		if err != nil {
			// Connection closed or error occurred
			errStr := err.Error()
			t.Logf("RCPT TO error: %v", err)
			if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
				t.Logf("✓ Connection closed during shutdown (acceptable)")
			} else {
				t.Logf("⚠ Unexpected error: %v", err)
			}
		} else {
			// Got a response
			resp := <-rcptRespChan
			t.Logf("RCPT TO response: %s", resp)

			// Check that we got a temporary failure (4xx) not permanent failure (5xx)
			if strings.HasPrefix(resp, "421") || strings.Contains(resp, "shutting down") || strings.Contains(resp, "try again") {
				t.Logf("✓ Correctly received temporary error during remotelookup context cancellation")
			} else if strings.HasPrefix(resp, "550") || strings.Contains(resp, "User unknown") {
				t.Errorf("FAIL: Received permanent 'User unknown' (550) instead of temporary error during shutdown")
				t.Errorf("This will cause senders to bounce emails instead of retrying")
			} else if strings.HasPrefix(resp, "250") {
				t.Error("Unexpected success during shutdown")
			} else {
				t.Logf("⚠ Unexpected response (but not permanent user unknown): %s", resp)
			}
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for RCPT TO response")
	}

	t.Log("✓ Test completed")
}
