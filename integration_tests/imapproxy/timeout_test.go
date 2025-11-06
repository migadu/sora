//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIdleTimeoutTrigger verifies that idle connections are actually closed after the timeout period
func TestIdleTimeoutTrigger(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend IMAP server with PROXY protocol support
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr := common.GetRandomAddress(t)

	// Record initial idle timeout count
	initialIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("imap_proxy", "idle"))
	t.Logf("Initial idle timeout count: %.0f", initialIdleTimeouts)

	// Create proxy server with short idle timeout for testing
	idleTimeout := 3 * time.Second
	proxyServer, err := imapproxy.New(ctx, backendServer.ResilientDB, "localhost", imapproxy.ServerOptions{
		Name:                   "test-proxy",
		Addr:                   proxyAddr,
		RemoteAddrs:            []string{backendServer.Address},
		RemoteUseProxyProtocol: true,        // Send PROXY protocol headers to backend
		MasterSASLUsername:     "proxyuser", // Master credentials for backend authentication
		MasterSASLPassword:     "proxypass", // Master credentials for backend authentication
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
		CommandTimeout:         idleTimeout,      // Short timeout for testing (3 seconds)
		AbsoluteSessionTimeout: 30 * time.Minute, // Long session timeout (not testing this)
		MinBytesPerMinute:      0,                // Disable throughput check for this test
		EnableAffinity:         false,
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	go func() {
		if err := proxyServer.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer proxyServer.Stop()

	time.Sleep(100 * time.Millisecond) // Wait for proxy to start

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Connected, greeting: %s", greeting)

	// Authenticate
	fmt.Fprintf(conn, "a001 LOGIN %s s3cur3p4ss!\r\n", account.Email)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read login response: %v", err)
	}
	if !contains(response, "OK") {
		t.Fatalf("Login failed: %s", response)
	}
	t.Logf("Authenticated successfully")

	// Now go completely idle (no reads or writes) for longer than timeout
	// The timeout checker runs every idleTimeout/4, so we wait idleTimeout + 2s to ensure it triggers
	idleWait := idleTimeout + 2*time.Second
	t.Logf("Going completely idle for %v (timeout is %v)...", idleWait, idleTimeout)
	time.Sleep(idleWait)

	// After idle timeout, server should send BYE and close connection
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Try to read - should get BYE message or connection closed
	response, readErr := reader.ReadString('\n')

	// We should either get a BYE message or a connection error
	if readErr == nil {
		// Got a response - should be a BYE message
		if !contains(response, "BYE") {
			t.Fatalf("Expected BYE message after idle timeout, got: %s", response)
		}
		t.Logf("✅ Received BYE message after idle timeout: %s", response)

		// Now the connection should be closed - try to send command
		fmt.Fprintf(conn, "a002 NOOP\r\n")
		_, readErr = reader.ReadString('\n')
		if readErr == nil {
			t.Fatalf("Connection should be closed after BYE, but command succeeded")
		}
		t.Logf("✅ Connection closed after BYE: %v", readErr)
	} else {
		// Got an error immediately - connection was closed without BYE
		t.Logf("✅ Connection closed after idle timeout: %v", readErr)
	}

	// Verify idle timeout metric increased
	time.Sleep(500 * time.Millisecond) // Give metrics time to update
	newIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("imap_proxy", "idle"))
	if newIdleTimeouts <= initialIdleTimeouts {
		t.Errorf("Expected idle timeout count to increase from %.0f, but got %.0f", initialIdleTimeouts, newIdleTimeouts)
	} else {
		t.Logf("✅ Idle timeout metric increased: %.0f → %.0f", initialIdleTimeouts, newIdleTimeouts)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInMiddle(s, substr)))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
