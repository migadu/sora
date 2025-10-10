//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIdleTimeoutTrigger verifies that idle connections are actually closed after the timeout period
func TestIdleTimeoutTrigger(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// For ManageSieve proxy timeout testing, we just need a minimal proxy setup
	// We don't need a real backend since we're testing the timeout during the initial connection phase
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	// Record initial idle timeout count
	initialIdleTimeouts := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("managesieve_proxy", "idle"))
	t.Logf("Initial idle timeout count: %.0f", initialIdleTimeouts)

	// Create proxy server with short idle timeout for testing
	idleTimeout := 3 * time.Second
	proxyServer, err := managesieveproxy.New(ctx, rdb, "localhost", managesieveproxy.ServerOptions{
		Name:                   "test-proxy",
		Addr:                   proxyAddr,
		RemoteAddrs:            []string{"127.0.0.1:9999"}, // Fake backend (we'll timeout before reaching it)
		ConnectTimeout:         10 * time.Second,
		SessionTimeout:         30 * time.Second,
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

	// Read greeting (multi-line, ends with OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		t.Logf("Greeting line: %s", line)
		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	t.Logf("Greeting received successfully")

	// Now go completely idle (no reads or writes) for longer than timeout
	// The timeout checker runs every idleTimeout/4, so we wait idleTimeout + 2s to ensure it triggers
	idleWait := idleTimeout + 2*time.Second
	t.Logf("Going completely idle for %v (timeout is %v)...", idleWait, idleTimeout)
	time.Sleep(idleWait)

	// Connection should be closed by now. Try to send a command.
	// Note: Write may succeed (buffered), but read should fail with EOF
	t.Logf("Attempting to send command after idle period...")
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, writeErr := fmt.Fprintf(conn, "CAPABILITY\r\n")

	// Try to read response
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	response, readErr := reader.ReadString('\n')

	// Either write or read should have failed (typically read fails with EOF)
	if writeErr == nil && readErr == nil {
		t.Fatalf("Expected connection to be closed after idle timeout, but both write and read succeeded. Response: %q", response)
	}
	t.Logf("✅ Connection closed after idle timeout (write_err=%v, read_err=%v)", writeErr, readErr)

	// Verify idle timeout metric increased
	time.Sleep(500 * time.Millisecond) // Give metrics time to update
	newIdleTimeouts := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("managesieve_proxy", "idle"))
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

func base64Encode(s string) string {
	// Simple base64 encoding for authentication
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	b := []byte(s)
	result := make([]byte, 0, ((len(b)+2)/3)*4)

	for i := 0; i < len(b); i += 3 {
		var n uint32
		n = uint32(b[i]) << 16
		if i+1 < len(b) {
			n |= uint32(b[i+1]) << 8
		}
		if i+2 < len(b) {
			n |= uint32(b[i+2])
		}

		result = append(result, base64Table[(n>>18)&63])
		result = append(result, base64Table[(n>>12)&63])
		if i+1 < len(b) {
			result = append(result, base64Table[(n>>6)&63])
		} else {
			result = append(result, '=')
		}
		if i+2 < len(b) {
			result = append(result, base64Table[n&63])
		} else {
			result = append(result, '=')
		}
	}

	return string(result)
}
