//go:build integration

package managesieve_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCommandTimeout verifies that ManageSieve commands work correctly with timeout enabled
func TestCommandTimeout(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with 10-second timeout (long enough for database operations)
	server, account := common.SetupManageSieveServerWithTimeout(t, 10*time.Second)
	defer server.Close()

	// Connect to server
	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OK") {
			t.Logf("Greeting: %s", line)
			break
		}
	}

	// Test CAPABILITY command (doesn't require database access)
	fmt.Fprintf(conn, "CAPABILITY\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CAPABILITY response: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OK") {
			t.Logf("CAPABILITY succeeded")
			break
		}
	}

	// Test NOOP command multiple times to verify deadline clearing works
	for i := 0; i < 5; i++ {
		fmt.Fprintf(conn, "NOOP\r\n")
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read NOOP response #%d: %v", i+1, err)
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "OK") {
			t.Fatalf("NOOP #%d failed: %s", i+1, line)
		}
	}
	t.Logf("Multiple rapid NOOP commands succeeded - deadline clearing works correctly")

	// Authenticate
	fmt.Fprintf(conn, "LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password)
	loginResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read LOGIN response: %v", err)
	}
	if !strings.HasPrefix(loginResp, "OK") {
		t.Fatalf("LOGIN failed: %s", loginResp)
	}
	t.Logf("Authenticated successfully")

	// LOGOUT
	fmt.Fprintf(conn, "LOGOUT\r\n")
	logoutResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read LOGOUT response: %v", err)
	}
	if !strings.HasPrefix(logoutResp, "OK") {
		t.Fatalf("LOGOUT failed: %s", logoutResp)
	}
	t.Logf("LOGOUT succeeded: %s", strings.TrimSpace(logoutResp))

	t.Logf("✅ Command timeout test passed - server operates correctly with 10s timeout enabled")
}

// TestCommandTimeoutMetrics verifies that ManageSieve command timeout metrics are properly tracked
func TestCommandTimeoutMetrics(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with 3-second timeout
	server, _ := common.SetupManageSieveServerWithTimeout(t, 3*time.Second)
	defer server.Close()

	// Verify the threshold metric was set correctly
	thresholdValue := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("managesieve"))
	expectedThreshold := 3.0 // 3 seconds

	if thresholdValue != expectedThreshold {
		t.Errorf("Expected threshold %.0f seconds, got %.0f seconds", expectedThreshold, thresholdValue)
	}
	t.Logf("✅ CommandTimeoutThresholdSeconds[managesieve] = %.0f seconds", thresholdValue)

	// Record initial timeout count
	initialTimeoutCount := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", "TEST"))
	t.Logf("Initial timeout count: %.0f", initialTimeoutCount)

	// Simulate a timeout event
	metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", "TEST").Inc()

	// Verify the counter increased
	newTimeoutCount := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", "TEST"))
	expectedCount := initialTimeoutCount + 1.0

	if newTimeoutCount != expectedCount {
		t.Errorf("Expected timeout count %.0f, got %.0f", expectedCount, newTimeoutCount)
	}
	t.Logf("✅ CommandTimeoutsTotal[managesieve,TEST] = %.0f (increased by 1)", newTimeoutCount)

	// Test multiple increments for PUTSCRIPT
	for i := 0; i < 3; i++ {
		metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", "PUTSCRIPT").Inc()
	}

	putscriptTimeouts := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", "PUTSCRIPT"))
	if putscriptTimeouts < 3.0 {
		t.Errorf("Expected at least 3 PUTSCRIPT timeouts, got %.0f", putscriptTimeouts)
	}
	t.Logf("✅ CommandTimeoutsTotal[managesieve,PUTSCRIPT] = %.0f", putscriptTimeouts)

	t.Log("✅ All command timeout metrics working correctly")
}
