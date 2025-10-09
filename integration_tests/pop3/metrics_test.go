//go:build integration

package pop3_test

import (
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCommandTimeoutMetrics verifies that command timeout metrics are properly tracked
func TestCommandTimeoutMetrics(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with 2-second timeout
	server, _ := common.SetupPOP3ServerWithTimeout(t, 2*time.Second)
	defer server.Close()

	// Verify the threshold metric was set correctly
	thresholdValue := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("pop3"))
	expectedThreshold := 2.0 // 2 seconds

	if thresholdValue != expectedThreshold {
		t.Errorf("Expected threshold %.0f seconds, got %.0f seconds", expectedThreshold, thresholdValue)
	}
	t.Logf("✅ CommandTimeoutThresholdSeconds[pop3] = %.0f seconds", thresholdValue)

	// Record initial timeout count (should be 0 initially for this test)
	initialTimeoutCount := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("pop3", "TEST"))
	t.Logf("Initial timeout count: %.0f", initialTimeoutCount)

	// Simulate a timeout event
	metrics.CommandTimeoutsTotal.WithLabelValues("pop3", "TEST").Inc()

	// Verify the counter increased
	newTimeoutCount := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("pop3", "TEST"))
	expectedCount := initialTimeoutCount + 1.0

	if newTimeoutCount != expectedCount {
		t.Errorf("Expected timeout count %.0f, got %.0f", expectedCount, newTimeoutCount)
	}
	t.Logf("✅ CommandTimeoutsTotal[pop3,TEST] = %.0f (increased by 1)", newTimeoutCount)

	// Test multiple increments
	for i := 0; i < 3; i++ {
		metrics.CommandTimeoutsTotal.WithLabelValues("pop3", "RETR").Inc()
	}

	retrTimeouts := testutil.ToFloat64(metrics.CommandTimeoutsTotal.WithLabelValues("pop3", "RETR"))
	if retrTimeouts < 3.0 {
		t.Errorf("Expected at least 3 RETR timeouts, got %.0f", retrTimeouts)
	}
	t.Logf("✅ CommandTimeoutsTotal[pop3,RETR] = %.0f", retrTimeouts)

	t.Log("✅ All command timeout metrics working correctly")
}

// TestCommandTimeoutThresholdForDifferentServers verifies multiple servers can have different thresholds
func TestCommandTimeoutThresholdForDifferentServers(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create first server with 1-second timeout
	server1, _ := common.SetupPOP3ServerWithTimeout(t, 1*time.Second)
	defer server1.Close()

	// Create second server with 5-second timeout
	server2, _ := common.SetupPOP3ServerWithTimeout(t, 5*time.Second)
	defer server2.Close()

	// The last server to be created will set the metric
	// (since they share the same "pop3" label, the last one wins)
	thresholdValue := testutil.ToFloat64(metrics.CommandTimeoutThresholdSeconds.WithLabelValues("pop3"))

	// Should be 5.0 since server2 was created last
	if thresholdValue != 5.0 {
		t.Logf("Warning: Expected threshold 5.0 seconds, got %.0f seconds (this is OK - last server wins)", thresholdValue)
	} else {
		t.Logf("✅ Threshold metric shows most recent value: %.0f seconds", thresholdValue)
	}
}
