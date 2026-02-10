//go:build integration

package imap_test

import (
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/prometheus/client_golang/prometheus"
)

// TestIMAP_AuthenticationMetricsNoNegative verifies that authenticated connection metrics
// never go negative even under rapid connect/disconnect cycles.
// This test catches the race condition where authenticated flag was set before metric increment.
func TestIMAP_AuthenticationMetricsNoNegative(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Number of concurrent authentication attempts
	numGoroutines := 30
	var wg sync.WaitGroup

	// Perform rapid authentication cycles
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Connect
			client, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				return
			}

			// Authenticate
			if err := client.Login(account.Email, account.Password).Wait(); err != nil {
				client.Close()
				return
			}

			// Small delay
			time.Sleep(5 * time.Millisecond)

			// Disconnect immediately (rapid cycle to trigger race condition)
			client.Logout()
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Give metrics a moment to settle
	time.Sleep(200 * time.Millisecond)

	// Gather all metrics and check for negative values
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundNegative := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "sora_authenticated_connections_current" {
			for _, metric := range mf.GetMetric() {
				value := metric.GetGauge().GetValue()
				if value < 0 {
					t.Errorf("FAIL: AuthenticatedConnectionsCurrent is NEGATIVE: %f (race condition bug)", value)
					foundNegative = true
				}
			}
		}
	}

	if !foundNegative {
		t.Logf("✅ PASS: No negative authenticated connection metrics detected")
	}
}
