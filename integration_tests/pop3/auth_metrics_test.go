//go:build integration

package pop3_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/prometheus/client_golang/prometheus"
)

// TestPOP3_AuthenticationMetricsNoNegative verifies that authenticated connection metrics
// never go negative even under rapid connect/disconnect cycles.
func TestPOP3_AuthenticationMetricsNoNegative(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// Number of concurrent authentication attempts
	numGoroutines := 30
	var wg sync.WaitGroup

	// Perform rapid authentication cycles
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}

			// Authenticate
			fmt.Fprintf(writer, "USER %s\r\n", account.Email)
			writer.Flush()
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}

			fmt.Fprintf(writer, "PASS %s\r\n", account.Password)
			writer.Flush()
			resp, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(resp, "+OK") {
				return
			}

			// Small delay
			time.Sleep(5 * time.Millisecond)

			// Disconnect immediately (rapid cycle)
			fmt.Fprintf(writer, "QUIT\r\n")
			writer.Flush()
			reader.ReadString('\n')
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
