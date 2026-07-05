//go:build integration

package lmtp_test

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

// TestIdleTimeoutTrigger verifies that an idle LMTP connection is closed at
// the idle timeout with EXACTLY ONE "421 4.4.2 Idle timeout" notice, and that
// the disconnect is counted exactly once in the idle metric. go-smtp is the
// single owner of the idle timer (there is deliberately no SoraConn idle
// checker for LMTP); the metric comes from its OnTimeout hook.
func TestIdleTimeoutTrigger(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServerWithIdleTimeout(t, 2*time.Second)
	defer server.Close()

	initialIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", "test", "localhost", "idle"))
	t.Logf("Initial idle timeout count: %.0f", initialIdleTimeouts)

	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	fmt.Fprintf(conn, "LHLO localhost\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		// Multiline reply: "250-..." continues, "250 ..." ends it.
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("LHLO failed: %s", line)
		}
	}
	t.Logf("LHLO complete, going idle for 3 seconds (timeout is 2s)...")

	time.Sleep(3 * time.Second)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Expected 421 idle timeout notice, got error: %v", err)
	}
	if !strings.HasPrefix(response, "421") || !strings.Contains(response, "Idle timeout") {
		t.Fatalf("Expected '421 ... Idle timeout' notice, got: %s", response)
	}
	t.Logf("✅ Received idle timeout notice: %s", strings.TrimSpace(response))

	// The connection must now be closed with nothing else buffered: a second
	// line here would mean two timeout owners both wrote a notice.
	fmt.Fprintf(conn, "NOOP\r\n")
	extra, readErr := reader.ReadString('\n')
	if readErr == nil {
		t.Fatalf("Expected connection closed after the notice, but read another line: %q", extra)
	}
	t.Logf("✅ Connection closed after single notice: %v", readErr)

	// The idle metric must count this disconnect exactly once.
	time.Sleep(500 * time.Millisecond) // Give metrics time to update
	newIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", "test", "localhost", "idle"))
	if delta := newIdleTimeouts - initialIdleTimeouts; delta != 1 {
		t.Errorf("Expected idle timeout count to increase by exactly 1, got %+.0f (%.0f → %.0f)", delta, initialIdleTimeouts, newIdleTimeouts)
	} else {
		t.Logf("✅ Idle timeout metric increased exactly once: %.0f → %.0f", initialIdleTimeouts, newIdleTimeouts)
	}
}
