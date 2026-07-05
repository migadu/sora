//go:build integration

package pop3_test

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

// TestIdleTimeoutTrigger verifies that an idle authenticated connection is
// closed after command_timeout with EXACTLY ONE "-ERR" notice, and that the
// idle metric counts the disconnect exactly once. The go-pop3 library owns
// the idle timer; historically the SoraConn checker was armed with the same
// knob, and when both fired the client received a duplicate notice and the
// metric double-counted (same bug class as the pop3proxy relay race).
func TestIdleTimeoutTrigger(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with a very short idle timeout (2 seconds)
	server, account := common.SetupPOP3ServerWithTimeout(t, 2*time.Second)
	defer server.Close()

	// Record initial idle timeout count
	initialIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("pop3", "test-timeout", "localhost", "idle"))
	t.Logf("Initial idle timeout count: %.0f", initialIdleTimeouts)

	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}
	t.Logf("Connected, greeting: %s", strings.TrimSpace(greeting))

	// Authenticate
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("USER failed: %s", response)
	}

	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("PASS failed: %s", response)
	}
	t.Logf("Authenticated successfully")

	// Go completely idle for longer than the timeout
	t.Logf("Going idle for 3 seconds (timeout is 2s)...")
	time.Sleep(3 * time.Second)

	// The server must have sent exactly one -ERR notice and closed the
	// connection.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Expected -ERR idle timeout notice, got error: %v", err)
	}
	if !strings.HasPrefix(response, "-ERR") {
		t.Fatalf("Expected -ERR notice after idle timeout, got: %s", response)
	}
	t.Logf("✅ Received idle timeout notice: %s", strings.TrimSpace(response))

	// The connection must now be closed with nothing else buffered: a second
	// line here means two timeout owners both wrote a notice (the regression
	// this test pins down).
	fmt.Fprintf(conn, "NOOP\r\n")
	extra, readErr := reader.ReadString('\n')
	if readErr == nil {
		t.Fatalf("Expected connection closed after the notice, but read another line: %q", extra)
	}
	t.Logf("✅ Connection closed after single notice: %v", readErr)

	// The idle metric must count this disconnect exactly once.
	time.Sleep(500 * time.Millisecond) // Give metrics time to update
	newIdleTimeouts := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("pop3", "test-timeout", "localhost", "idle"))
	if delta := newIdleTimeouts - initialIdleTimeouts; delta != 1 {
		t.Errorf("Expected idle timeout count to increase by exactly 1, got %+.0f (%.0f → %.0f)", delta, initialIdleTimeouts, newIdleTimeouts)
	} else {
		t.Logf("✅ Idle timeout metric increased exactly once: %.0f → %.0f", initialIdleTimeouts, newIdleTimeouts)
	}
}
