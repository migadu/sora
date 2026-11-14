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

// startDataTransfer opens a session to server and sends the envelope for
// account and DATA, so the next thing to send is the message content.
func startDataTransfer(t *testing.T, server *common.TestServer, account common.TestAccount) *LMTPClient {
	t.Helper()
	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	t.Cleanup(func() { client.conn.Close() })
	client.conn.SetDeadline(time.Now().Add(30 * time.Second))

	client.SendCommand("LHLO client.example.org")
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	for _, cmd := range []string{"MAIL FROM:<sender@example.org>", fmt.Sprintf("RCPT TO:<%s>", account.Email)} {
		client.SendCommand(cmd)
		if resp, err := client.ReadResponse(); err != nil || !strings.HasPrefix(resp, "250") {
			t.Fatalf("%s: %q, %v", cmd, resp, err)
		}
	}
	client.SendCommand("DATA")
	if resp, err := client.ReadResponse(); err != nil || !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA: %q, %v", resp, err)
	}
	return client
}

// trickleBody sends a message of lines body lines, one every interval,
// stopping at the first write error.
func trickleBody(client *LMTPClient, lines int, interval time.Duration) {
	if _, err := fmt.Fprintf(client.conn, "From: sender@example.org\r\nSubject: slow sender\r\n\r\n"); err != nil {
		return
	}
	for i := 0; i < lines; i++ {
		if _, err := fmt.Fprintf(client.conn, "body line %d of a message sent slowly but steadily\r\n", i); err != nil {
			return
		}
		time.Sleep(interval)
	}
}

// TestDataOutlastsIdleTimeout verifies that the idle timeout bounds each wait
// for message content, not the whole DATA transfer (RFC 5321 section 4.5.3.2:
// "a timer is set for each SMTP command and for each buffer of the data
// transfer"). A body that keeps arriving for three times the idle timeout is
// delivered.
func TestDataOutlastsIdleTimeout(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServerWithIdleTimeout(t, time.Second)
	defer server.Close()

	client := startDataTransfer(t, server, account)
	trickleBody(client, 30, 100*time.Millisecond) // 3s, a line every 100ms
	client.conn.Write([]byte(".\r\n"))

	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read the DATA reply: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("A body still arriving after the idle timeout was refused: %s", resp)
	}
}

// TestDataStallClosesConnection verifies that a client that stops sending in
// the middle of the body gets a temporary failure, and that the connection is
// then closed instead of reading the rest of the message as commands. The
// disconnect is counted once in the idle metric.
func TestDataStallClosesConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServerWithIdleTimeout(t, time.Second)
	defer server.Close()

	before := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", "test", "localhost", "idle"))

	client := startDataTransfer(t, server, account)
	fmt.Fprintf(client.conn, "From: sender@example.org\r\nSubject: stalled\r\n\r\nfirst line\r\n")

	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read the DATA reply: %v", err)
	}
	if !strings.HasPrefix(resp, "421 4.4.2") {
		t.Fatalf("Expected 421 4.4.2 for a stalled body, got: %s", resp)
	}

	// What the client sends next is the rest of its message, not a command.
	client.SendCommand("NOOP")
	if extra, err := client.ReadResponse(); err == nil {
		t.Fatalf("Expected the connection closed after the stalled body, read %q", extra)
	}

	time.Sleep(500 * time.Millisecond)
	after := testutil.ToFloat64(metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", "test", "localhost", "idle"))
	if after-before != 1 {
		t.Errorf("Expected the idle timeout metric to increase by 1, got %+.0f", after-before)
	}
}
