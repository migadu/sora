//go:build integration
// +build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestSlowlorisQuickCheck is a quick test (< 5 minutes) to verify the improved
// slowloris protection works correctly.
func TestSlowlorisQuickCheck(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Server with 20-second idle timeout and 512 bytes/min slowloris protection
	server, account := common.SetupIMAPServerWithSlowloris(t, 20*time.Second, 512)

	t.Logf("Quick slowloris protection test")
	t.Logf("Expected: Survive 1 slow minute, disconnect after 2 consecutive")

	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	sessionStart := time.Now()

	// Authenticate
	fmt.Fprintf(conn, "a001 LOGIN %s %s\r\n", account.Email, account.Password)
	loginResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}
	if !strings.HasPrefix(loginResp, "a001 OK") {
		t.Fatalf("LOGIN failed: %s", loginResp)
	}
	t.Logf("✓ Authenticated at T+%.1fs", time.Since(sessionStart).Seconds())

	commandNum := 2

	// Pass grace period with good throughput (keep it short - just get past 2 minutes)
	t.Logf("Passing grace period (2min) with 600 bytes/min...")
	gracePeriodEnd := sessionStart.Add(2*time.Minute + 5*time.Second)
	ticker := time.NewTicker(1200 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(gracePeriodEnd) {
		<-ticker.C
		tag := fmt.Sprintf("a%03d", commandNum)
		fmt.Fprintf(conn, "%s NOOP\r\n", tag)
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Disconnected during grace period: %v", err)
		}
		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}
	ticker.Stop()
	t.Logf("✓ Grace period passed at T+%.1fs", time.Since(sessionStart).Seconds())

	// ONE slow minute - should survive
	t.Logf("\nSending 300 bytes in first minute (slow but should survive)...")
	slowMinuteEnd := time.Now().Add(62 * time.Second) // Give full minute + buffer
	bytesSent := 0
	for time.Now().Before(slowMinuteEnd) && bytesSent < 300 {
		time.Sleep(7 * time.Second) // ~8-9 commands = ~100 bytes
		tag := fmt.Sprintf("a%03d", commandNum)
		cmd := fmt.Sprintf("%s NOOP\r\n", tag)
		conn.Write([]byte(cmd))
		bytesSent += len(cmd)

		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("❌ Disconnected after ONE slow minute (should survive!): %v", err)
		}
		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}
	t.Logf("✓ Survived ONE slow minute (~%d bytes) at T+%.1fs", bytesSent, time.Since(sessionStart).Seconds())

	// SECOND consecutive slow minute - should disconnect
	t.Logf("\nSending 300 bytes in second minute (should disconnect)...")
	slowMinuteEnd = time.Now().Add(62 * time.Second)
	bytesSent = 0
	disconnected := false

	for time.Now().Before(slowMinuteEnd) && bytesSent < 300 {
		time.Sleep(7 * time.Second)
		tag := fmt.Sprintf("a%03d", commandNum)
		cmd := fmt.Sprintf("%s NOOP\r\n", tag)
		conn.Write([]byte(cmd))
		bytesSent += len(cmd)

		resp, err := reader.ReadString('\n')
		if err != nil {
			// Expected!
			t.Logf("✅ EXPECTED: Disconnected after 2 consecutive slow minutes")
			t.Logf("   Time: T+%.1fs, Bytes in last minute: ~%d", time.Since(sessionStart).Seconds(), bytesSent)
			disconnected = true
			break
		}
		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}

	if !disconnected {
		t.Errorf("❌ FAILED: Connection should have been disconnected after 2 consecutive slow minutes!")
		t.Errorf("   Sent ~%d bytes in second slow minute", bytesSent)
	}

	t.Logf("\n✅ Test completed successfully!")
}
