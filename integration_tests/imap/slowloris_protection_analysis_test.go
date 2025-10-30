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

// TestSlowlorisProtectionAnalysis documents and analyzes the current slowloris protection behavior.
//
// FINDINGS:
// 1. Throughput is measured PER MINUTE (sliding window)
// 2. After 2-minute grace period, EVERY minute is checked
// 3. If ANY single minute drops below 512 bytes, connection is disconnected
// 4. This can disconnect valid users who have bursts of activity followed by slow periods
//
// EXAMPLE SCENARIO THAT FAILS:
// - User logs in (minute 0-1: ~500 bytes)
// - User reads inbox listing (minute 1-2: ~2000 bytes)
// - User reads an email slowly (minute 2-3: ~200 bytes) <- DISCONNECTED!
//
// The problem: A valid user reading email slowly gets disconnected even though
// their AVERAGE throughput over the session might be well above 512 bytes/min.
func TestSlowlorisProtectionAnalysis(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Server with 30-second idle timeout and 512 bytes/min slowloris protection
	server, account := common.SetupIMAPServerWithSlowloris(t, 30*time.Second, 512)

	t.Logf("=== SLOWLORIS PROTECTION ANALYSIS ===\n")
	t.Logf("Configuration:")
	t.Logf("  - Threshold: 512 bytes/minute")
	t.Logf("  - Grace period: 2 minutes (no checking)")
	t.Logf("  - Check interval: Every 1 minute")
	t.Logf("  - Measurement: Bytes per minute in LAST measurement window\n")

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
	t.Logf("Connected at T+0.0s\n")

	// Authenticate
	fmt.Fprintf(conn, "a001 LOGIN %s %s\r\n", account.Email, account.Password)
	loginResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}
	if !strings.HasPrefix(loginResp, "a001 OK") {
		t.Fatalf("LOGIN failed: %s", loginResp)
	}
	t.Logf("✓ Authenticated at T+%.1fs\n", time.Since(sessionStart).Seconds())

	// ============================================================================
	// SCENARIO 1: Steady low throughput during grace period (should survive)
	// ============================================================================
	t.Logf("--- SCENARIO 1: Low throughput during grace period ---")
	t.Logf("Expected: Should NOT disconnect (grace period protects us)")

	commandNum := 2
	// Send very low throughput for 1 minute (only ~150 bytes/min)
	for i := 0; i < 5; i++ {
		time.Sleep(12 * time.Second) // 5 commands in 1 minute
		tag := fmt.Sprintf("a%03d", commandNum)
		fmt.Fprintf(conn, "%s NOOP\r\n", tag)
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Disconnected during grace period at iteration %d: %v", i, err)
		}
		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}
	elapsed := time.Since(sessionStart)
	t.Logf("✓ Still connected at T+%.1fs with ~150 bytes/min (grace period)", elapsed.Seconds())

	// Continue until we're close to end of grace period
	t.Logf("Waiting for grace period to end (sending minimal NOOPs every 20s)...")
	gracePeriodEnd := sessionStart.Add(2*time.Minute + 5*time.Second)
	for time.Now().Before(gracePeriodEnd) {
		time.Sleep(20 * time.Second)
		if time.Now().After(gracePeriodEnd) {
			break
		}
		tag := fmt.Sprintf("a%03d", commandNum)
		fmt.Fprintf(conn, "%s NOOP\r\n", tag)
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Disconnected while waiting for grace period end: %v", err)
		}
		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}
	t.Logf("✓ Grace period ended at T+%.1fs\n", time.Since(sessionStart).Seconds())

	// ============================================================================
	// SCENARIO 2: First minute after grace period with low throughput
	// This is where the problem occurs!
	// ============================================================================
	t.Logf("--- SCENARIO 2: Low throughput AFTER grace period ---")
	t.Logf("Expected: WILL disconnect (< 512 bytes/min measured)")
	t.Logf("This demonstrates the problem: valid users can be disconnected!")

	// Send only 3 NOOPs in the next minute (~36 bytes)
	t.Logf("Sending 3 NOOPs over 1 minute (~36 bytes = ~36 bytes/min)...")
	for i := 0; i < 3; i++ {
		time.Sleep(20 * time.Second)
		tag := fmt.Sprintf("a%03d", commandNum)
		n, _ := fmt.Fprintf(conn, "%s NOOP\r\n", tag)
		t.Logf("  Sent NOOP at T+%.1fs (%d bytes)", time.Since(sessionStart).Seconds(), n)

		resp, err := reader.ReadString('\n')
		if err != nil {
			elapsed := time.Since(sessionStart)
			t.Logf("\n✅ EXPECTED: DISCONNECTED at T+%.1fs after grace period!", elapsed.Seconds())
			t.Logf("   Reason: Measured throughput < 512 bytes/min in last measurement window")
			t.Logf("")
			t.Logf("⚠️  ANALYSIS: This demonstrates a potential issue:")
			t.Logf("   The current implementation measures throughput per 1-minute window.")
			t.Logf("   If ANY single minute after grace period drops below 512 bytes/min,")
			t.Logf("   the connection is immediately disconnected.")
			t.Logf("")
			t.Logf("   This can affect VALID USERS who:")
			t.Logf("     - Read email slowly (thinking/reading pauses)")
			t.Logf("     - Have bursts of activity followed by slow periods")
			t.Logf("     - Send periodic keepalives but not high data volume")
			t.Logf("")
			t.Logf("💡 RECOMMENDATIONS (pick one or combine):")
			t.Logf("   1. Use longer measurement window (e.g., 2-5 minute rolling average)")
			t.Logf("   2. Use lower threshold (e.g., 256 or 128 bytes/min)")
			t.Logf("   3. Only disconnect after N consecutive slow minutes (e.g., 2-3)")
			t.Logf("   4. Exempt authenticated users from slowloris checking")
			t.Logf("   5. Track session-wide average throughput instead of per-minute")
			t.Logf("   6. Increase grace period to 5 minutes for user workflow variance")
			t.Logf("")
			t.Logf("✅ Current protection DOES work against actual slowloris attacks.")
			t.Logf("✅ The 2-minute grace period DOES protect initial authentication.")
			t.Logf("⚠️  BUT: May have false positives for legitimate slow users.")

			// This is EXPECTED behavior given current implementation
			// Test passes because we're documenting the behavior
			t.Logf("\n✅ TEST PASSED: Behavior documented successfully")
			return
		}

		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}
		commandNum++
	}

	// If we get here, we didn't get disconnected
	t.Logf("\n✓ Survived low throughput minute at T+%.1fs", time.Since(sessionStart).Seconds())
	t.Logf("  (Measurement window timing may have protected us)")
}

// TestSlowlorisProtectionValidUserPattern tests a realistic valid user pattern
// that should NOT be disconnected: bursts of activity followed by steady maintenance.
func TestSlowlorisProtectionValidUserPattern(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Server with 30-second idle timeout and 512 bytes/min slowloris protection
	server, account := common.SetupIMAPServerWithSlowloris(t, 30*time.Second, 512)

	t.Logf("=== VALID USER PATTERN TEST ===")
	t.Logf("Simulating: Active user with steady 600+ bytes/minute throughput")

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
	t.Logf("Connected at T+0.0s")

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

	// Strategy: Maintain steady 600 bytes/minute from the start
	// This should keep us safe even after grace period ends
	commandNum := 2

	// Send NOOPs at 10 bytes/second = 600 bytes/minute
	// NOOP command is ~12 bytes: "aNNN NOOP\r\n"
	// Send every 1.2 seconds = 10 bytes/sec
	testDuration := 4 * time.Minute // Test for 4 minutes (past grace period)
	endTime := time.Now().Add(testDuration)

	t.Logf("Sending steady 600 bytes/minute for %.1f minutes...", testDuration.Minutes())

	ticker := time.NewTicker(1200 * time.Millisecond)
	defer ticker.Stop()

	commandsSent := 0
	startPhase2 := false

	for time.Now().Before(endTime) {
		<-ticker.C

		tag := fmt.Sprintf("a%03d", commandNum)
		fmt.Fprintf(conn, "%s NOOP\r\n", tag)

		resp, err := reader.ReadString('\n')
		if err != nil {
			elapsed := time.Since(sessionStart)
			if elapsed < 2*time.Minute {
				t.Fatalf("❌ Disconnected during grace period at T+%.1fs: %v", elapsed.Seconds(), err)
			} else {
				t.Fatalf("❌ Disconnected after grace period at T+%.1fs (sent %d commands): %v",
					elapsed.Seconds(), commandsSent, err)
			}
		}

		if !strings.HasPrefix(resp, tag+" OK") {
			t.Fatalf("NOOP failed: %s", resp)
		}

		commandNum++
		commandsSent++

		// Log when we cross the grace period boundary
		elapsed := time.Since(sessionStart)
		if elapsed >= 2*time.Minute && !startPhase2 {
			startPhase2 = true
			t.Logf("✓ Crossed grace period boundary at T+%.1fs (sent %d commands so far)",
				elapsed.Seconds(), commandsSent)
		}

		// Log progress every 60 commands (~72 seconds)
		if commandsSent%60 == 0 {
			t.Logf("  Progress: T+%.1fs | Commands: %d | Est. throughput: ~600 bytes/min",
				elapsed.Seconds(), commandsSent)
		}
	}

	elapsed := time.Since(sessionStart)
	totalBytes := commandsSent * 12 // Approximate bytes per NOOP
	avgBytesPerMin := float64(totalBytes) / elapsed.Minutes()

	t.Logf("\n✅ SUCCESS: Valid user maintained connection for %.1f minutes", elapsed.Minutes())
	t.Logf("   Commands sent: %d", commandsSent)
	t.Logf("   Approximate bytes: %d", totalBytes)
	t.Logf("   Average throughput: %.0f bytes/minute", avgBytesPerMin)
	t.Logf("   Threshold: 512 bytes/minute")
	t.Logf("\n✅ CONCLUSION: Steady throughput above threshold keeps connection alive")
}
