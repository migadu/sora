//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net/textproto"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestConnectionTrackerLeak verifies that the connection tracker properly unregisters
// connections when clients disconnect, preventing the connection leak bug where
// connections remained registered indefinitely due to a circular dependency in
// the context cancellation handler.
//
// NOTE: LMTP registers connections on RCPT TO command (when accountID is determined),
// so we need to send a full LMTP transaction to test connection tracking.
func TestConnectionTrackerLeak(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend LMTP server
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy
	proxyAddress := common.GetRandomAddress(t)

	proxy, err := lmtpproxy.New(
		context.Background(),
		backendServer.ResilientDB,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:             "test-proxy",
			Addr:             proxyAddress,
			RemoteAddrs:      []string{backendServer.Address},
			RemotePort:       24,
			RemoteUseXCLIENT: true,
			TrustedProxies:   []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	// Create and set connection tracker (local mode with nil cluster manager)
	tracker := server.NewConnectionTracker("LMTP", "test-instance", nil, 5, 2, 1000)
	proxy.SetConnectionTracker(tracker)

	// Start proxy in background
	go proxy.Start()
	time.Sleep(100 * time.Millisecond)
	defer proxy.Stop()

	// Get account ID for tracking
	accountID, err := backendServer.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	t.Logf("Testing connection tracker leak for account: %s (ID: %d)", account.Email, accountID)

	// Verify initial connection count
	initialCount := tracker.GetConnectionCount(accountID)
	if initialCount != 0 {
		t.Errorf("Initial connection count should be 0, got %d", initialCount)
	}

	// Connect to LMTP proxy
	conn, err := common.DialLMTP(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}

	// Use textproto for LMTP protocol communication
	tp := textproto.NewConn(conn)
	defer tp.Close()

	// Send LHLO
	if err := tp.PrintfLine("LHLO client.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	// Read multi-line response
	_, _, err = tp.ReadResponse(250)
	if err != nil {
		t.Fatalf("LHLO failed: %v", err)
	}

	// Send MAIL FROM
	if err := tp.PrintfLine("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	_, _, err = tp.ReadResponse(250)
	if err != nil {
		t.Fatalf("MAIL FROM failed: %v", err)
	}

	// Send RCPT TO (this triggers connection tracking)
	if err := tp.PrintfLine("RCPT TO:<%s>", account.Email); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	_, _, err = tp.ReadResponse(250)
	if err != nil {
		t.Fatalf("RCPT TO failed: %v", err)
	}

	// Give server time to register connection
	time.Sleep(100 * time.Millisecond)

	// Verify connection was registered
	count := tracker.GetConnectionCount(accountID)
	if count != 1 {
		t.Errorf("After RCPT TO, connection count should be 1, got %d", count)
	}

	t.Log("Disconnecting client...")

	// THE CRITICAL TEST: Send QUIT and disconnect
	if err := tp.PrintfLine("QUIT"); err != nil {
		t.Logf("Failed to send QUIT (may be expected): %v", err)
	}
	tp.Close()

	// Give server time to unregister connection (should be immediate after the fix)
	time.Sleep(5 * time.Second)

	// Verify connection was unregistered
	finalCount := tracker.GetConnectionCount(accountID)
	if finalCount != 0 {
		t.Errorf("❌ BUG REPRODUCED: After disconnect, connection count should be 0, got %d", finalCount)
		t.Error("This indicates the connection tracker leak bug still exists!")
	} else {
		t.Logf("✓ Connection properly unregistered: count=%d", finalCount)
	}
}

// Helper function to read LMTP response (for debugging)
func readLMTPResponse(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("connection closed")
	}
	return scanner.Text(), nil
}
