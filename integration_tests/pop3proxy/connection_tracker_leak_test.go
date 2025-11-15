//go:build integration

package pop3proxy_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestConnectionTrackerLeak verifies that the connection tracker properly unregisters
// connections when clients disconnect, preventing the connection leak bug where
// connections remained registered indefinitely due to a circular dependency in
// the context cancellation handler.
func TestConnectionTrackerLeak(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Set up POP3 proxy
	proxyAddress := common.GetRandomAddress(t)

	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddress,
		backendServer.ResilientDB,
		pop3proxy.POP3ProxyServerOptions{
			Name:               "test-proxy",
			RemoteAddrs:        []string{backendServer.Address},
			RemotePort:         110,
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
			AuthRateLimit: server.AuthRateLimiterConfig{
				Enabled: false,
			},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	// Create and set connection tracker (local mode with nil cluster manager)
	tracker := server.NewConnectionTracker("POP3", "test-instance", nil, 5, 2, 1000)
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

	// Connect and authenticate
	conn, err := common.DialPOP3(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 proxy: %v", err)
	}

	if err := common.POP3Login(conn, account.Email, account.Password); err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}

	// Give server time to register connection
	time.Sleep(100 * time.Millisecond)

	// Verify connection was registered
	count := tracker.GetConnectionCount(accountID)
	if count != 1 {
		t.Errorf("After authentication, connection count should be 1, got %d", count)
	}

	t.Log("Disconnecting client...")

	// THE CRITICAL TEST: Disconnect and verify connection is unregistered
	if err := common.POP3Quit(conn); err != nil {
		t.Logf("Error during QUIT (may be expected): %v", err)
	}

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
