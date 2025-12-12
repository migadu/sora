//go:build integration

package imapproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestConnectionTrackerLeak verifies that connections are properly unregistered
// when clients disconnect. This is a regression test for a critical bug where
// proxy sessions would leak in the connection tracker, causing the counter to
// grow indefinitely until hitting the per-user limit.
//
// Root cause: handleConnection() defers close(), but gets stuck in wg.Wait()
// waiting for copy goroutines that never complete when client disconnects.
func TestConnectionTrackerLeak(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Get account ID from database
	ctx := context.Background()
	accountIDNum, err := backendServer.ResilientDB.GetAccountIDByEmailWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}
	accountID := accountIDNum

	// Set up IMAP proxy with connection tracking
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupProxyWithConnectionTracking(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address})
	defer proxyServer.Close()

	// Get the connection tracker
	proxy, ok := proxyServer.Server.(*imapproxy.Server)
	if !ok {
		t.Fatalf("Failed to cast to IMAP proxy server")
	}
	tracker := proxy.GetConnectionTracker()
	if tracker == nil {
		t.Fatalf("Connection tracker is nil - tracking not enabled")
	}

	t.Logf("Testing connection tracker leak for account: %s (ID: %d)", account.Email, accountID)

	// Verify initial state
	initialCount := tracker.GetConnectionCount(accountID)
	if initialCount != 0 {
		t.Errorf("Initial connection count should be 0, got %d", initialCount)
	}

	// Connect and authenticate
	client, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		client.Close()
		t.Fatalf("Failed to authenticate: %v", err)
	}

	// Wait for connection to be registered
	time.Sleep(300 * time.Millisecond)

	// Verify connection was registered
	count := tracker.GetConnectionCount(accountID)
	if count != 1 {
		t.Errorf("After authentication, connection count should be 1, got %d", count)
	}

	// THE CRITICAL TEST: Disconnect and verify connection is unregistered
	t.Log("Disconnecting client...")
	err = client.Close()
	if err != nil {
		t.Logf("Warning: client.Close() returned error: %v", err)
	}

	// Wait for proxy to process disconnect and call close()
	// This should be fast (< 1 second) but we give it generous time
	time.Sleep(5 * time.Second)

	// Verify connection was unregistered
	finalCount := tracker.GetConnectionCount(accountID)
	if finalCount != 0 {
		t.Errorf("❌ BUG REPRODUCED: After disconnect, connection count should be 0, got %d", finalCount)
		t.Error("This confirms the connection tracker leak bug - sessions are not being cleaned up!")
		t.Log("Root cause: handleConnection() is stuck in wg.Wait() because copy goroutines never exit")
	} else {
		t.Logf("✓ Connection properly unregistered: count=%d", finalCount)
	}
}

// setupProxyWithConnectionTracking creates an IMAP proxy with ConnectionTracker enabled
func setupProxyWithConnectionTracking(t *testing.T, rdb *resilient.ResilientDatabase,
	proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	// Create connection tracker
	tracker := server.NewConnectionTracker("IMAP", "test-instance", nil, 5, 2, 1000, false)

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        10 * time.Minute,
		EnableAffinity:         false,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, "test-proxy", opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Set the connection tracker
	proxy.SetConnectionTracker(tracker)

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
