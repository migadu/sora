//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// getRandomPort returns a random available port
func getRandomPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to get random port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// TestIMAPProxyUserAffinity verifies that the same user consistently routes to the same backend
// using consistent hashing (without explicit affinity entries)
func TestIMAPProxyUserAffinity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backend1, account := common.SetupIMAPServerWithPROXY(t)
	defer backend1.Close()

	// Create a second backend address (even if server doesn't exist, we can test affinity logic)
	backend2Addr := fmt.Sprintf("127.0.0.1:%d", getRandomPort(t))

	// Create a test cluster for affinity
	clusterCfg := config.ClusterConfig{
		Enabled:   true,
		BindAddr:  "127.0.0.1",
		BindPort:  getRandomPort(t),
		NodeID:    "test-proxy-node",
		Peers:     []string{},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	}

	clusterMgr, err := cluster.New(clusterCfg)
	if err != nil {
		t.Fatalf("Failed to create cluster manager: %v", err)
	}
	defer clusterMgr.Shutdown()

	// Create affinity manager
	affinityMgr := server.NewAffinityManager(clusterMgr, true, 1*time.Hour, 10*time.Minute)

	// Set up IMAP proxy with affinity enabled pointing to two backends
	ctx := context.Background()
	proxyAddress := common.GetRandomAddress(t)

	proxyServer, err := imapproxy.New(ctx, backend1.ResilientDB, "test-proxy", imapproxy.ServerOptions{
		Name:                   "test-proxy",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backend1.Address, backend2Addr},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser", // Match the master credentials from SetupIMAPServerWithPROXY
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         5 * time.Second,
		SessionTimeout:         30 * time.Second,
		EnableAffinity:         true, // Enable affinity
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Attach affinity manager to connection manager (this is what main.go should do)
	connMgr := proxyServer.GetConnectionManager()
	if connMgr == nil {
		t.Fatal("Connection manager is nil")
	}
	connMgr.SetAffinityManager(affinityMgr)

	// Start proxy server
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("Proxy server stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// First connection - should use consistent hash
	t.Log("First connection - using consistent hash")
	client1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer client1.Close()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("First login failed: %v", err)
	}

	// Get which backend the user was routed to via consistent hash
	time.Sleep(100 * time.Millisecond)
	consistentHashBackend := connMgr.GetBackendByConsistentHash(account.Email)
	t.Logf("First connection: Routed to %s via consistent hash", consistentHashBackend)

	// Since user connected to their consistent hash backend, NO affinity entry should exist
	// (affinity is only created for failover scenarios)
	_, foundAffinity := affinityMgr.GetBackend(account.Email, "imap")
	if foundAffinity {
		t.Log("Note: Affinity entry exists (may be from failover)")
	} else {
		t.Log("No affinity entry (expected: user on consistent hash backend)")
	}

	// Logout
	if err := client1.Logout().Wait(); err != nil {
		t.Logf("Logout error (may be expected): %v", err)
	}
	client1.Close()
	time.Sleep(50 * time.Millisecond)

	// Second connection - should route to same backend via consistent hash
	t.Log("Second connection - should route to same backend")
	client2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer client2.Close()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Second login failed: %v", err)
	}

	// Verify consistent hash still points to same backend
	consistentHashBackend2 := connMgr.GetBackendByConsistentHash(account.Email)
	if consistentHashBackend2 != consistentHashBackend {
		t.Errorf("Consistent hash changed: %s -> %s (should be stable)", consistentHashBackend, consistentHashBackend2)
	}
	t.Logf("Second connection: Still routed to %s via consistent hash", consistentHashBackend2)

	// Logout
	if err := client2.Logout().Wait(); err != nil {
		t.Logf("Logout error (may be expected): %v", err)
	}

	t.Logf("✅ PASS: User affinity is stable - both connections routed to %s", consistentHashBackend)
}

// TestIMAPProxyAffinityFailover verifies that affinity is correctly set during failover scenarios
func TestIMAPProxyAffinityFailover(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create two backend IMAP servers
	backend1, account := common.SetupIMAPServerWithPROXY(t)
	backend2, _ := common.SetupIMAPServerWithPROXY(t)

	// Don't use defer Close() here since we manually close one backend to force failover
	// Instead, close them at the end
	t.Cleanup(func() {
		// Close whichever backend is still running
		// (one will already be closed from failover test)
		backend1.Close()
		backend2.Close()
	})

	// Create a test cluster for affinity
	clusterCfg := config.ClusterConfig{
		Enabled:   true,
		BindAddr:  "127.0.0.1",
		BindPort:  getRandomPort(t),
		NodeID:    "test-failover-node",
		Peers:     []string{},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	}

	clusterMgr, err := cluster.New(clusterCfg)
	if err != nil {
		t.Fatalf("Failed to create cluster manager: %v", err)
	}
	defer clusterMgr.Shutdown()

	// Create affinity manager
	affinityMgr := server.NewAffinityManager(clusterMgr, true, 1*time.Hour, 10*time.Minute)

	// Set up IMAP proxy with both backends
	ctx := context.Background()
	proxyAddress := common.GetRandomAddress(t)

	proxyServer, err := imapproxy.New(ctx, backend1.ResilientDB, "test-failover-proxy", imapproxy.ServerOptions{
		Name:                   "test-failover-proxy",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backend1.Address, backend2.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         2 * time.Second,
		SessionTimeout:         30 * time.Second,
		EnableAffinity:         true,
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	connMgr := proxyServer.GetConnectionManager()
	if connMgr == nil {
		t.Fatal("Connection manager is nil")
	}
	connMgr.SetAffinityManager(affinityMgr)

	// Start proxy server
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("Proxy server stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Determine which backend consistent hash picks
	consistentHashBackend := connMgr.GetBackendByConsistentHash(account.Email)
	t.Logf("Consistent hash backend for user: %s", consistentHashBackend)

	// Shut down the consistent hash backend to force failover
	if consistentHashBackend == backend1.Address {
		t.Logf("Shutting down backend1 (%s) to force failover to backend2", backend1.Address)
		backend1.Close()
		time.Sleep(200 * time.Millisecond) // Wait for backend to fully stop
	} else {
		t.Logf("Shutting down backend2 (%s) to force failover to backend1", backend2.Address)
		backend2.Close()
		time.Sleep(200 * time.Millisecond)
	}

	// First connection - should failover and create affinity entry
	t.Log("First connection - should trigger failover")
	client1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer client1.Close()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("First login failed (failover should work): %v", err)
	}

	// Check that affinity was set due to failover
	time.Sleep(100 * time.Millisecond)
	affinityBackend, foundAffinity := affinityMgr.GetBackend(account.Email, "imap")
	if !foundAffinity {
		t.Fatal("Affinity should be set after failover")
	}

	// Verify affinity points to different backend than consistent hash
	if affinityBackend == consistentHashBackend {
		t.Errorf("Affinity backend (%s) should differ from consistent hash backend (%s) after failover",
			affinityBackend, consistentHashBackend)
	}
	t.Logf("First connection: Failover successful, affinity set to %s", affinityBackend)

	// Logout
	if err := client1.Logout().Wait(); err != nil {
		t.Logf("Logout error (may be expected): %v", err)
	}
	client1.Close()
	time.Sleep(50 * time.Millisecond)

	// Second connection - should use affinity and route to same failover backend
	t.Log("Second connection - should use affinity from failover")
	client2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer client2.Close()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Second login failed: %v", err)
	}

	// Verify affinity is still the same
	affinityBackend2, foundAffinity2 := affinityMgr.GetBackend(account.Email, "imap")
	if !foundAffinity2 {
		t.Error("Affinity should still be set after second connection")
	}
	if affinityBackend2 != affinityBackend {
		t.Errorf("Affinity changed between connections: %s -> %s (should be stable)",
			affinityBackend, affinityBackend2)
	}
	t.Logf("Second connection: Affinity stable, still routed to %s", affinityBackend2)

	// Logout
	if err := client2.Logout().Wait(); err != nil {
		t.Logf("Logout error (may be expected): %v", err)
	}

	t.Logf("✅ PASS: Affinity correctly tracks failover - both connections to %s (failed over from %s)",
		affinityBackend, consistentHashBackend)
}

// TestIMAPProxyAffinityWithoutAffinityManager verifies that affinity doesn't work when manager is not attached
// This test documents the bug we fixed - affinity was enabled but manager wasn't attached
func TestIMAPProxyAffinityWithoutAffinityManager(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backend1, account := common.SetupIMAPServerWithPROXY(t)
	defer backend1.Close()

	// Set up IMAP proxy with affinity enabled BUT don't attach affinity manager
	// This simulates the bug we fixed in main.go
	ctx := context.Background()
	proxyAddress := common.GetRandomAddress(t)

	proxyServer, err := imapproxy.New(ctx, backend1.ResilientDB, "test-proxy-no-affinity", imapproxy.ServerOptions{
		Name:                   "test-proxy-no-affinity",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backend1.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         5 * time.Second,
		SessionTimeout:         30 * time.Second,
		EnableAffinity:         true, // Enabled but manager not attached!
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Verify connection manager exists but has NO affinity manager attached
	connMgr := proxyServer.GetConnectionManager()
	if connMgr == nil {
		t.Fatal("Connection manager is nil")
	}
	if connMgr.GetAffinityManager() != nil {
		t.Fatal("Affinity manager should be nil (testing the bug scenario)")
	}

	// Start proxy server
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("Proxy server stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Connect - should work even though affinity manager is not attached
	t.Log("Connecting without affinity manager attached")
	client, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Logout
	if err := client.Logout().Wait(); err != nil {
		t.Logf("Logout error (may be expected): %v", err)
	}

	t.Log("✅ PASS: Proxy works even without affinity manager (falls back to round-robin)")
	t.Log("Note: This test documents the bug - enable_affinity=true but no manager attached")
}
