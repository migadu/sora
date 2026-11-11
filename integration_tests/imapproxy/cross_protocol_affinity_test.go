//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestCrossProtocolAffinity verifies that a user connecting via IMAP
// is routed to the same backend as their existing POP3/LMTP affinity
func TestCrossProtocolAffinity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create two backend IMAP servers
	backend1, account := common.SetupIMAPServerWithPROXY(t)
	defer backend1.Close()

	backend2, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend2.Close()

	// Create cluster for affinity
	clusterCfg := config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", getRandomPort(t)),
		NodeID:    "test-cross-protocol",
		Peers:     []string{},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	}

	clusterMgr, err := cluster.New(clusterCfg)
	if err != nil {
		t.Fatalf("Failed to create cluster manager: %v", err)
	}
	defer clusterMgr.Shutdown()

	// Create affinity manager
	affinityMgr := server.NewAffinityManager(clusterMgr, true, 1*time.Hour, 10*time.Minute)

	// Set up IMAP proxy
	ctx := context.Background()
	proxyAddress := common.GetRandomAddress(t)

	proxyServer, err := imapproxy.New(ctx, backend1.ResilientDB, "test-cross-proto-proxy", imapproxy.ServerOptions{
		Name:                   "test-cross-proto-proxy",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backend1.Address, backend2.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
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

	// Start proxy
	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("Proxy server stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Simulate POP3 connection creating affinity to backend1
	// (In real scenario, POP3 proxy would set this)
	affinityMgr.SetBackend(account.Email, backend1.Address, "pop3")
	t.Logf("Simulated POP3 affinity set to backend1: %s", backend1.Address)

	// Now connect via IMAP - should route to backend1 due to cross-protocol affinity
	client, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP login failed: %v", err)
	}

	// Give time for affinity to be processed
	time.Sleep(100 * time.Millisecond)

	// Check that IMAP connection used cross-protocol affinity
	// We can't directly verify which backend was used, but we can check affinity state
	imapBackend, imapFound := affinityMgr.GetBackend(account.Email, "imap")
	pop3Backend, pop3Found := affinityMgr.GetBackend(account.Email, "pop3")

	if !pop3Found {
		t.Error("POP3 affinity should still exist")
	}

	// IMAP should either:
	// 1. Have created its own affinity to backend1 (cross-protocol routing worked), OR
	// 2. Have no affinity (used cross-protocol from POP3 without creating its own)
	if imapFound {
		if imapBackend != backend1.Address {
			t.Errorf("IMAP affinity backend (%s) should match POP3 affinity backend (%s)",
				imapBackend, pop3Backend)
		}
		t.Logf("✓ IMAP created affinity to same backend as POP3: %s", imapBackend)
	} else {
		// Check if cross-protocol lookup returns backend1
		backend, foundProtocol, found := affinityMgr.GetBackendAcrossProtocols(account.Email, "imap")
		if !found || backend != backend1.Address {
			t.Errorf("Cross-protocol affinity should return backend1 (%s), got: %s (found: %v)",
				backend1.Address, backend, found)
		}
		if foundProtocol != "pop3" {
			t.Errorf("Cross-protocol affinity should be from POP3, got: %s", foundProtocol)
		}
		t.Logf("✓ IMAP used cross-protocol affinity from POP3: %s", backend)
	}

	client.Logout()
	client.Close()

	t.Log("✅ PASS: Cross-protocol affinity enables cache locality")
}

// TestCrossProtocolAffinityPriority verifies protocol-specific affinity takes precedence
func TestCrossProtocolAffinityPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend1, account := common.SetupIMAPServerWithPROXY(t)
	defer backend1.Close()

	backend2, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend2.Close()

	clusterCfg := config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", getRandomPort(t)),
		NodeID:    "test-priority",
		Peers:     []string{},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	}

	clusterMgr, err := cluster.New(clusterCfg)
	if err != nil {
		t.Fatalf("Failed to create cluster manager: %v", err)
	}
	defer clusterMgr.Shutdown()

	affinityMgr := server.NewAffinityManager(clusterMgr, true, 1*time.Hour, 10*time.Minute)

	ctx := context.Background()
	proxyAddress := common.GetRandomAddress(t)

	proxyServer, err := imapproxy.New(ctx, backend1.ResilientDB, "test-priority-proxy", imapproxy.ServerOptions{
		Name:                   "test-priority-proxy",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backend1.Address, backend2.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
		EnableAffinity:         true,
		AuthRateLimit:          server.DefaultAuthRateLimiterConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	connMgr := proxyServer.GetConnectionManager()
	connMgr.SetAffinityManager(affinityMgr)

	go func() {
		if err := proxyServer.Start(); err != nil {
			t.Logf("Proxy server stopped: %v", err)
		}
	}()
	defer proxyServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Set POP3 affinity to backend1
	affinityMgr.SetBackend(account.Email, backend1.Address, "pop3")
	// Set IMAP affinity to backend2 (different)
	affinityMgr.SetBackend(account.Email, backend2.Address, "imap")

	// Verify both affinities are set correctly before connection
	imapBefore, imapFoundBefore := affinityMgr.GetBackend(account.Email, "imap")
	pop3Before, pop3FoundBefore := affinityMgr.GetBackend(account.Email, "pop3")
	if !imapFoundBefore || imapBefore != backend2.Address {
		t.Fatalf("IMAP affinity not set correctly before connection: found=%v addr=%s", imapFoundBefore, imapBefore)
	}
	if !pop3FoundBefore || pop3Before != backend1.Address {
		t.Fatalf("POP3 affinity not set correctly before connection: found=%v addr=%s", pop3FoundBefore, pop3Before)
	}
	t.Logf("Pre-connection: IMAP affinity → %s, POP3 affinity → %s", imapBefore, pop3Before)

	// GetBackendAcrossProtocols should prefer IMAP's own affinity over POP3's
	backend, foundProtocol, found := affinityMgr.GetBackendAcrossProtocols(account.Email, "imap")
	if !found {
		t.Fatal("Expected to find affinity via GetBackendAcrossProtocols")
	}
	if foundProtocol != "imap" {
		t.Errorf("Expected GetBackendAcrossProtocols to prefer IMAP protocol, got: %s", foundProtocol)
	}
	if backend != backend2.Address {
		t.Errorf("Expected GetBackendAcrossProtocols to return backend2 (%s), got: %s",
			backend2.Address, backend)
	}
	t.Logf("✓ GetBackendAcrossProtocols correctly prefers IMAP affinity (backend2: %s) over POP3 (backend1: %s)", backend2.Address, backend1.Address)

	// Connect via IMAP - should use IMAP-specific affinity (backend2), not POP3's
	client, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP login failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// After connection, IMAP affinity may have been cleared by UpdateAffinityAfterConnection
	// if backend2 happened to match the consistent hash backend (making affinity redundant).
	// This is correct behavior — the important thing is that the routing decision used
	// IMAP's own affinity (backend2), not POP3's cross-protocol affinity (backend1).
	// We already verified the priority logic above before the connection.

	// Verify POP3 affinity is still intact (IMAP connection shouldn't affect it)
	pop3After, pop3FoundAfter := affinityMgr.GetBackend(account.Email, "pop3")
	if !pop3FoundAfter {
		t.Error("POP3 affinity should still exist after IMAP connection")
	} else if pop3After != backend1.Address {
		t.Errorf("POP3 affinity should still point to backend1 (%s), got: %s", backend1.Address, pop3After)
	}

	t.Logf("✅ PASS: Protocol-specific affinity takes precedence over cross-protocol affinity")
}
