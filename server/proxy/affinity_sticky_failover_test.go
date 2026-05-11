//go:build integration

package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestAffinityStickyFailover tests that users stay on their failover backend
// even after the original backend auto-recovers (1-minute grace period)
func TestAffinityStickyFailover(t *testing.T) {
	cluster1, err := createTestCluster("node-sticky-test", 30946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	affinity := server.NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	connMgr, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}
	connMgr.SetAffinityManager(affinity)

	username := "sticky-user@example.com"
	protocol := "imap"

	// Step 1: User has affinity to backend2
	affinity.SetBackend(username, "backend2:143", protocol)
	t.Logf("Step 1: Set affinity to backend2:143")

	// Step 2: Mark backend2 as unhealthy (3 consecutive failures)
	t.Logf("Step 2: Marking backend2:143 as unhealthy (3 failures)...")
	for i := 0; i < 3; i++ {
		connMgr.RecordConnectionFailure("backend2:143")
	}

	if connMgr.IsBackendHealthy("backend2:143") {
		t.Fatal("backend2:143 should be unhealthy after 3 failures")
	}
	t.Logf("backend2:143 marked unhealthy")

	// Step 3: Route user - should detect unhealthy backend, delete affinity, fall back
	t.Logf("Step 3: Routing user (should failover to healthy backend)...")
	result, err := DetermineRoute(RouteParams{
		Ctx:                   context.Background(),
		Username:              username,
		Protocol:              protocol,
		IsRemoteLookupAccount: false,
		RoutingInfo:           nil,
		ConnManager:           connMgr,
		EnableAffinity:        true,
		ProxyName:             "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	if result.PreferredAddr == "backend2:143" {
		t.Fatal("Should NOT route to unhealthy backend2:143")
	}

	failoverBackend := result.PreferredAddr
	t.Logf("User failed over to: %s (method: %s)", failoverBackend, result.RoutingMethod)

	// Step 4: Simulate successful connection - affinity should be updated
	affinity.UpdateBackend(username, "backend2:143", failoverBackend, protocol)
	t.Logf("Step 4: Affinity updated to failover backend: %s", failoverBackend)

	// Step 5: Wait for 1-minute auto-recovery window
	t.Logf("Step 5: Waiting 61 seconds for auto-recovery window...")
	time.Sleep(61 * time.Second)

	// Step 6: Check IsBackendHealthyForAffinity FIRST (before auto-recovery mutates state)
	// IMPORTANT: Must check affinity health BEFORE calling IsBackendHealthy() which triggers auto-recovery
	healthyForAffinity := connMgr.IsBackendHealthyForAffinity("backend2:143")
	healthyWithAutoRecovery := connMgr.IsBackendHealthy("backend2:143")

	t.Logf("Step 6: backend2:143 status after 1 minute:")
	t.Logf("  - IsBackendHealthyForAffinity (no auto-recovery): %v", healthyForAffinity)
	t.Logf("  - IsBackendHealthy (with auto-recovery): %v", healthyWithAutoRecovery)

	if healthyForAffinity {
		t.Error("❌ FAIL: backend2:143 should NOT be healthy for affinity checks (sticky failover)")
	} else {
		t.Logf("✅ PASS: backend2:143 NOT healthy for affinity (sticky failover works)")
	}

	if !healthyWithAutoRecovery {
		t.Error("backend2:143 should be auto-recovered for consistent-hash routing")
	} else {
		t.Logf("✅ PASS: backend2:143 auto-recovered for consistent-hash (new users can use it)")
	}

	// Step 7: Route the user again - should stay on failover backend (sticky)
	t.Logf("Step 7: Routing user again (should stay on failover backend)...")
	result, err = DetermineRoute(RouteParams{
		Ctx:                   context.Background(),
		Username:              username,
		Protocol:              protocol,
		IsRemoteLookupAccount: false,
		RoutingInfo:           nil,
		ConnManager:           connMgr,
		EnableAffinity:        true,
		ProxyName:             "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	t.Logf("Routing result: method=%s, addr=%s", result.RoutingMethod, result.PreferredAddr)

	// CRITICAL: User should stay on failover backend, NOT cycle back to backend2
	if result.PreferredAddr != failoverBackend {
		t.Errorf("❌ FAIL: User cycled back to different backend: %s (expected: %s)",
			result.PreferredAddr, failoverBackend)
		t.Error("Users should stay on their failover backend (sticky failover)")
	} else {
		t.Logf("✅ PASS: User stayed on failover backend: %s (sticky failover works!)", failoverBackend)
	}

	// Step 8: Verify new users CAN use the recovered backend (via consistent hash)
	t.Logf("Step 8: Testing that NEW users can use recovered backend...")
	newUser := "new-user@example.com"

	// Check if consistent hash picks backend2 for this new user
	consistentBackend := connMgr.GetBackendByConsistentHash(newUser)
	t.Logf("Consistent hash for new user picks: %s", consistentBackend)

	if consistentBackend == "backend2:143" {
		t.Logf("✅ PASS: New users CAN use recovered backend2:143 (auto-recovery works for consistent-hash)")
	} else {
		t.Logf("Note: Consistent hash picked different backend for new user (expected behavior)")
	}
}

// TestAffinityDeletesOnRealUnhealthy verifies affinity is deleted when backend stays unhealthy
func TestAffinityDeletesOnRealUnhealthy(t *testing.T) {
	cluster1, err := createTestCluster("node-delete-test", 31946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	affinity := server.NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	backends := []string{"backend1:143", "backend2:143"}
	connMgr, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}
	connMgr.SetAffinityManager(affinity)

	username := "delete-test@example.com"
	protocol := "imap"

	// Set affinity
	affinity.SetBackend(username, "backend1:143", protocol)

	// Mark backend unhealthy
	for i := 0; i < 3; i++ {
		connMgr.RecordConnectionFailure("backend1:143")
	}

	// Route user - affinity should be deleted
	result, err := DetermineRoute(RouteParams{
		Ctx:                   context.Background(),
		Username:              username,
		Protocol:              protocol,
		IsRemoteLookupAccount: false,
		RoutingInfo:           nil,
		ConnManager:           connMgr,
		EnableAffinity:        true,
		ProxyName:             "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	// Verify affinity was deleted
	time.Sleep(100 * time.Millisecond)
	_, found := affinity.GetBackend(username, protocol)
	if found {
		t.Error("Affinity should be deleted when backend is unhealthy")
	}

	// Verify routed to different backend
	if result.PreferredAddr == "backend1:143" {
		t.Error("Should not route to unhealthy backend")
	}

	t.Logf("✅ PASS: Affinity deleted, routed to healthy backend: %s", result.PreferredAddr)
}
