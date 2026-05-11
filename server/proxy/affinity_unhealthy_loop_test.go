//go:build integration

package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestAffinityUnhealthyBackendLoop tests that users don't get stuck on unhealthy backends
// Reproduces the issue where:
// 1. Affinity backend becomes unhealthy
// 2. Affinity is deleted
// 3. Consistent hash picks the SAME unhealthy backend (deterministic)
// 4. User gets stuck in a loop
func TestAffinityUnhealthyBackendLoop(t *testing.T) {
	// Create cluster and affinity manager
	cluster1, err := createTestCluster("node-loop-test", 26946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	affinity := server.NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	// Create connection manager with 3 backends
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	connMgr, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}
	connMgr.SetAffinityManager(affinity)

	username := "test-user@example.com"
	protocol := "imap"

	// Step 1: Set affinity to backend2
	affinity.SetBackend(username, "backend2:143", protocol)
	t.Logf("Step 1: Set affinity to backend2:143")

	// Verify affinity is set
	backend, found := affinity.GetBackend(username, protocol)
	if !found || backend != "backend2:143" {
		t.Fatalf("Initial affinity not set correctly: backend=%s, found=%v", backend, found)
	}

	// Step 2: Mark backend2 as unhealthy (3 consecutive failures)
	t.Logf("Step 2: Marking backend2:143 as unhealthy...")
	for i := 0; i < 3; i++ {
		connMgr.RecordConnectionFailure("backend2:143")
	}

	if connMgr.IsBackendHealthy("backend2:143") {
		t.Fatal("backend2:143 should be unhealthy after 3 failures")
	}

	// Step 3: Try to route the user - should detect unhealthy backend and fall back
	t.Logf("Step 3: Attempting to route user with unhealthy affinity backend...")
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

	t.Logf("Routing result: method=%s, addr=%s", result.RoutingMethod, result.PreferredAddr)

	// Step 4: Verify we did NOT route to backend2 (unhealthy)
	if result.PreferredAddr == "backend2:143" {
		t.Errorf("❌ FAIL: Routed to unhealthy backend2:143 - user is STUCK")
	}

	// Step 5: Verify affinity was deleted
	time.Sleep(100 * time.Millisecond) // Give gossip time to propagate
	_, found = affinity.GetBackend(username, protocol)
	if found {
		t.Error("Affinity should be deleted after detecting unhealthy backend")
	}

	// Step 6: Check which backend was selected by consistent hash
	consistentHashBackend := connMgr.GetBackendByConsistentHash(username)
	t.Logf("Step 6: Consistent hash selected: %s", consistentHashBackend)

	// If consistent hash picks backend2 (the unhealthy one), it should skip it
	if consistentHashBackend == "backend2:143" {
		t.Error("❌ FAIL: Consistent hash returned unhealthy backend2:143 - should have been excluded")
	}

	// Step 7: Verify final routing is to a healthy backend
	if result.PreferredAddr != "" && result.PreferredAddr != "backend2:143" {
		t.Logf("✅ PASS: User routed to healthy backend: %s (method: %s)", result.PreferredAddr, result.RoutingMethod)
	} else if result.PreferredAddr == "" {
		// Empty means round-robin fallback (all backends in consistent hash were unhealthy)
		t.Logf("Note: Fell back to round-robin (PreferredAddr empty)")
	}

	// Step 8: Make multiple attempts to verify user doesn't cycle back to backend2
	t.Logf("Step 8: Making 5 consecutive routing attempts to verify stability...")
	for i := 0; i < 5; i++ {
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
			t.Fatalf("DetermineRoute attempt %d failed: %v", i+1, err)
		}

		if result.PreferredAddr == "backend2:143" {
			t.Errorf("❌ FAIL: Attempt %d routed to unhealthy backend2:143", i+1)
		} else {
			t.Logf("Attempt %d: %s (method: %s)", i+1, result.PreferredAddr, result.RoutingMethod)
		}
	}

	t.Logf("✅ PASS: User successfully avoided unhealthy backend across multiple attempts")
}

// TestAffinityFailoverWithConsistentHashCollision tests the specific case where
// consistent hash wants to route to the same unhealthy backend as affinity
func TestAffinityFailoverWithConsistentHashCollision(t *testing.T) {
	cluster1, err := createTestCluster("node-collision-test", 27946, []string{})
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

	username := "collision-user@example.com"
	protocol := "imap"

	// Find which backend consistent hash naturally picks for this user
	naturalBackend := connMgr.GetBackendByConsistentHash(username)
	t.Logf("Consistent hash naturally picks: %s", naturalBackend)

	// Set affinity to the same backend that consistent hash would pick
	affinity.SetBackend(username, naturalBackend, protocol)
	t.Logf("Set affinity to match consistent hash: %s", naturalBackend)

	// Mark that backend as unhealthy
	t.Logf("Marking %s as unhealthy...", naturalBackend)
	for i := 0; i < 3; i++ {
		connMgr.RecordConnectionFailure(naturalBackend)
	}

	if connMgr.IsBackendHealthy(naturalBackend) {
		t.Fatalf("%s should be unhealthy after 3 failures", naturalBackend)
	}

	// Attempt routing - should NOT get stuck on the unhealthy backend
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

	t.Logf("Result: method=%s, addr=%s", result.RoutingMethod, result.PreferredAddr)

	// CRITICAL: Should NOT route to the unhealthy backend
	if result.PreferredAddr == naturalBackend {
		t.Errorf("❌ FAIL: Routed to unhealthy backend %s even though consistent hash points there", naturalBackend)
		t.Error("This is the COLLISION BUG - consistent hash picked the same unhealthy backend")
	} else {
		t.Logf("✅ PASS: Routed to different backend %s, avoiding unhealthy %s", result.PreferredAddr, naturalBackend)
	}

	// Verify affinity was deleted
	_, found := affinity.GetBackend(username, protocol)
	if found {
		t.Error("Affinity should be deleted")
	}
}
