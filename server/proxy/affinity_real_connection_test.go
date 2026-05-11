//go:build integration

package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestAffinityWithRealConnectionFailures simulates what happens in production:
// - Multiple users have affinity to a backend
// - Backend goes down
// - Users keep getting routed there until 3 failures accumulate
func TestAffinityWithRealConnectionFailures(t *testing.T) {
	cluster1, err := createTestCluster("node-conn-test", 28946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	affinity := server.NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	// Create connection manager with backends (none are actually listening)
	backends := []string{"127.0.0.1:19143", "127.0.0.1:19144"}
	connMgr, err := NewConnectionManager(backends, 143, false, false, false, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}
	connMgr.SetAffinityManager(affinity)

	// Simulate 5 users with affinity to backend1 (which is down)
	users := []string{
		"user1@example.com",
		"user2@example.com",
		"user3@example.com",
		"user4@example.com",
		"user5@example.com",
	}

	downBackend := "127.0.0.1:19143"
	upBackend := "127.0.0.1:19144"

	// Set affinity for all users to the down backend
	for _, user := range users {
		affinity.SetBackend(user, downBackend, "pop3")
	}
	t.Logf("Set affinity for all 5 users to down backend: %s", downBackend)

	// Start a listener on the "up" backend
	listener, err := net.Listen("tcp", upBackend)
	if err != nil {
		t.Fatalf("Failed to start test backend: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	var acceptWg sync.WaitGroup
	acceptWg.Add(1)
	go func() {
		defer acceptWg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}
			// Send POP3 greeting
			fmt.Fprint(conn, "+OK Test backend ready\r\n")
			conn.Close()
		}
	}()

	// Simulate each user trying to connect
	failedBeforeHealthy := 0
	succeededAfterFailover := 0

	for i, user := range users {
		t.Logf("\n--- User %d: %s ---", i+1, user)

		// Determine route (checks affinity)
		result, err := DetermineRoute(RouteParams{
			Ctx:                   context.Background(),
			Username:              user,
			Protocol:              "pop3",
			IsRemoteLookupAccount: false,
			RoutingInfo:           nil,
			ConnManager:           connMgr,
			EnableAffinity:        true,
			ProxyName:             "Test Proxy",
		})
		if err != nil {
			t.Fatalf("DetermineRoute failed: %v", err)
		}

		t.Logf("Routing: method=%s, preferred=%s", result.RoutingMethod, result.PreferredAddr)

		// Try to actually connect (simulates what the proxy does)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, actualAddr, err := connMgr.ConnectWithProxy(
			ctx,
			result.PreferredAddr,
			"127.0.0.1", 50000, "127.0.0.1", 110,
			result.RoutingInfo,
		)
		cancel()

		if err != nil {
			t.Logf("Connection FAILED: %v (preferred: %s)", err, result.PreferredAddr)
			if result.PreferredAddr == downBackend || actualAddr == downBackend {
				failedBeforeHealthy++
			}
		} else {
			t.Logf("Connection SUCCESS: connected to %s", actualAddr)
			conn.Close()
			if actualAddr == upBackend {
				succeededAfterFailover++
			}
		}

		// Check backend health status
		downHealth := connMgr.IsBackendHealthy(downBackend)
		upHealth := connMgr.IsBackendHealthy(upBackend)
		t.Logf("Health status: down=%v, up=%v", downHealth, upHealth)

		// Check if affinity still exists
		currentAffinity, found := affinity.GetBackend(user, "pop3")
		if found {
			t.Logf("Affinity exists: %s", currentAffinity)
		} else {
			t.Logf("Affinity deleted")
		}
	}

	listener.Close()
	acceptWg.Wait()

	t.Logf("\n=== RESULTS ===")
	t.Logf("Failed before backend marked unhealthy: %d users", failedBeforeHealthy)
	t.Logf("Succeeded after failover: %d users", succeededAfterFailover)

	// The problem: First 3 users will fail trying to connect to the down backend
	// because it takes 3 consecutive failures to mark it unhealthy
	if failedBeforeHealthy >= 1 {
		t.Logf("⚠️  ISSUE REPRODUCED: %d users sent to down backend before it was marked unhealthy", failedBeforeHealthy)
		t.Logf("This is the production issue - users get errors until 3 failures accumulate")
	}

	// By user 4 or 5, the backend should be marked unhealthy and they should succeed
	if succeededAfterFailover >= 1 {
		t.Logf("✅ Failover worked for %d users after backend marked unhealthy", succeededAfterFailover)
	} else {
		t.Error("❌ FAIL: No users successfully failed over to healthy backend")
	}
}

// TestAffinityAutoRecoveryLoop tests the 1-minute auto-recovery causing users to cycle back
func TestAffinityAutoRecoveryLoop(t *testing.T) {
	t.Skip("Skipping: requires 1-minute wait for auto-recovery (too slow for regular tests)")

	cluster1, err := createTestCluster("node-recovery-test", 29946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	affinity := server.NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	backends := []string{"127.0.0.1:19243", "127.0.0.1:19244"}
	connMgr, err := NewConnectionManager(backends, 143, false, false, false, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}
	connMgr.SetAffinityManager(affinity)

	downBackend := "127.0.0.1:19243"
	user := "test@example.com"

	// Set affinity to down backend
	affinity.SetBackend(user, downBackend, "imap")

	// Mark backend unhealthy (3 failures)
	for i := 0; i < 3; i++ {
		connMgr.RecordConnectionFailure(downBackend)
	}

	if connMgr.IsBackendHealthy(downBackend) {
		t.Fatal("Backend should be unhealthy after 3 failures")
	}

	t.Logf("Backend marked unhealthy at: %v", time.Now())

	// Wait for 1-minute auto-recovery
	t.Logf("Waiting 61 seconds for auto-recovery...")
	time.Sleep(61 * time.Second)

	// After 1 minute, IsBackendHealthy should return true (auto-recovery)
	if !connMgr.IsBackendHealthy(downBackend) {
		t.Error("Backend should be auto-recovered after 1 minute")
	}

	t.Logf("Backend auto-recovered at: %v", time.Now())

	// Now route the user - will try the affinity backend again!
	result, err := DetermineRoute(RouteParams{
		Ctx:                   context.Background(),
		Username:              user,
		Protocol:              "imap",
		IsRemoteLookupAccount: false,
		RoutingInfo:           nil,
		ConnManager:           connMgr,
		EnableAffinity:        true,
		ProxyName:             "Test Proxy",
	})
	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	if result.PreferredAddr == downBackend {
		t.Errorf("⚠️  ISSUE: User routed back to down backend after 1-minute auto-recovery")
		t.Error("This causes users to cycle between healthy and down backends")
	}
}
