package proxy

import (
	"context"
	"testing"
	"time"
)

// TestConnectionManager_ConsistentHashInitialization verifies consistent hash ring is initialized
func TestConnectionManager_ConsistentHashInitialization(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	if cm.consistentHash == nil {
		t.Fatal("Consistent hash should be initialized")
	}

	if cm.consistentHash.Size() != len(backends) {
		t.Errorf("Expected %d backends in ring, got %d", len(backends), cm.consistentHash.Size())
	}
}

// TestConnectionManager_GetBackendByConsistentHash verifies deterministic backend selection
func TestConnectionManager_GetBackendByConsistentHash(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	testCases := []struct {
		username string
	}{
		{"user1@example.com"},
		{"user2@example.com"},
		{"admin@test.com"},
		{"me@dejanstrbac.com"},
	}

	for _, tc := range testCases {
		backend1 := cm.GetBackendByConsistentHash(tc.username)
		if backend1 == "" {
			t.Errorf("Expected backend for %s, got empty", tc.username)
			continue
		}

		// Call multiple times - should get same result
		for i := 0; i < 5; i++ {
			backend := cm.GetBackendByConsistentHash(tc.username)
			if backend != backend1 {
				t.Errorf("Inconsistent result for %s: expected %s, got %s on iteration %d",
					tc.username, backend1, backend, i)
			}
		}

		t.Logf("User %s consistently maps to %s", tc.username, backend1)
	}
}

// TestConnectionManager_ConsistentHashWithUnhealthyBackends verifies failover behavior
func TestConnectionManager_ConsistentHashWithUnhealthyBackends(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	username := "test@example.com"

	// Get initial backend
	primaryBackend := cm.GetBackendByConsistentHash(username)
	if primaryBackend == "" {
		t.Fatal("Expected primary backend, got empty")
	}
	t.Logf("Primary backend for %s: %s", username, primaryBackend)

	// Mark primary as unhealthy
	cm.RecordConnectionFailure(primaryBackend)
	cm.RecordConnectionFailure(primaryBackend)
	cm.RecordConnectionFailure(primaryBackend) // 3 failures should mark unhealthy

	// Should get different backend
	failoverBackend := cm.GetBackendByConsistentHash(username)
	if failoverBackend == "" {
		t.Fatal("Expected failover backend, got empty")
	}

	if failoverBackend == primaryBackend {
		t.Errorf("Failover backend should be different from unhealthy primary: %s", primaryBackend)
	}

	t.Logf("Failover backend for %s: %s", username, failoverBackend)

	// Mark failover as unhealthy too
	cm.RecordConnectionFailure(failoverBackend)
	cm.RecordConnectionFailure(failoverBackend)
	cm.RecordConnectionFailure(failoverBackend)

	// Should get third backend
	secondaryFailover := cm.GetBackendByConsistentHash(username)
	if secondaryFailover == "" {
		t.Fatal("Expected secondary failover backend, got empty")
	}

	if secondaryFailover == primaryBackend || secondaryFailover == failoverBackend {
		t.Errorf("Secondary failover should be different from previous backends")
	}

	t.Logf("Secondary failover backend for %s: %s", username, secondaryFailover)
}

// TestConnectionManager_ConsistentHashAllBackendsUnhealthy verifies behavior when all backends fail
func TestConnectionManager_ConsistentHashAllBackendsUnhealthy(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	username := "test@example.com"

	// Mark all backends as unhealthy
	for _, backend := range backends {
		for i := 0; i < 3; i++ {
			cm.RecordConnectionFailure(backend)
		}
	}

	// Should return empty string when all unhealthy
	backend := cm.GetBackendByConsistentHash(username)
	if backend != "" {
		t.Errorf("Expected empty string when all backends unhealthy, got %s", backend)
	}
}

// TestDetermineRoute_ConsistentHashPrecedence verifies routing precedence
func TestDetermineRoute_ConsistentHashPrecedence(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	// Create mock affinity manager
	mockAffinity := &MockAffinityManager{
		backends: make(map[string]string),
	}
	cm.SetAffinityManager(mockAffinity)

	username := "test@example.com"
	ctx := context.Background()

	// Test 1: No affinity, no remotelookup → should use consistent hash
	result, err := DetermineRoute(RouteParams{
		Ctx:            ctx,
		Username:       username,
		Protocol:       "imap",
		ConnManager:    cm,
		EnableAffinity: true,
		ProxyName:      "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	if result.RoutingMethod != "consistent_hash" {
		t.Errorf("Expected consistent_hash routing method, got %s", result.RoutingMethod)
	}

	if result.PreferredAddr == "" {
		t.Error("Expected preferred address from consistent hash, got empty")
	}

	consistentHashBackend := result.PreferredAddr
	t.Logf("Consistent hash selected: %s", consistentHashBackend)

	// Test 2: With affinity → should use affinity
	affinityBackend := "backend2:143"
	mockAffinity.SetBackend(username, affinityBackend, "imap")

	result, err = DetermineRoute(RouteParams{
		Ctx:            ctx,
		Username:       username,
		Protocol:       "imap",
		ConnManager:    cm,
		EnableAffinity: true,
		ProxyName:      "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	if result.RoutingMethod != "affinity" {
		t.Errorf("Expected affinity routing method, got %s", result.RoutingMethod)
	}

	if result.PreferredAddr != affinityBackend {
		t.Errorf("Expected affinity backend %s, got %s", affinityBackend, result.PreferredAddr)
	}

	t.Logf("Affinity selected: %s", affinityBackend)

	// Test 3: With remotelookup → should use remotelookup (highest priority)
	remotelookupBackend := "backend3:143"
	routingInfo := &UserRoutingInfo{
		ServerAddress:         remotelookupBackend,
		IsRemoteLookupAccount: true,
	}

	result, err = DetermineRoute(RouteParams{
		Ctx:            ctx,
		Username:       username,
		Protocol:       "imap",
		ConnManager:    cm,
		EnableAffinity: true,
		RoutingInfo:    routingInfo,
		ProxyName:      "Test Proxy",
	})

	if err != nil {
		t.Fatalf("DetermineRoute failed: %v", err)
	}

	if result.RoutingMethod != "remotelookup" {
		t.Errorf("Expected remotelookup routing method, got %s", result.RoutingMethod)
	}

	if result.PreferredAddr != remotelookupBackend {
		t.Errorf("Expected remotelookup backend %s, got %s", remotelookupBackend, result.PreferredAddr)
	}

	t.Logf("RemoteLookup selected: %s", remotelookupBackend)
}

// TestUpdateAffinityAfterConnection_ConsistentHashScenarios tests affinity update logic
func TestUpdateAffinityAfterConnection_ConsistentHashScenarios(t *testing.T) {
	backends := []string{"backend1:143", "backend2:143", "backend3:143"}
	cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	mockAffinity := &MockAffinityManager{
		backends: make(map[string]string),
	}
	cm.SetAffinityManager(mockAffinity)

	username := "test@example.com"
	consistentHashBackend := cm.GetBackendByConsistentHash(username)

	// Scenario 1: User connects to consistent hash backend → no affinity set
	t.Run("NoAffinityOnConsistentHashBackend", func(t *testing.T) {
		mockAffinity.backends = make(map[string]string) // Clear

		UpdateAffinityAfterConnection(RouteParams{
			Username:       username,
			Protocol:       "imap",
			ConnManager:    cm,
			EnableAffinity: true,
			ProxyName:      "Test Proxy",
		}, consistentHashBackend, false)

		// Should NOT set affinity
		_, hasAffinity := mockAffinity.GetBackend(username, "imap")
		if hasAffinity {
			t.Error("Should not set affinity when user on consistent hash backend")
		}
		t.Log("✓ No affinity set for consistent hash placement")
	})

	// Scenario 2: User connects to different backend (failover) → set affinity
	t.Run("SetAffinityOnFailover", func(t *testing.T) {
		mockAffinity.backends = make(map[string]string) // Clear

		failoverBackend := "backend2:143"
		if failoverBackend == consistentHashBackend {
			failoverBackend = "backend3:143"
		}

		UpdateAffinityAfterConnection(RouteParams{
			Username:       username,
			Protocol:       "imap",
			ConnManager:    cm,
			EnableAffinity: true,
			ProxyName:      "Test Proxy",
		}, failoverBackend, false)

		// Should set affinity
		affinityBackend, hasAffinity := mockAffinity.GetBackend(username, "imap")
		if !hasAffinity {
			t.Error("Should set affinity when user on failover backend")
		}
		if affinityBackend != failoverBackend {
			t.Errorf("Expected affinity to %s, got %s", failoverBackend, affinityBackend)
		}
		t.Logf("✓ Affinity set for failover: %s", failoverBackend)
	})

	// Scenario 3: User with affinity reconnects to consistent hash backend → clear affinity
	t.Run("ClearAffinityOnRecovery", func(t *testing.T) {
		// Set affinity to failover backend
		failoverBackend := "backend2:143"
		if failoverBackend == consistentHashBackend {
			failoverBackend = "backend3:143"
		}
		mockAffinity.SetBackend(username, failoverBackend, "imap")

		// User reconnects to consistent hash backend
		UpdateAffinityAfterConnection(RouteParams{
			Username:       username,
			Protocol:       "imap",
			ConnManager:    cm,
			EnableAffinity: true,
			ProxyName:      "Test Proxy",
		}, consistentHashBackend, false)

		// Should clear affinity
		_, hasAffinity := mockAffinity.GetBackend(username, "imap")
		if hasAffinity {
			t.Error("Should clear affinity when user back on consistent hash backend")
		}
		t.Log("✓ Affinity cleared on recovery to consistent hash backend")
	})

	// Scenario 4: User with affinity has another failover → update affinity
	t.Run("UpdateAffinityOnSecondFailover", func(t *testing.T) {
		// Set affinity to first failover
		firstFailover := "backend2:143"
		mockAffinity.SetBackend(username, firstFailover, "imap")

		// User fails over to second backend
		secondFailover := "backend3:143"

		UpdateAffinityAfterConnection(RouteParams{
			Username:       username,
			Protocol:       "imap",
			ConnManager:    cm,
			EnableAffinity: true,
			ProxyName:      "Test Proxy",
		}, secondFailover, true) // wasAffinityRoute=true

		// Should update affinity
		affinityBackend, hasAffinity := mockAffinity.GetBackend(username, "imap")
		if !hasAffinity {
			t.Error("Should maintain affinity after second failover")
		}
		if affinityBackend != secondFailover {
			t.Errorf("Expected affinity updated to %s, got %s", secondFailover, affinityBackend)
		}
		t.Logf("✓ Affinity updated on second failover: %s → %s", firstFailover, secondFailover)
	})
}

// TestMultipleProxies_ConsistentHashAgreement simulates multiple proxies
func TestMultipleProxies_ConsistentHashAgreement(t *testing.T) {
	backends := []string{"10.10.10.31:143", "10.10.10.32:143"}

	// Create two connection managers (simulating two proxies)
	proxy1, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create proxy1: %v", err)
	}

	proxy2, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to create proxy2: %v", err)
	}

	// Test that both proxies agree on placement
	testUsers := []string{
		"me@dejanstrbac.com",
		"user1@example.com",
		"user2@example.com",
		"admin@test.com",
		"support@example.com",
	}

	for _, user := range testUsers {
		backend1 := proxy1.GetBackendByConsistentHash(user)
		backend2 := proxy2.GetBackendByConsistentHash(user)

		if backend1 != backend2 {
			t.Errorf("Proxies disagree on placement for %s: proxy1=%s, proxy2=%s",
				user, backend1, backend2)
		}

		t.Logf("✓ Both proxies agree: %s → %s", user, backend1)
	}
}

// TestConsistentHash_EdgeCases tests edge cases
func TestConsistentHash_EdgeCases(t *testing.T) {
	t.Run("EmptyUsername", func(t *testing.T) {
		backends := []string{"backend1:143", "backend2:143"}
		cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to create connection manager: %v", err)
		}

		backend := cm.GetBackendByConsistentHash("")
		if backend == "" {
			t.Error("Should return a backend even for empty username (for safety)")
		}
	})

	t.Run("SingleBackend", func(t *testing.T) {
		backends := []string{"backend1:143"}
		cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to create connection manager: %v", err)
		}

		username := "test@example.com"
		backend := cm.GetBackendByConsistentHash(username)
		if backend != "backend1:143" {
			t.Errorf("Expected backend1:143, got %s", backend)
		}

		// Should always return same backend
		for i := 0; i < 10; i++ {
			b := cm.GetBackendByConsistentHash(username)
			if b != backend {
				t.Errorf("Inconsistent result with single backend")
			}
		}
	})

	t.Run("VeryLongUsername", func(t *testing.T) {
		backends := []string{"backend1:143", "backend2:143"}
		cm, err := NewConnectionManager(backends, 143, false, false, false, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to create connection manager: %v", err)
		}

		// Very long username (1000 chars)
		longUsername := ""
		for i := 0; i < 100; i++ {
			longUsername += "verylongusername"
		}

		backend := cm.GetBackendByConsistentHash(longUsername)
		if backend == "" {
			t.Error("Should handle very long usernames")
		}

		// Should be consistent
		backend2 := cm.GetBackendByConsistentHash(longUsername)
		if backend != backend2 {
			t.Error("Should be consistent for very long usernames")
		}
	})
}

// MockAffinityManager is a simple mock for testing
type MockAffinityManager struct {
	backends map[string]string // key: "username:protocol" → backend
}

func (m *MockAffinityManager) GetBackend(username, protocol string) (string, bool) {
	key := username + ":" + protocol
	backend, exists := m.backends[key]
	return backend, exists
}

func (m *MockAffinityManager) SetBackend(username, backend, protocol string) {
	key := username + ":" + protocol
	m.backends[key] = backend
}

func (m *MockAffinityManager) UpdateBackend(username, oldBackend, newBackend, protocol string) {
	key := username + ":" + protocol
	m.backends[key] = newBackend
}

func (m *MockAffinityManager) DeleteBackend(username, protocol string) {
	key := username + ":" + protocol
	delete(m.backends, key)
}

func (m *MockAffinityManager) Stop() {}

func (m *MockAffinityManager) GetStats(ctx context.Context) map[string]any {
	return map[string]any{
		"enabled":       true,
		"total_entries": len(m.backends),
	}
}

// Verify MockAffinityManager implements AffinityManager interface
var _ AffinityManager = (*MockAffinityManager)(nil)
