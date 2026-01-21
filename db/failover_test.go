package db

import (
	"testing"

	"github.com/migadu/sora/config"
)

func TestFailoverManager(t *testing.T) {
	hosts := []string{"host1", "host2", "host3"}
	endpointConfig := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		User:     "test",
		Password: "test",
		Name:     "test",
	}
	fm := NewFailoverManager(endpointConfig, "test")

	// Test that all hosts start healthy
	for _, h := range fm.hosts {
		if !h.IsHealthy.Load() {
			t.Errorf("Host %s should start healthy", h.Host)
		}
	}

	// Test round-robin selection
	seen := make(map[string]bool)
	for i := 0; i < 6; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		seen[host] = true
	}

	// Should have seen all hosts
	if len(seen) != 3 {
		t.Errorf("Expected to see 3 different hosts, saw %d: %v", len(seen), seen)
	}

	// Test marking host unhealthy - requires threshold failures (default: 3)
	fm.MarkHostUnhealthy("host1", nil)
	fm.MarkHostUnhealthy("host1", nil)
	fm.MarkHostUnhealthy("host1", nil)

	// Get next 10 hosts, should not include host1
	for i := 0; i < 10; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		if host == "host1" {
			t.Errorf("Should not return unhealthy host1, got: %s", host)
		}
	}

	// Test marking host healthy again
	fm.MarkHostHealthy("host1")

	// Should be able to get host1 again
	foundHost1 := false
	for i := 0; i < 10; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		if host == "host1" {
			foundHost1 = true
			break
		}
	}

	if !foundHost1 {
		t.Error("Should be able to get host1 after marking it healthy again")
	}
}

func TestFailoverManagerSingleHost(t *testing.T) {
	hosts := []string{"onlyhost"}
	endpointConfig := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		User:     "test",
		Password: "test",
		Name:     "test",
	}
	fm := NewFailoverManager(endpointConfig, "test")

	// Should always return the only host, even if unhealthy
	fm.MarkHostUnhealthy("onlyhost", nil)
	fm.MarkHostUnhealthy("onlyhost", nil)
	fm.MarkHostUnhealthy("onlyhost", nil)

	host, err := fm.GetNextHealthyHost()
	if err != nil {
		t.Fatalf("GetNextHealthyHost failed: %v", err)
	}
	if host != "onlyhost" {
		t.Errorf("Expected onlyhost, got: %s", host)
	}
}

func TestFailoverManagerBackoff(t *testing.T) {
	hosts := []string{"host1", "host2"}
	endpointConfig := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		User:     "test",
		Password: "test",
		Name:     "test",
	}
	fm := NewFailoverManager(endpointConfig, "test")

	// Mark both hosts unhealthy (requires threshold failures)
	for i := 0; i < 3; i++ {
		fm.MarkHostUnhealthy("host1", nil)
		fm.MarkHostUnhealthy("host2", nil)
	}

	// Should still return a host (fallback behavior)
	host, err := fm.GetNextHealthyHost()
	if err != nil {
		t.Fatalf("GetNextHealthyHost failed: %v", err)
	}
	if host == "" {
		t.Error("Should return a host even when all are unhealthy")
	}

	// Check that consecutive failures increment
	for _, h := range fm.hosts {
		if h.Host == "host1" {
			h.mu.RLock()
			fails := h.ConsecutiveFails
			h.mu.RUnlock()
			if fails != 3 {
				t.Errorf("Expected 3 consecutive failures for host1, got: %d", fails)
			}
		}
	}

	// Mark one host healthy and verify it gets selected
	fm.MarkHostHealthy("host1")

	// Should prefer the healthy host
	healthyCount := 0
	for i := 0; i < 10; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		if host == "host1" {
			healthyCount++
		}
	}

	if healthyCount == 0 {
		t.Error("Should select healthy host1 at least once")
	}
}

func TestFailoverThreshold(t *testing.T) {
	hosts := []string{"host1", "host2", "host3"}
	endpointConfig := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		User:     "test",
		Password: "test",
		Name:     "test",
	}
	fm := NewFailoverManager(endpointConfig, "test")

	// Verify threshold is set correctly
	if fm.failureThreshold != 3 {
		t.Errorf("Expected failure threshold of 3, got: %d", fm.failureThreshold)
	}

	// First failure - should remain healthy
	fm.MarkHostUnhealthy("host1", nil)

	host1 := fm.hosts[0]
	if !host1.IsHealthy.Load() {
		t.Error("Host should remain healthy after first failure")
	}
	host1.mu.RLock()
	if host1.ConsecutiveFails != 1 {
		t.Errorf("Expected 1 consecutive failure, got: %d", host1.ConsecutiveFails)
	}
	host1.mu.RUnlock()

	// Second failure - should still remain healthy
	fm.MarkHostUnhealthy("host1", nil)

	if !host1.IsHealthy.Load() {
		t.Error("Host should remain healthy after second failure")
	}
	host1.mu.RLock()
	if host1.ConsecutiveFails != 2 {
		t.Errorf("Expected 2 consecutive failures, got: %d", host1.ConsecutiveFails)
	}
	host1.mu.RUnlock()

	// Host should still be returned in rotation
	foundHost1 := false
	for i := 0; i < 10; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		if host == "host1" {
			foundHost1 = true
			break
		}
	}
	if !foundHost1 {
		t.Error("Host1 should still be returned before reaching threshold")
	}

	// Third failure - should now be marked unhealthy
	fm.MarkHostUnhealthy("host1", nil)

	if host1.IsHealthy.Load() {
		t.Error("Host should be marked unhealthy after third failure")
	}
	host1.mu.RLock()
	if host1.ConsecutiveFails != 3 {
		t.Errorf("Expected 3 consecutive failures, got: %d", host1.ConsecutiveFails)
	}
	host1.mu.RUnlock()

	// Host should NOT be returned anymore (within backoff period)
	for i := 0; i < 20; i++ {
		host, err := fm.GetNextHealthyHost()
		if err != nil {
			t.Fatalf("GetNextHealthyHost failed: %v", err)
		}
		if host == "host1" {
			t.Error("Host1 should not be returned after reaching failure threshold")
		}
	}

	// Marking healthy should reset the counter
	fm.MarkHostHealthy("host1")

	if !host1.IsHealthy.Load() {
		t.Error("Host should be healthy after marking it healthy")
	}
	host1.mu.RLock()
	if host1.ConsecutiveFails != 0 {
		t.Errorf("Expected 0 consecutive failures after marking healthy, got: %d", host1.ConsecutiveFails)
	}
	host1.mu.RUnlock()
}

func TestHostHealthStats(t *testing.T) {
	hosts := []string{"host1", "host2"}
	endpointConfig := &config.DatabaseEndpointConfig{
		Hosts:    hosts,
		User:     "test",
		Password: "test",
		Name:     "test",
	}
	fm := NewFailoverManager(endpointConfig, "test")

	// Get initial stats
	stats := fm.GetHostStats()
	if len(stats) != 2 {
		t.Errorf("Expected 2 host stats, got: %d", len(stats))
	}

	// Check initial health
	for _, stat := range stats {
		if !stat["healthy"].(bool) {
			t.Errorf("Host %s should start healthy", stat["host"].(string))
		}
		if stat["consecutive_fails"].(int64) != 0 {
			t.Errorf("Host %s should start with 0 failures", stat["host"].(string))
		}
	}

	// Mark one host unhealthy (requires threshold failures)
	for i := 0; i < 3; i++ {
		fm.MarkHostUnhealthy("host1", nil)
	}

	// Check updated stats
	stats = fm.GetHostStats()
	for _, stat := range stats {
		if stat["host"].(string) == "host1" {
			if stat["healthy"].(bool) {
				t.Error("Host1 should be marked unhealthy")
			}
			if stat["consecutive_fails"].(int64) != 3 {
				t.Errorf("Host1 should have 3 failures, got: %d", stat["consecutive_fails"].(int64))
			}
		}
	}
}
