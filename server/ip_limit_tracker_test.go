package server

import (
	"testing"
)

// TestIPLimitTrackerNegativeCount tests that decrementing a non-existent or
// zero-count IP doesn't result in negative counts.
func TestIPLimitTrackerNegativeCount(t *testing.T) {
	// Create tracker in local mode (no cluster)
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	// Test 1: Decrement non-existent IP should not create negative count
	tracker.DecrementIP("192.0.2.1")
	count := tracker.GetIPCount("192.0.2.1")
	if count < 0 {
		t.Errorf("Decrementing non-existent IP resulted in negative count: %d", count)
	}
	if count != 0 {
		t.Errorf("Expected count=0 for non-existent IP, got %d", count)
	}

	// Test 2: Decrement IP that exists but has LocalCount=0
	// This simulates receiving a remote decrement for an IP we don't own
	tracker.mu.Lock()
	tracker.connections["192.0.2.2"] = &IPConnectionInfo{
		IP:             "192.0.2.2",
		TotalCount:     5, // Remote instances have connections
		LocalCount:     0, // But we don't
		LocalInstances: map[string]int{"other-instance": 5},
	}
	tracker.mu.Unlock()

	// Decrementing should not go negative
	tracker.DecrementIP("192.0.2.2")
	count = tracker.GetIPCount("192.0.2.2")
	if count < 0 {
		t.Errorf("Decrementing IP with LocalCount=0 resulted in negative count: %d", count)
	}
	// Should still be 4 or 5 depending on whether we decremented TotalCount
	// Current buggy behavior: decrements TotalCount even if LocalCount=0
	// After fix: should remain 5
	t.Logf("Count after decrement with LocalCount=0: %d (expected: 5)", count)

	// Test 3: Multiple decrements beyond actual count
	tracker.IncrementIP("192.0.2.3")
	tracker.IncrementIP("192.0.2.3")
	// Now count = 2

	// Decrement 5 times (more than actual)
	for i := 0; i < 5; i++ {
		tracker.DecrementIP("192.0.2.3")
	}

	count = tracker.GetIPCount("192.0.2.3")
	if count < 0 {
		t.Errorf("Multiple decrements resulted in negative count: %d", count)
	}
	if count != 0 {
		t.Errorf("Expected count=0 after excessive decrements, got %d", count)
	}
}

// TestIPLimitTrackerConcurrentIncrementDecrement tests concurrent operations
// to ensure counts remain non-negative under race conditions.
func TestIPLimitTrackerConcurrentIncrementDecrement(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	const goroutines = 10
	const operations = 100

	// Run concurrent increment/decrement operations
	done := make(chan bool)
	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < operations; i++ {
				tracker.IncrementIP("192.0.2.1")
				tracker.DecrementIP("192.0.2.1")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for g := 0; g < goroutines; g++ {
		<-done
	}

	// Final count should be 0, not negative
	count := tracker.GetIPCount("192.0.2.1")
	if count < 0 {
		t.Errorf("Concurrent operations resulted in negative count: %d", count)
	}
	if count != 0 {
		t.Errorf("Expected count=0 after balanced inc/dec, got %d", count)
	}
}

// TestIPLimitTrackerLocalCountConsistency tests that LocalCount and TotalCount
// remain consistent.
func TestIPLimitTrackerLocalCountConsistency(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	// Increment 10 times
	for i := 0; i < 10; i++ {
		tracker.IncrementIP("192.0.2.1")
	}

	// Check consistency
	tracker.mu.RLock()
	info := tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if info == nil {
		t.Fatal("IP info not found")
	}

	if info.LocalCount != 10 {
		t.Errorf("Expected LocalCount=10, got %d", info.LocalCount)
	}
	if info.TotalCount != 10 {
		t.Errorf("Expected TotalCount=10, got %d", info.TotalCount)
	}
	if info.LocalInstances["instance-1"] != 10 {
		t.Errorf("Expected LocalInstances[instance-1]=10, got %d", info.LocalInstances["instance-1"])
	}

	// Decrement 5 times
	for i := 0; i < 5; i++ {
		tracker.DecrementIP("192.0.2.1")
	}

	// Check consistency again
	tracker.mu.RLock()
	info = tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if info.LocalCount != 5 {
		t.Errorf("Expected LocalCount=5, got %d", info.LocalCount)
	}
	if info.TotalCount != 5 {
		t.Errorf("Expected TotalCount=5, got %d", info.TotalCount)
	}
	if info.LocalInstances["instance-1"] != 5 {
		t.Errorf("Expected LocalInstances[instance-1]=5, got %d", info.LocalInstances["instance-1"])
	}

	// All three should match
	if info.LocalCount != info.TotalCount || info.LocalCount != info.LocalInstances["instance-1"] {
		t.Errorf("Counts not consistent: LocalCount=%d, TotalCount=%d, LocalInstances[instance-1]=%d",
			info.LocalCount, info.TotalCount, info.LocalInstances["instance-1"])
	}
}

// TestIPLimitTrackerCleanupAfterZero tests that IP entries are cleaned up
// when count reaches zero.
func TestIPLimitTrackerCleanupAfterZero(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	// Increment then decrement
	tracker.IncrementIP("192.0.2.1")
	tracker.DecrementIP("192.0.2.1")

	// IP should be cleaned up
	tracker.mu.RLock()
	_, exists := tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if exists {
		t.Error("IP entry should be cleaned up after count reaches zero")
	}

	// Count should be 0
	count := tracker.GetIPCount("192.0.2.1")
	if count != 0 {
		t.Errorf("Expected count=0 for cleaned up IP, got %d", count)
	}
}

// TestIPLimitTrackerStaleInstanceCleanup tests that stale instance IDs are
// cleaned up by the cleanup routine.
func TestIPLimitTrackerStaleInstanceCleanup(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	// Add an IP with zero-count instances (simulating old instances that disconnected)
	tracker.mu.Lock()
	tracker.connections["192.0.2.1"] = &IPConnectionInfo{
		IP:         "192.0.2.1",
		TotalCount: 0,
		LocalCount: 0,
		LocalInstances: map[string]int{
			"old-instance-1": 0,
			"old-instance-2": 0,
			"old-instance-3": 0,
		},
	}
	tracker.mu.Unlock()

	// Run cleanup
	tracker.performCleanup()

	// IP should be completely removed (TotalCount=0 and all instances have count=0)
	tracker.mu.RLock()
	info, exists := tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if exists {
		t.Errorf("IP with TotalCount=0 and all zero-count instances should be removed, but exists with %d instances",
			len(info.LocalInstances))
	}
}

// TestIPLimitTrackerStaleInstancesWithActiveConnections tests that zero-count
// instance IDs are removed while keeping active instances.
func TestIPLimitTrackerStaleInstancesWithActiveConnections(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "current-instance", nil, 1000)

	// Add an IP with mix of active and stale instances
	tracker.mu.Lock()
	tracker.connections["192.0.2.1"] = &IPConnectionInfo{
		IP:         "192.0.2.1",
		TotalCount: 5, // Total from active instances
		LocalCount: 5,
		LocalInstances: map[string]int{
			"current-instance": 5, // Active - should be kept
			"old-instance-1":   0, // Stale - should be removed
			"old-instance-2":   0, // Stale - should be removed
			"old-instance-3":   0, // Stale - should be removed
		},
	}
	tracker.mu.Unlock()

	// Before cleanup: 4 instances
	tracker.mu.RLock()
	beforeCount := len(tracker.connections["192.0.2.1"].LocalInstances)
	tracker.mu.RUnlock()
	if beforeCount != 4 {
		t.Errorf("Expected 4 instances before cleanup, got %d", beforeCount)
	}

	// Run cleanup
	tracker.performCleanup()

	// After cleanup: should have only 1 instance (current-instance with count=5)
	tracker.mu.RLock()
	info, exists := tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if !exists {
		t.Fatal("IP should still exist (has active connections)")
	}

	if info.TotalCount != 5 {
		t.Errorf("Expected TotalCount=5, got %d", info.TotalCount)
	}

	afterCount := len(info.LocalInstances)
	if afterCount != 1 {
		t.Errorf("Expected 1 instance after cleanup (current-instance), got %d instances", afterCount)
	}

	if count, ok := info.LocalInstances["current-instance"]; !ok || count != 5 {
		t.Errorf("Expected current-instance with count=5, got %v", info.LocalInstances)
	}

	// Verify stale instances were removed
	for _, staleID := range []string{"old-instance-1", "old-instance-2", "old-instance-3"} {
		if _, exists := info.LocalInstances[staleID]; exists {
			t.Errorf("Stale instance %s should have been removed", staleID)
		}
	}
}

// TestIPLimitTrackerMemoryGrowth tests that tracker doesn't leak memory with
// frequent instance restarts.
func TestIPLimitTrackerMemoryGrowth(t *testing.T) {
	tracker := NewIPLimitTracker("TEST", "instance-1", nil, 1000)

	// Simulate 1000 instance restarts, each with connections that get closed
	for i := 0; i < 1000; i++ {
		instanceID := "instance-" + string(rune(i))

		tracker.mu.Lock()
		info, exists := tracker.connections["192.0.2.1"]
		if !exists {
			info = &IPConnectionInfo{
				IP:             "192.0.2.1",
				TotalCount:     0,
				LocalCount:     0,
				LocalInstances: make(map[string]int),
			}
			tracker.connections["192.0.2.1"] = info
		}
		// Add connections for this instance
		info.LocalInstances[instanceID] = 5
		info.TotalCount += 5
		tracker.mu.Unlock()

		// Simulate instance shutdown - set count to 0
		tracker.mu.Lock()
		info.LocalInstances[instanceID] = 0
		info.TotalCount -= 5
		tracker.mu.Unlock()
	}

	// Before cleanup: should have 1000 instance IDs (all with count=0)
	tracker.mu.RLock()
	beforeCount := len(tracker.connections["192.0.2.1"].LocalInstances)
	tracker.mu.RUnlock()

	t.Logf("Instance IDs before cleanup: %d", beforeCount)
	if beforeCount != 1000 {
		t.Errorf("Expected 1000 instance IDs before cleanup, got %d", beforeCount)
	}

	// Run cleanup
	tracker.performCleanup()

	// After cleanup: IP entry should be completely removed (TotalCount=0 and no instances)
	tracker.mu.RLock()
	info, exists := tracker.connections["192.0.2.1"]
	tracker.mu.RUnlock()

	if exists {
		// If it still exists, check instance count
		afterCount := len(info.LocalInstances)
		totalCount := info.TotalCount

		t.Logf("IP still exists after cleanup! Instance IDs: %d, TotalCount: %d", afterCount, totalCount)

		if afterCount != 0 {
			t.Errorf("Expected 0 instance IDs after cleanup (all zero-count), got %d - MEMORY LEAK!", afterCount)
		}

		if totalCount != 0 {
			t.Errorf("Expected TotalCount=0, got %d", totalCount)
		}

		t.Error("IP entry should be completely removed (TotalCount=0 and no instances)")
	} else {
		t.Log("✓ IP entry was completely removed after cleanup (no memory leak)")
	}
}
