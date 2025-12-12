package server

import (
	"context"
	"testing"
	"time"
)

// TestConnectionTracker_PerIPCountByInstanceCleanup tests that empty instance maps are removed during cleanup
func TestConnectionTracker_PerIPCountByInstanceCleanup(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0, false)
	defer tracker.Stop()

	// Simulate a user connecting and disconnecting from multiple instances via gossip
	accountID := int64(12345)
	username := "test@example.com"

	// Register connections from 3 different instances (via gossip events)
	tracker.mu.Lock()
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:            accountID,
		Username:             username,
		LastUpdate:           time.Now(),
		FirstSeen:            time.Now(),
		PerIPCountByInstance: make(map[string]map[string]int),
	}
	info := tracker.connections[accountID]
	// Each instance has 2 connections from different IPs
	info.PerIPCountByInstance["instance-1"] = map[string]int{"192.168.1.1": 1, "192.168.1.2": 1}
	info.PerIPCountByInstance["instance-2"] = map[string]int{"192.168.1.3": 1, "192.168.1.4": 1}
	info.PerIPCountByInstance["instance-3"] = map[string]int{"192.168.1.5": 1, "192.168.1.6": 1}
	tracker.mu.Unlock()

	// Verify we have 3 instances
	tracker.mu.RLock()
	initialInstances := len(info.PerIPCountByInstance)
	tracker.mu.RUnlock()
	if initialInstances != 3 {
		t.Fatalf("Expected 3 instances, got %d", initialInstances)
	}

	// Simulate disconnections - clear IP maps (via gossip state snapshots)
	tracker.mu.Lock()
	info.PerIPCountByInstance["instance-1"] = make(map[string]int) // Empty map
	info.PerIPCountByInstance["instance-2"] = make(map[string]int) // Empty map
	// instance-3 still has connections
	tracker.mu.Unlock()

	// Run cleanup
	tracker.cleanup()

	// Verify empty instance maps were removed
	tracker.mu.RLock()
	remainingInstances := len(info.PerIPCountByInstance)
	_, inst1Exists := info.PerIPCountByInstance["instance-1"]
	_, inst2Exists := info.PerIPCountByInstance["instance-2"]
	_, inst3Exists := info.PerIPCountByInstance["instance-3"]
	tracker.mu.RUnlock()

	if remainingInstances != 1 {
		t.Errorf("Expected 1 instance after cleanup, got %d", remainingInstances)
	}
	if inst1Exists {
		t.Errorf("instance-1 should have been removed (empty map)")
	}
	if inst2Exists {
		t.Errorf("instance-2 should have been removed (empty map)")
	}
	if !inst3Exists {
		t.Errorf("instance-3 should still exist (has connections)")
	}
}

// TestConnectionTracker_PerIPCountCleanup tests that zero-count PerIPCount entries are removed during cleanup
func TestConnectionTracker_PerIPCountCleanup(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 5, 0, false)
	defer tracker.Stop()

	ctx := context.Background()

	// Register connections from user at 3 different IPs
	accountID := int64(67890)
	username := "multiip@example.com"

	// First IP - register 2 connections
	err := tracker.RegisterConnection(ctx, accountID, username, "test", "192.168.1.1:1234")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}
	err = tracker.RegisterConnection(ctx, accountID, username, "test", "192.168.1.1:1235")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Second IP - register 2 connections
	err = tracker.RegisterConnection(ctx, accountID, username, "test", "192.168.1.2:1234")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}
	err = tracker.RegisterConnection(ctx, accountID, username, "test", "192.168.1.2:1235")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Third IP - register 1 connection
	err = tracker.RegisterConnection(ctx, accountID, username, "test", "192.168.1.3:1234")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Verify we have 3 IPs tracked
	tracker.mu.RLock()
	info := tracker.connections[accountID]
	initialIPs := 0
	if perIPMap := info.PerIPCountByInstance[tracker.instanceID]; perIPMap != nil {
		initialIPs = len(perIPMap)
	}
	tracker.mu.RUnlock()
	if initialIPs != 3 {
		t.Fatalf("Expected 3 IPs tracked, got %d", initialIPs)
	}

	// Disconnect all from first two IPs
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.1:1234")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.1:1235")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.2:1234")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.2:1235")

	// At this point, PerIPCountByInstance should have counts: IP1=0, IP2=0, IP3=1
	tracker.mu.RLock()
	var ip1Count, ip2Count, ip3Count int
	if perIPMap := info.PerIPCountByInstance[tracker.instanceID]; perIPMap != nil {
		ip1Count = perIPMap["192.168.1.1"]
		ip2Count = perIPMap["192.168.1.2"]
		ip3Count = perIPMap["192.168.1.3"]
	}
	tracker.mu.RUnlock()

	if ip1Count != 0 {
		t.Errorf("IP1 count should be 0, got %d", ip1Count)
	}
	if ip2Count != 0 {
		t.Errorf("IP2 count should be 0, got %d", ip2Count)
	}
	if ip3Count != 1 {
		t.Errorf("IP3 count should be 1, got %d", ip3Count)
	}

	// Run cleanup
	tracker.cleanup()

	// Verify zero-count IPs were removed
	tracker.mu.RLock()
	var remainingIPs int
	var ip1Exists, ip2Exists, ip3Exists bool
	var finalIP3Count int
	if perIPMap := info.PerIPCountByInstance[tracker.instanceID]; perIPMap != nil {
		remainingIPs = len(perIPMap)
		_, ip1Exists = perIPMap["192.168.1.1"]
		_, ip2Exists = perIPMap["192.168.1.2"]
		_, ip3Exists = perIPMap["192.168.1.3"]
		finalIP3Count = perIPMap["192.168.1.3"]
	}
	tracker.mu.RUnlock()

	if remainingIPs != 1 {
		t.Errorf("Expected 1 IP after cleanup, got %d", remainingIPs)
	}
	if ip1Exists {
		t.Errorf("192.168.1.1 should have been removed (count was 0)")
	}
	if ip2Exists {
		t.Errorf("192.168.1.2 should have been removed (count was 0)")
	}
	if !ip3Exists {
		t.Errorf("192.168.1.3 should still exist (count > 0)")
	}
	if finalIP3Count != 1 {
		t.Errorf("192.168.1.3 count should still be 1, got %d", finalIP3Count)
	}
}

// TestConnectionTracker_CleanupPreventsBoundlessGrowth tests that cleanup prevents memory leaks over time
func TestConnectionTracker_CleanupPreventsBoundlessGrowth(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 3, 0, false)
	defer tracker.Stop()

	// Simulate user connecting from many instances over time
	accountID := int64(99999)
	username := "longterm@example.com"

	// Register user from 20 different instances (simulating cluster turnover over weeks)
	tracker.mu.Lock()
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:            accountID,
		Username:             username,
		LastUpdate:           time.Now(),
		FirstSeen:            time.Now(),
		PerIPCountByInstance: make(map[string]map[string]int),
	}
	info := tracker.connections[accountID]
	for i := 1; i <= 20; i++ {
		instanceID := string(rune('a' + i))
		// Most instances have disconnected (empty maps), only 2 are still active
		if i <= 2 {
			info.PerIPCountByInstance[instanceID] = map[string]int{"192.168.1.1": 1} // Active instances
		} else {
			info.PerIPCountByInstance[instanceID] = make(map[string]int) // Empty maps (disconnected)
		}
	}
	tracker.mu.Unlock()

	// Verify we start with 20 instance entries
	tracker.mu.RLock()
	initialSize := len(info.PerIPCountByInstance)
	tracker.mu.RUnlock()
	if initialSize != 20 {
		t.Fatalf("Expected 20 instances initially, got %d", initialSize)
	}

	// Run cleanup
	tracker.cleanup()

	// Verify we cleaned up to only active instances
	tracker.mu.RLock()
	finalSize := len(info.PerIPCountByInstance)
	tracker.mu.RUnlock()

	if finalSize != 2 {
		t.Errorf("Expected 2 instances after cleanup (only active ones), got %d", finalSize)
	}

	// Calculate memory saved: 18 empty instance maps × ~20 bytes = ~360 bytes per user
	// With 30k users, that's ~11MB saved
	savedEntries := initialSize - finalSize
	if savedEntries != 18 {
		t.Errorf("Expected to clean 18 empty instance maps, cleaned %d", savedEntries)
	}
}

// TestConnectionTracker_CleanupHandlesEmptyMaps tests cleanup doesn't crash on empty/nil maps
func TestConnectionTracker_CleanupHandlesEmptyMaps(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0, false)
	defer tracker.Stop()

	// Add user with empty maps
	tracker.mu.Lock()
	tracker.connections[123] = &UserConnectionInfo{
		AccountID:            123,
		Username:             "test@example.com",
		FirstSeen:            time.Now().Add(-20 * time.Minute),
		LastUpdate:           time.Now().Add(-20 * time.Minute), // Stale
		PerIPCountByInstance: make(map[string]map[string]int),   // empty map
	}
	tracker.mu.Unlock()

	// Should not panic
	tracker.cleanup()

	// User should be removed (stale + zero count)
	tracker.mu.RLock()
	_, exists := tracker.connections[123]
	tracker.mu.RUnlock()

	if exists {
		t.Errorf("Stale user with zero connections should have been removed")
	}
}

// TestConnectionTracker_CleanupFrequency tests that cleanup runs periodically
func TestConnectionTracker_CleanupFrequency(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0, false)
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(555)

	// Register and immediately unregister (creates zero-count entry)
	tracker.RegisterConnection(ctx, accountID, "test@example.com", "test", "1.2.3.4:1234")
	tracker.UnregisterConnection(ctx, accountID, "test", "1.2.3.4:1234")

	// Mark as stale
	tracker.mu.Lock()
	if info, exists := tracker.connections[accountID]; exists {
		info.LastUpdate = time.Now().Add(-20 * time.Minute)
	}
	tracker.mu.Unlock()

	// Wait for cleanup cycle (runs every 5 minutes, but we can trigger manually)
	tracker.cleanup()

	// Verify cleanup happened
	tracker.mu.RLock()
	_, exists := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if exists {
		t.Errorf("Cleanup should have removed stale zero-count user")
	}
}
