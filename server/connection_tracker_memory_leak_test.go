package server

import (
	"context"
	"testing"
	"time"
)

// TestConnectionTracker_LocalInstancesCleanup tests that zero-count LocalInstances entries are removed during cleanup
func TestConnectionTracker_LocalInstancesCleanup(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0)
	defer tracker.Stop()

	// Simulate a user connecting and disconnecting from multiple instances via gossip
	accountID := int64(12345)
	username := "test@example.com"

	// Register connections from 3 different instances (via gossip events)
	tracker.mu.Lock()
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:      accountID,
		Username:       username,
		TotalCount:     6,
		LocalCount:     0,
		LastUpdate:     time.Now(),
		LocalInstances: make(map[string]int),
		PerIPCount:     make(map[string]int),
	}
	info := tracker.connections[accountID]
	info.LocalInstances["instance-1"] = 2
	info.LocalInstances["instance-2"] = 2
	info.LocalInstances["instance-3"] = 2
	tracker.mu.Unlock()

	// Verify we have 3 instances
	tracker.mu.RLock()
	initialInstances := len(info.LocalInstances)
	tracker.mu.RUnlock()
	if initialInstances != 3 {
		t.Fatalf("Expected 3 instances, got %d", initialInstances)
	}

	// Simulate disconnections - set counts to 0 (via gossip unregister events)
	tracker.mu.Lock()
	info.LocalInstances["instance-1"] = 0
	info.LocalInstances["instance-2"] = 0
	// instance-3 still has connections
	info.TotalCount = 2 // Only instance-3 remains
	tracker.mu.Unlock()

	// Run cleanup
	tracker.cleanup()

	// Verify zero-count instances were removed
	tracker.mu.RLock()
	remainingInstances := len(info.LocalInstances)
	_, inst1Exists := info.LocalInstances["instance-1"]
	_, inst2Exists := info.LocalInstances["instance-2"]
	_, inst3Exists := info.LocalInstances["instance-3"]
	tracker.mu.RUnlock()

	if remainingInstances != 1 {
		t.Errorf("Expected 1 instance after cleanup, got %d", remainingInstances)
	}
	if inst1Exists {
		t.Errorf("instance-1 should have been removed (count was 0)")
	}
	if inst2Exists {
		t.Errorf("instance-2 should have been removed (count was 0)")
	}
	if !inst3Exists {
		t.Errorf("instance-3 should still exist (count > 0)")
	}
}

// TestConnectionTracker_PerIPCountCleanup tests that zero-count PerIPCount entries are removed during cleanup
func TestConnectionTracker_PerIPCountCleanup(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 5, 0)
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
	initialIPs := len(info.PerIPCount)
	tracker.mu.RUnlock()
	if initialIPs != 3 {
		t.Fatalf("Expected 3 IPs tracked, got %d", initialIPs)
	}

	// Disconnect all from first two IPs
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.1:1234")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.1:1235")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.2:1234")
	tracker.UnregisterConnection(ctx, accountID, "test", "192.168.1.2:1235")

	// At this point, PerIPCount should have counts: IP1=0, IP2=0, IP3=1
	tracker.mu.RLock()
	ip1Count := info.PerIPCount["192.168.1.1"]
	ip2Count := info.PerIPCount["192.168.1.2"]
	ip3Count := info.PerIPCount["192.168.1.3"]
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
	remainingIPs := len(info.PerIPCount)
	_, ip1Exists := info.PerIPCount["192.168.1.1"]
	_, ip2Exists := info.PerIPCount["192.168.1.2"]
	_, ip3Exists := info.PerIPCount["192.168.1.3"]
	finalIP3Count := info.PerIPCount["192.168.1.3"]
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
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 3, 0)
	defer tracker.Stop()

	// Simulate user connecting from many instances over time
	accountID := int64(99999)
	username := "longterm@example.com"

	// Register user from 20 different instances (simulating cluster turnover over weeks)
	tracker.mu.Lock()
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:      accountID,
		Username:       username,
		TotalCount:     1,
		LocalCount:     0,
		LastUpdate:     time.Now(),
		LocalInstances: make(map[string]int),
		PerIPCount:     make(map[string]int),
	}
	info := tracker.connections[accountID]
	for i := 1; i <= 20; i++ {
		// Most instances have disconnected (count=0), only 2 are still active
		if i <= 2 {
			info.LocalInstances[string(rune('a'+i))] = 1 // Active instances
		} else {
			info.LocalInstances[string(rune('a'+i))] = 0 // Disconnected instances
		}
	}
	tracker.mu.Unlock()

	// Verify we start with 20 instance entries
	tracker.mu.RLock()
	initialSize := len(info.LocalInstances)
	tracker.mu.RUnlock()
	if initialSize != 20 {
		t.Fatalf("Expected 20 instances initially, got %d", initialSize)
	}

	// Run cleanup
	tracker.cleanup()

	// Verify we cleaned up to only active instances
	tracker.mu.RLock()
	finalSize := len(info.LocalInstances)
	tracker.mu.RUnlock()

	if finalSize != 2 {
		t.Errorf("Expected 2 instances after cleanup (only active ones), got %d", finalSize)
	}

	// Calculate memory saved: 18 instance IDs × ~20 bytes = ~360 bytes per user
	// With 30k users, that's ~11MB saved
	savedEntries := initialSize - finalSize
	if savedEntries != 18 {
		t.Errorf("Expected to clean 18 zero-count entries, cleaned %d", savedEntries)
	}
}

// TestConnectionTracker_CleanupHandlesEmptyMaps tests cleanup doesn't crash on empty/nil maps
func TestConnectionTracker_CleanupHandlesEmptyMaps(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0)
	defer tracker.Stop()

	// Add user with nil/empty maps
	tracker.mu.Lock()
	tracker.connections[123] = &UserConnectionInfo{
		AccountID:      123,
		Username:       "test@example.com",
		TotalCount:     0,
		LocalCount:     0,
		LastUpdate:     time.Now().Add(-20 * time.Minute), // Stale
		LocalInstances: nil,                               // nil map
		PerIPCount:     make(map[string]int),              // empty map
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
	tracker := NewConnectionTracker("test", "instance-1", nil, 100, 0, 0)
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
