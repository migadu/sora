package server

import (
	"context"
	"testing"
)

// TestLocalInstancesMapLeak proves that LocalInstances map accumulates zero-count entries
func TestLocalInstancesMapLeak(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(123)
	username := "test@example.com"
	protocol := "IMAP"

	// Simulate multiple connection/disconnection cycles
	// This simulates a user connecting and disconnecting repeatedly
	for i := 0; i < 100; i++ {
		clientAddr := "192.168.1.100:50000"

		// Register connection
		err := tracker.RegisterConnection(ctx, accountID, username, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection %d: %v", i, err)
		}

		// Unregister connection
		err = tracker.UnregisterConnection(ctx, accountID, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to unregister connection %d: %v", i, err)
		}
	}

	// After 100 register/unregister cycles, check the LocalInstances map
	tracker.mu.RLock()
	info, exists := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if !exists {
		// User was cleaned up - this is good
		t.Log("✓ User entry was cleaned up (no leak)")
		return
	}

	// Check PerIPCountByInstance map for empty instance maps
	emptyInstanceMaps := 0
	for instanceID, perIPMap := range info.PerIPCountByInstance {
		if len(perIPMap) == 0 {
			t.Logf("PerIPCountByInstance[%s] is empty", instanceID)
			emptyInstanceMaps++
		}
	}

	if emptyInstanceMaps > 0 {
		t.Errorf("MEMORY LEAK: PerIPCountByInstance has %d empty instance maps", emptyInstanceMaps)
		t.Errorf("These entries should be deleted immediately, not wait for cleanup")
	}

	// Check PerIPCountByInstance map for comparison
	perIPCountSize := 0
	for instanceID, perIPMap := range info.PerIPCountByInstance {
		perIPCountSize += len(perIPMap)
		for ip, count := range perIPMap {
			t.Logf("PerIPCountByInstance[%s][%s] = %d", instanceID, ip, count)
		}
	}
	if perIPCountSize > 0 {
		zeroCountIPs := 0
		for _, perIPMap := range info.PerIPCountByInstance {
			for _, count := range perIPMap {
				if count == 0 {
					zeroCountIPs++
				}
			}
		}

		if zeroCountIPs > 0 {
			t.Errorf("BUG: PerIPCount has zero-count entries (should be cleaned immediately)")
		} else if perIPCountSize > 0 {
			t.Logf("✓ PerIPCount cleans up zero-count entries immediately")
		}
	}

	t.Logf("PerIPCountByInstance total IP entries: %d", perIPCountSize)
}

// TestLocalInstancesMapGrowthWithMultipleInstances tests that the fix prevents map growth
func TestLocalInstancesMapGrowthWithMultipleInstances(t *testing.T) {
	// Test that LocalInstances map doesn't accumulate zero-count entries after fix
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 1000, false)
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(456)
	username := "user@example.com"
	protocol := "IMAP"

	// Register and unregister 100 connections
	for i := 0; i < 100; i++ {
		clientAddr := "192.168.1.100:50000"

		// Register
		err := tracker.RegisterConnection(ctx, accountID, username, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to register: %v", err)
		}

		// Unregister
		err = tracker.UnregisterConnection(ctx, accountID, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to unregister: %v", err)
		}
	}

	// Check PerIPCountByInstance map - should be empty or have only active entries
	tracker.mu.RLock()
	info, exists := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if !exists {
		t.Logf("✓ User entry was cleaned up (optimal)")
		return
	}

	totalInstanceMaps := len(info.PerIPCountByInstance)
	t.Logf("PerIPCountByInstance has %d instance maps", totalInstanceMaps)

	// Count zero-count entries
	zeroCountEntries := 0
	emptyInstanceMaps := 0
	for instanceID, perIPMap := range info.PerIPCountByInstance {
		if len(perIPMap) == 0 {
			emptyInstanceMaps++
			t.Logf("  %s: empty instance map", instanceID)
		} else {
			for ip, count := range perIPMap {
				t.Logf("  %s[%s]: %d connections", instanceID, ip, count)
				if count == 0 {
					zeroCountEntries++
				}
			}
		}
	}

	if zeroCountEntries > 0 || emptyInstanceMaps > 0 {
		t.Errorf("MEMORY LEAK: %d zero-count entries and %d empty instance maps",
			zeroCountEntries, emptyInstanceMaps)
		t.Errorf("The fix should delete zero-count entries immediately")
	} else {
		t.Logf("✓ No zero-count entries or empty maps - fix is working")
	}
}

// TestLocalInstancesVsPerIPCountConsistency tests the inconsistency between cleanup strategies
func TestLocalInstancesVsPerIPCountConsistency(t *testing.T) {
	// Test with per-IP limiting enabled
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 10, 1000, false)
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(789)
	username := "test@example.com"
	protocol := "IMAP"

	// Register and unregister from different IPs
	for i := 0; i < 5; i++ {
		clientAddr := "192.168.1." + string(rune('1'+i)) + ":50000"

		// Register
		err := tracker.RegisterConnection(ctx, accountID, username, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to register: %v", err)
		}

		// Unregister
		err = tracker.UnregisterConnection(ctx, accountID, protocol, clientAddr)
		if err != nil {
			t.Fatalf("Failed to unregister: %v", err)
		}
	}

	tracker.mu.RLock()
	info, exists := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if !exists {
		t.Log("✓ User cleaned up completely")
		return
	}

	totalInstanceMaps := len(info.PerIPCountByInstance)
	perIPCountSize := 0
	zeroCountEntries := 0
	emptyInstanceMaps := 0
	for _, perIPMap := range info.PerIPCountByInstance {
		if len(perIPMap) == 0 {
			emptyInstanceMaps++
		} else {
			perIPCountSize += len(perIPMap)
			for _, count := range perIPMap {
				if count == 0 {
					zeroCountEntries++
				}
			}
		}
	}

	t.Logf("PerIPCountByInstance instances: %d", totalInstanceMaps)
	t.Logf("PerIPCountByInstance total IP entries: %d", perIPCountSize)
	t.Logf("Empty instance maps: %d", emptyInstanceMaps)
	t.Logf("Zero-count IP entries: %d", zeroCountEntries)

	// PerIPCountByInstance should be empty (cleaned immediately)
	if perIPCountSize > 0 {
		t.Errorf("BUG: PerIPCountByInstance has %d entries (should be 0 after disconnect)", perIPCountSize)
		for instanceID, perIPMap := range info.PerIPCountByInstance {
			for ip, count := range perIPMap {
				t.Logf("  PerIPCountByInstance[%s][%s] = %d", instanceID, ip, count)
			}
		}
	} else {
		t.Logf("✓ PerIPCountByInstance is empty (immediate cleanup works)")
	}

	if emptyInstanceMaps > 0 {
		t.Errorf("BUG: PerIPCountByInstance has %d empty instance maps (should be cleaned immediately)", emptyInstanceMaps)
	}
}

// TestMemoryImpactWithManyUsers tests map growth with many users
func TestMemoryImpactWithManyUsers(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 10000, false)
	defer tracker.Stop()

	ctx := context.Background()
	protocol := "IMAP"

	// Simulate 1000 users each connecting and disconnecting
	numUsers := 1000
	for i := 0; i < numUsers; i++ {
		accountID := int64(i)
		username := "user" + string(rune('0'+(i%10))) + "@example.com"
		clientAddr := "192.168.1.1:50000"

		// Register
		tracker.RegisterConnection(ctx, accountID, username, protocol, clientAddr)

		// Unregister
		tracker.UnregisterConnection(ctx, accountID, protocol, clientAddr)
	}

	// Count total PerIPCountByInstance entries across all users
	tracker.mu.RLock()
	totalUsers := len(tracker.connections)
	totalInstanceMaps := 0
	totalIPEntries := 0
	totalZeroCountEntries := 0
	totalEmptyInstanceMaps := 0

	for _, info := range tracker.connections {
		totalInstanceMaps += len(info.PerIPCountByInstance)
		for _, perIPMap := range info.PerIPCountByInstance {
			if len(perIPMap) == 0 {
				totalEmptyInstanceMaps++
			} else {
				totalIPEntries += len(perIPMap)
				for _, count := range perIPMap {
					if count == 0 {
						totalZeroCountEntries++
					}
				}
			}
		}
	}
	tracker.mu.RUnlock()

	t.Logf("Simulated %d users connecting/disconnecting", numUsers)
	t.Logf("Users in tracker: %d", totalUsers)
	t.Logf("Total instance maps: %d", totalInstanceMaps)
	t.Logf("Total IP entries: %d", totalIPEntries)
	t.Logf("Empty instance maps: %d", totalEmptyInstanceMaps)
	t.Logf("Zero-count IP entries: %d", totalZeroCountEntries)

	if totalZeroCountEntries > 0 || totalEmptyInstanceMaps > 0 {
		estimatedWaste := (totalZeroCountEntries + totalEmptyInstanceMaps) * 32 // map entry overhead
		t.Errorf("MEMORY LEAK: %d zero-count entries and %d empty maps wasting ~%d bytes",
			totalZeroCountEntries, totalEmptyInstanceMaps, estimatedWaste)
		t.Errorf("This memory won't be reclaimed until cleanup runs (every 5 minutes)")
	}

	// Run cleanup
	tracker.cleanup()

	tracker.mu.RLock()
	totalIPEntriesAfter := 0
	totalEmptyInstanceMapsAfter := 0
	for _, info := range tracker.connections {
		for _, perIPMap := range info.PerIPCountByInstance {
			if len(perIPMap) == 0 {
				totalEmptyInstanceMapsAfter++
			} else {
				totalIPEntriesAfter += len(perIPMap)
			}
		}
	}
	tracker.mu.RUnlock()

	removed := (totalIPEntries + totalEmptyInstanceMaps) - (totalIPEntriesAfter + totalEmptyInstanceMapsAfter)
	if removed > 0 {
		t.Logf("✓ Cleanup removed %d entries/maps", removed)
	}
}
