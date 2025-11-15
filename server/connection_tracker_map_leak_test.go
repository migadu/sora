package server

import (
	"context"
	"testing"
)

// TestLocalInstancesMapLeak proves that LocalInstances map accumulates zero-count entries
func TestLocalInstancesMapLeak(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 1000)
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

	// Check LocalInstances map
	localInstancesSize := len(info.LocalInstances)
	if localInstancesSize > 0 {
		// Check if entries are zero-count
		zeroCountEntries := 0
		for instanceID, count := range info.LocalInstances {
			t.Logf("LocalInstances[%s] = %d", instanceID, count)
			if count == 0 {
				zeroCountEntries++
			}
		}

		if zeroCountEntries > 0 {
			t.Errorf("MEMORY LEAK: LocalInstances map has %d zero-count entries", zeroCountEntries)
			t.Errorf("These entries should be deleted immediately, not wait for cleanup")
		}
	}

	// Check PerIPCount map for comparison
	perIPCountSize := len(info.PerIPCount)
	if perIPCountSize > 0 {
		zeroCountIPs := 0
		for ip, count := range info.PerIPCount {
			t.Logf("PerIPCount[%s] = %d", ip, count)
			if count == 0 {
				zeroCountIPs++
			}
		}

		if zeroCountIPs > 0 {
			t.Errorf("BUG: PerIPCount has zero-count entries (should be cleaned immediately)")
		} else if perIPCountSize > 0 {
			t.Logf("✓ PerIPCount cleans up zero-count entries immediately")
		}
	}

	t.Logf("LocalInstances map size: %d", localInstancesSize)
	t.Logf("PerIPCount map size: %d", perIPCountSize)
}

// TestLocalInstancesMapGrowthWithMultipleInstances tests that the fix prevents map growth
func TestLocalInstancesMapGrowthWithMultipleInstances(t *testing.T) {
	// Test that LocalInstances map doesn't accumulate zero-count entries after fix
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 1000)
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

	// Check LocalInstances map - should be empty or have only active entries
	tracker.mu.RLock()
	info, exists := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if !exists {
		t.Logf("✓ User entry was cleaned up (optimal)")
		return
	}

	localInstancesSize := len(info.LocalInstances)
	t.Logf("LocalInstances map has %d entries", localInstancesSize)

	// Count zero-count entries
	zeroCountEntries := 0
	for instanceID, count := range info.LocalInstances {
		t.Logf("  %s: %d connections", instanceID, count)
		if count == 0 {
			zeroCountEntries++
		}
	}

	if zeroCountEntries > 0 {
		t.Errorf("MEMORY LEAK: %d/%d entries in LocalInstances have zero count",
			zeroCountEntries, localInstancesSize)
		t.Errorf("The fix should delete zero-count entries immediately")
	} else {
		t.Logf("✓ No zero-count entries - fix is working")
	}
}

// TestLocalInstancesVsPerIPCountConsistency tests the inconsistency between cleanup strategies
func TestLocalInstancesVsPerIPCountConsistency(t *testing.T) {
	// Test with per-IP limiting enabled
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 10, 1000)
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

	localInstancesSize := len(info.LocalInstances)
	perIPCountSize := len(info.PerIPCount)

	t.Logf("LocalInstances size: %d", localInstancesSize)
	t.Logf("PerIPCount size: %d", perIPCountSize)

	// PerIPCount should be empty (cleaned immediately)
	if perIPCountSize > 0 {
		t.Errorf("INCONSISTENCY: PerIPCount has %d entries (should be 0)", perIPCountSize)
		for ip, count := range info.PerIPCount {
			t.Logf("  PerIPCount[%s] = %d", ip, count)
		}
	} else {
		t.Logf("✓ PerIPCount is empty (immediate cleanup works)")
	}

	// LocalInstances should also be empty but likely isn't
	if localInstancesSize > 0 {
		t.Logf("⚠️  INCONSISTENCY: LocalInstances has %d entries (PerIPCount has %d)",
			localInstancesSize, perIPCountSize)
		t.Logf("LocalInstances uses deferred cleanup, PerIPCount uses immediate cleanup")
		t.Logf("This inconsistency suggests LocalInstances should also use immediate cleanup")

		for instanceID, count := range info.LocalInstances {
			t.Logf("  LocalInstances[%s] = %d", instanceID, count)
		}
	}
}

// TestMemoryImpactWithManyUsers tests map growth with many users
func TestMemoryImpactWithManyUsers(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 10000)
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

	// Count total LocalInstances entries across all users
	tracker.mu.RLock()
	totalUsers := len(tracker.connections)
	totalLocalInstances := 0
	totalZeroCountEntries := 0

	for _, info := range tracker.connections {
		totalLocalInstances += len(info.LocalInstances)
		for _, count := range info.LocalInstances {
			if count == 0 {
				totalZeroCountEntries++
			}
		}
	}
	tracker.mu.RUnlock()

	t.Logf("Simulated %d users connecting/disconnecting", numUsers)
	t.Logf("Users in tracker: %d", totalUsers)
	t.Logf("Total LocalInstances entries: %d", totalLocalInstances)
	t.Logf("Zero-count entries: %d", totalZeroCountEntries)

	if totalZeroCountEntries > 0 {
		estimatedWaste := totalZeroCountEntries * 32 // map entry overhead
		t.Errorf("MEMORY LEAK: %d zero-count entries wasting ~%d bytes",
			totalZeroCountEntries, estimatedWaste)
		t.Errorf("This memory won't be reclaimed until cleanup runs (every 5 minutes)")
	}

	// Run cleanup
	tracker.cleanup()

	tracker.mu.RLock()
	totalLocalInstancesAfter := 0
	for _, info := range tracker.connections {
		totalLocalInstancesAfter += len(info.LocalInstances)
	}
	tracker.mu.RUnlock()

	removed := totalLocalInstances - totalLocalInstancesAfter
	if removed > 0 {
		t.Logf("✓ Cleanup removed %d zero-count entries", removed)
	}
}
