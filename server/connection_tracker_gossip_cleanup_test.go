package server

import (
	"context"
	"testing"
	"time"
)

// TestGossipCleanupUsesFirstSeenNotLastUpdate verifies that cleanup is based on
// FirstSeen timestamp, not LastUpdate, so gossip refreshes don't prevent cleanup
func TestGossipCleanupUsesFirstSeenNotLastUpdate(t *testing.T) {
	// Create a connection tracker without cluster (simpler for testing)
	tracker := NewConnectionTracker("LMTP", "test-instance", nil, 0, 0, 0, false)

	// Register a connection
	accountID := int64(12345)
	username := "test@example.com"
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Verify connection exists
	connections := tracker.GetAllConnections()
	if len(connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(connections))
	}

	// Get the connection info
	tracker.mu.Lock()
	info := tracker.connections[accountID]
	if info == nil {
		tracker.mu.Unlock()
		t.Fatal("Connection info not found")
	}

	// Record the FirstSeen timestamp
	originalFirstSeen := info.FirstSeen
	tracker.mu.Unlock()

	// Unregister the connection (simulating connection close)
	err = tracker.UnregisterConnection(context.Background(), accountID, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to unregister connection: %v", err)
	}

	// Verify LocalCount is now 0
	tracker.mu.Lock()
	localCount := info.GetLocalCount(tracker.instanceID)
	if localCount != 0 {
		tracker.mu.Unlock()
		t.Fatalf("Expected LocalCount=0 after unregister, got %d", localCount)
	}
	tracker.mu.Unlock()

	// Simulate gossip refreshes by updating LastUpdate multiple times
	// (This is what happens every 60 seconds in production via state snapshots)
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		tracker.mu.Lock()
		info.LastUpdate = time.Now() // Simulate gossip refresh
		tracker.mu.Unlock()
	}

	// Verify that FirstSeen hasn't changed despite LastUpdate refreshes
	tracker.mu.Lock()
	if !info.FirstSeen.Equal(originalFirstSeen) {
		tracker.mu.Unlock()
		t.Fatalf("FirstSeen changed from %v to %v - should remain constant", originalFirstSeen, info.FirstSeen)
	}

	// Verify LastUpdate is recent (updated by our simulated gossip)
	if time.Since(info.LastUpdate) > 200*time.Millisecond {
		tracker.mu.Unlock()
		t.Fatalf("LastUpdate should be recent, but it's %v old", time.Since(info.LastUpdate))
	}
	tracker.mu.Unlock()

	// Manually set FirstSeen to 4 minutes ago (older than 3-minute threshold)
	tracker.mu.Lock()
	info.FirstSeen = time.Now().Add(-4 * time.Minute)
	tracker.mu.Unlock()

	// Run cleanup
	tracker.cleanup()

	// Verify the connection was cleaned up despite recent LastUpdate
	tracker.mu.Lock()
	info = tracker.connections[accountID]
	tracker.mu.Unlock()

	if info != nil {
		t.Fatalf("Connection should have been cleaned up (FirstSeen > 3min, LocalCount=0), but still exists. FirstSeen age: %v, LastUpdate age: %v",
			time.Since(info.FirstSeen), time.Since(info.LastUpdate))
	}
}

// TestGossipCleanupPreservesActiveConnections verifies that connections
// with LocalCount > 0 are never cleaned up, even if old
func TestGossipCleanupPreservesActiveConnections(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "test-instance", nil, 0, 0, 0, false)

	// Register a connection
	accountID := int64(12345)
	username := "test@example.com"
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Set FirstSeen to 10 minutes ago (much older than threshold)
	tracker.mu.Lock()
	info := tracker.connections[accountID]
	info.FirstSeen = time.Now().Add(-10 * time.Minute)
	tracker.mu.Unlock()

	// Run cleanup
	tracker.cleanup()

	// Verify connection is preserved because LocalCount > 0
	tracker.mu.Lock()
	info = tracker.connections[accountID]
	if info == nil {
		tracker.mu.Unlock()
		t.Fatal("Active connection (LocalCount > 0) was incorrectly cleaned up")
	}

	localCount := info.GetLocalCount(tracker.instanceID)
	tracker.mu.Unlock()

	if localCount != 1 {
		t.Fatalf("Expected LocalCount=1, got %d", localCount)
	}
}

// TestGossipCleanupThreeMinuteThreshold verifies the 3-minute threshold
// for gossip entries (LocalCount=0 but TotalCount>0 from other nodes)
func TestGossipCleanupThreeMinuteThreshold(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "test-instance", nil, 0, 0, 0, false)

	// Test cases with different ages
	testCases := []struct {
		name          string
		ageMinutes    float64
		shouldCleanup bool
	}{
		{"30 seconds old", 0.5, false},  // Too recent
		{"2 minutes old", 2, false},     // Just under threshold
		{"2.9 minutes old", 2.9, false}, // Just under threshold
		{"3.1 minutes old", 3.1, true},  // Just over threshold
		{"5 minutes old", 5, true},      // Well over threshold
		{"1 hour old", 60, true},        // Very old
		{"1 day old", 1440, true},       // Extremely old
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate a gossip entry: connection on another node
			// (LocalCount=0, TotalCount>0)
			accountID := int64(12345 + int(tc.ageMinutes*10)) // Unique ID per test
			username := "test@example.com"

			tracker.mu.Lock()
			// Manually create a gossip entry (simulating entry from another node)
			firstSeenTime := time.Now().Add(time.Duration(-tc.ageMinutes*60) * time.Second)
			perIPCountByInstance := make(map[string]map[string]int)
			perIPCountByInstance["other-node"] = map[string]int{"192.168.1.1": 1}
			tracker.connections[accountID] = &UserConnectionInfo{
				AccountID:            accountID,
				Username:             username,
				FirstSeen:            firstSeenTime,
				LastUpdate:           time.Now(), // Kept fresh by gossip
				PerIPCountByInstance: perIPCountByInstance,
			}
			tracker.mu.Unlock()

			// Run cleanup
			tracker.cleanup()

			// Check if cleaned up
			tracker.mu.Lock()
			info := tracker.connections[accountID]
			tracker.mu.Unlock()

			wasCleanedUp := (info == nil)

			if wasCleanedUp != tc.shouldCleanup {
				if tc.shouldCleanup {
					t.Errorf("Gossip entry aged %s (%.1fm) should have been cleaned up but wasn't", tc.name, tc.ageMinutes)
				} else {
					t.Errorf("Gossip entry aged %s (%.1fm) should NOT have been cleaned up but was", tc.name, tc.ageMinutes)
				}
			}
		})
	}
}

// TestFirstSeenNotUpdatedByLastUpdate verifies that FirstSeen stays constant
// even when LastUpdate is refreshed (simulating gossip behavior)
func TestFirstSeenNotUpdatedByLastUpdate(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "test-instance", nil, 0, 0, 0, false)

	// Register a connection
	accountID := int64(12345)
	username := "test@example.com"
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Get the original FirstSeen
	tracker.mu.Lock()
	originalFirstSeen := tracker.connections[accountID].FirstSeen
	tracker.mu.Unlock()

	// Wait and update LastUpdate multiple times (simulating gossip refreshes)
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		tracker.mu.Lock()
		tracker.connections[accountID].LastUpdate = time.Now()
		tracker.mu.Unlock()
	}

	// Verify FirstSeen hasn't changed
	tracker.mu.Lock()
	currentFirstSeen := tracker.connections[accountID].FirstSeen
	lastUpdate := tracker.connections[accountID].LastUpdate
	tracker.mu.Unlock()

	if !currentFirstSeen.Equal(originalFirstSeen) {
		t.Errorf("FirstSeen changed from %v to %v - should remain constant even when LastUpdate is refreshed",
			originalFirstSeen, currentFirstSeen)
	}

	// Verify LastUpdate is recent (confirms we actually updated it)
	if time.Since(lastUpdate) > 100*time.Millisecond {
		t.Errorf("LastUpdate should be recent (< 100ms), but is %v old", time.Since(lastUpdate))
	}

	// Verify FirstSeen is older than LastUpdate
	if !originalFirstSeen.Before(lastUpdate) {
		t.Error("FirstSeen should be older than LastUpdate after multiple updates")
	}
}

// TestSnapshotOnlyBackendCleansUpLocalEntries verifies that backend servers
// (snapshotOnly=true) clean up entries when local count reaches 0, even if
// they've received gossip about other instances showing TotalCount > 0
func TestSnapshotOnlyBackendCleansUpLocalEntries(t *testing.T) {
	// Create a tracker simulating a backend LMTP server in cluster mode
	// (has cluster manager, but is snapshotOnly=true)
	tracker := NewConnectionTracker("LMTP", "backend-instance", nil, 0, 0, 0, true) // snapshotOnly=true
	defer tracker.Stop()

	accountID := int64(12345)
	username := "test@example.com"
	clientAddr := "192.168.1.100:54321"

	// Register a local connection
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", clientAddr)
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Simulate receiving gossip from another instance about the same user
	tracker.mu.Lock()
	info := tracker.connections[accountID]
	if info.PerIPCountByInstance == nil {
		info.PerIPCountByInstance = make(map[string]map[string]int)
	}
	// Add entry from another instance
	info.PerIPCountByInstance["other-backend"] = map[string]int{"192.168.1.200": 1}
	tracker.mu.Unlock()

	// Verify TotalCount > LocalCount
	tracker.mu.Lock()
	localCount := info.GetLocalCount(tracker.instanceID)
	totalCount := info.GetTotalCount()
	tracker.mu.Unlock()

	if localCount != 1 {
		t.Fatalf("Expected LocalCount=1, got %d", localCount)
	}
	if totalCount != 2 {
		t.Fatalf("Expected TotalCount=2 (1 local + 1 from other instance), got %d", totalCount)
	}

	// Unregister the local connection
	err = tracker.UnregisterConnection(context.Background(), accountID, "LMTP", clientAddr)
	if err != nil {
		t.Fatalf("Failed to unregister connection: %v", err)
	}

	// Verify the entry was DELETED despite TotalCount still being 1 (from other instance)
	tracker.mu.Lock()
	info = tracker.connections[accountID]
	tracker.mu.Unlock()

	if info != nil {
		t.Errorf("Backend server (snapshotOnly=true) should clean up entry when LocalCount=0, even if TotalCount > 0")
		t.Errorf("LocalCount: %d, TotalCount: %d", info.GetLocalCount(tracker.instanceID), info.GetTotalCount())
		t.Error("This would cause the backend to keep including this user in state snapshots, causing the proxy to never clean up the entry")
	} else {
		t.Log("✓ Backend server correctly cleaned up entry when LocalCount=0 (even though TotalCount > 0)")
	}
}
