package server

import (
	"context"
	"testing"
	"time"
)

// These tests focus on the cleanup semantics for gossip-tracked state.
//
// Key principle (simplified model):
// - We never delete "remote-only" entries based on an arbitrary per-user age.
// - We prune remote data when the *instance* that produced it is considered stale
//   (no gossip seen for that instance for some threshold).
// - After pruning per-instance data, user entries are removed only when the total count reaches 0.

func TestGossipCleanup_DoesNotRemoveRemoteEntriesWhenInstanceAlive(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "", "", "local-instance", nil, 0, 0, 0, false)
	defer tracker.Stop()

	remoteInstanceID := "remote-node"
	accountID := int64(12345)

	tracker.mu.Lock()
	// Pretend we recently heard from this instance.
	tracker.instanceLastSeen[remoteInstanceID] = time.Now()
	// Create a remote-only entry (LocalCount=0, TotalCount>0)
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:  accountID,
		Username:   "test@example.com",
		FirstSeen:  time.Now().Add(-24 * time.Hour), // old on purpose
		LastUpdate: time.Now(),
		PerIPCountByInstance: map[string]map[string]int{
			remoteInstanceID: {"192.0.2.1": 1},
		},
	}
	tracker.mu.Unlock()

	tracker.cleanup()

	tracker.mu.RLock()
	info := tracker.connections[accountID]
	tracker.mu.RUnlock()
	if info == nil {
		t.Fatalf("remote-only entry should not be removed while instance is alive")
	}
	if got := info.GetLocalCount(tracker.instanceID); got != 0 {
		t.Fatalf("expected local count to remain 0, got %d", got)
	}
	if got := info.GetTotalCount(); got != 1 {
		t.Fatalf("expected total count to remain 1, got %d", got)
	}
}

func TestGossipCleanup_PurgesStaleInstanceData(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "", "", "local-instance", nil, 0, 0, 0, false)
	defer tracker.Stop()

	remoteInstanceID := "remote-node"

	tracker.mu.Lock()
	// Pretend this instance hasn't been seen for long enough to be stale.
	tracker.instanceLastSeen[remoteInstanceID] = time.Now().Add(-10 * time.Minute)

	// Two users with remote-only data.
	tracker.connections[1] = &UserConnectionInfo{
		AccountID:  1,
		Username:   "u1@example.com",
		FirstSeen:  time.Now().Add(-time.Hour),
		LastUpdate: time.Now(),
		PerIPCountByInstance: map[string]map[string]int{
			remoteInstanceID: {"192.0.2.1": 1},
		},
	}
	tracker.connections[2] = &UserConnectionInfo{
		AccountID:  2,
		Username:   "u2@example.com",
		FirstSeen:  time.Now().Add(-time.Hour),
		LastUpdate: time.Now(),
		PerIPCountByInstance: map[string]map[string]int{
			remoteInstanceID: {"192.0.2.2": 3},
		},
	}
	tracker.mu.Unlock()

	tracker.cleanup()

	tracker.mu.RLock()
	_, instanceStillTracked := tracker.instanceLastSeen[remoteInstanceID]
	_, user1Exists := tracker.connections[1]
	_, user2Exists := tracker.connections[2]
	tracker.mu.RUnlock()

	if instanceStillTracked {
		t.Fatalf("expected stale instance %q to be removed from instanceLastSeen", remoteInstanceID)
	}
	if user1Exists || user2Exists {
		t.Fatalf("expected users to be removed after stale instance data is purged (no counts remain); got user1=%v user2=%v", user1Exists, user2Exists)
	}
}

// TestGossipCleanupPreservesActiveConnections verifies that connections
// with LocalCount > 0 are never cleaned up, even if old.
func TestGossipCleanupPreservesActiveConnections(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 0, false)
	defer tracker.Stop()

	accountID := int64(12345)
	username := "test@example.com"
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Set FirstSeen to 10 minutes ago (much older than any pruning threshold)
	tracker.mu.Lock()
	info := tracker.connections[accountID]
	info.FirstSeen = time.Now().Add(-10 * time.Minute)
	tracker.mu.Unlock()

	tracker.cleanup()

	tracker.mu.RLock()
	info = tracker.connections[accountID]
	tracker.mu.RUnlock()
	if info == nil {
		t.Fatal("Active connection (LocalCount > 0) was incorrectly cleaned up")
	}

	if localCount := info.GetLocalCount(tracker.instanceID); localCount != 1 {
		t.Fatalf("Expected LocalCount=1, got %d", localCount)
	}
}

// TestFirstSeenNotUpdatedByLastUpdate verifies that FirstSeen stays constant
// even when LastUpdate is refreshed (simulating gossip behavior).
func TestFirstSeenNotUpdatedByLastUpdate(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 0, false)
	defer tracker.Stop()

	accountID := int64(12345)
	username := "test@example.com"
	err := tracker.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	tracker.mu.Lock()
	originalFirstSeen := tracker.connections[accountID].FirstSeen
	tracker.mu.Unlock()

	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		tracker.mu.Lock()
		tracker.connections[accountID].LastUpdate = time.Now()
		tracker.mu.Unlock()
	}

	tracker.mu.Lock()
	currentFirstSeen := tracker.connections[accountID].FirstSeen
	lastUpdate := tracker.connections[accountID].LastUpdate
	tracker.mu.Unlock()

	if !currentFirstSeen.Equal(originalFirstSeen) {
		t.Errorf("FirstSeen changed from %v to %v - should remain constant even when LastUpdate is refreshed",
			originalFirstSeen, currentFirstSeen)
	}
	if time.Since(lastUpdate) > 100*time.Millisecond {
		t.Errorf("LastUpdate should be recent (< 100ms), but is %v old", time.Since(lastUpdate))
	}
	if !originalFirstSeen.Before(lastUpdate) {
		t.Error("FirstSeen should be older than LastUpdate after multiple updates")
	}
}

// TestSnapshotOnlyBackendCleansUpLocalEntries verifies that backend servers
// (snapshotOnly=true) clean up entries when local count reaches 0, even if
// they've received gossip about other instances showing TotalCount > 0.
func TestSnapshotOnlyBackendCleansUpLocalEntries(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "", "", "backend-instance", nil, 0, 0, 0, true) // snapshotOnly=true
	defer tracker.Stop()

	accountID := int64(12345)
	username := "test@example.com"
	clientAddr := "192.168.1.100:54321"

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
	info.PerIPCountByInstance["other-backend"] = map[string]int{"192.168.1.200": 1}
	tracker.mu.Unlock()

	// Unregister the local connection
	err = tracker.UnregisterConnection(context.Background(), accountID, "LMTP", clientAddr)
	if err != nil {
		t.Fatalf("Failed to unregister connection: %v", err)
	}

	tracker.mu.RLock()
	info = tracker.connections[accountID]
	tracker.mu.RUnlock()
	if info != nil {
		t.Errorf("Backend server (snapshotOnly=true) should clean up entry when LocalCount=0, even if TotalCount > 0")
		t.Errorf("LocalCount: %d, TotalCount: %d", info.GetLocalCount(tracker.instanceID), info.GetTotalCount())
	}
}
