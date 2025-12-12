package server

import (
	"context"
	"testing"
	"time"
)

// TestStaleConnectionsFromMissedUnregister reproduces the issue where stale connections
// accumulate when unregister events are missed and state snapshots don't remove them.
//
// Scenario:
// 1. Node A has an active connection for user X
// 2. Node B receives gossip and tracks it (LocalInstances["node-a"] = 1)
// 3. Connection on Node A closes → unregister event sent
// 4. Node B misses the unregister event (simulated by not processing it)
// 5. Node A broadcasts state snapshot (no longer includes user X)
// 6. Node B receives snapshot but doesn't remove the stale entry
// 7. Result: Node B still shows user X with connections from Node A
func TestStaleConnectionsFromMissedUnregister(t *testing.T) {
	// Create two connection trackers (simulating two nodes)
	nodeA := NewConnectionTracker("LMTP", "node-a", nil, 0, 0, 10000, false)
	defer nodeA.Stop()

	nodeB := NewConnectionTracker("LMTP", "node-b", nil, 0, 0, 10000, false)
	defer nodeB.Stop()

	accountID := int64(12345)
	username := "test@example.com"

	// Step 1: Node A registers a connection
	err := nodeA.RegisterConnection(context.Background(), accountID, username, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Node A failed to register connection: %v", err)
	}

	// Verify Node A has the connection
	if nodeA.GetConnectionCount(accountID) != 1 {
		t.Fatalf("Node A should have 1 connection, got %d", nodeA.GetConnectionCount(accountID))
	}

	// Step 2: Simulate gossip - Node B receives register event from Node A
	// We do this by manually creating the connection entry (simulating gossip reception)
	nodeB.mu.Lock()
	perIPCountByInstance := make(map[string]map[string]int)
	perIPCountByInstance["node-a"] = map[string]int{"192.168.1.100": 1}
	nodeB.connections[accountID] = &UserConnectionInfo{
		AccountID:            accountID,
		Username:             username,
		FirstSeen:            time.Now(),
		LastUpdate:           time.Now(),
		PerIPCountByInstance: perIPCountByInstance,
	}
	nodeB.mu.Unlock()

	// Verify Node B tracks the remote connection
	if nodeB.GetConnectionCount(accountID) != 1 {
		t.Fatalf("Node B should track 1 remote connection, got %d", nodeB.GetConnectionCount(accountID))
	}

	// Step 3: Connection on Node A closes
	err = nodeA.UnregisterConnection(context.Background(), accountID, "LMTP", "192.168.1.100:54321")
	if err != nil {
		t.Fatalf("Node A failed to unregister connection: %v", err)
	}

	// Verify Node A no longer has the connection
	if nodeA.GetConnectionCount(accountID) != 0 {
		t.Fatalf("Node A should have 0 connections after unregister, got %d", nodeA.GetConnectionCount(accountID))
	}

	// Step 4: Simulate missed unregister event (Node B doesn't receive it)
	// In real scenario, this could happen due to:
	// - Network packet loss
	// - Event queue overflow
	// - Gossip message dropped due to size limits
	// We simulate this by NOT calling unregister on Node B

	// Step 5: Node A broadcasts state snapshot (60 second interval)
	// Since Node A has no connections, the snapshot will be empty
	nodeA.mu.RLock()
	snapshot := &ConnectionStateSnapshot{
		InstanceID:  "node-a",
		Timestamp:   time.Now(),
		Connections: make(map[int64]UserConnectionData), // Empty - no connections
	}
	nodeA.mu.RUnlock()

	// Step 6: Node B receives and reconciles the state snapshot
	nodeB.reconcileState(snapshot)

	// Step 7: Verify the issue - Node B SHOULD remove the stale entry, but currently doesn't
	nodeB.mu.RLock()
	info := nodeB.connections[accountID]
	nodeB.mu.RUnlock()

	if info == nil {
		t.Log("PASS: Node B correctly removed stale connection after state snapshot")
		return
	}

	// Check if Node B still has the stale entry from Node A
	if perIPMap, exists := info.PerIPCountByInstance["node-a"]; exists && len(perIPMap) > 0 {
		t.Errorf("FAIL: Node B still has stale entry for Node A: PerIPCountByInstance[node-a]=%v, TotalCount=%d",
			perIPMap, info.GetTotalCount())
		t.Errorf("This is the bug: State snapshot from Node A was empty (no connections), but Node B didn't remove the stale entry")
	} else {
		t.Log("PASS: Node B correctly removed stale connection")
	}
}

// TestStateSnapshotRemovesStaleInstances verifies that when a node sends a state snapshot,
// any entries for that node that are NOT in the snapshot should be removed.
func TestStateSnapshotRemovesStaleInstances(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "local-node", nil, 0, 0, 10000, false)
	defer tracker.Stop()

	// Set up initial state: We have connections from two remote nodes
	account1 := int64(100)
	account2 := int64(200)
	account3 := int64(300)

	tracker.mu.Lock()
	// Account 1: Connection on remote-node-a
	perIPCountByInstance1 := make(map[string]map[string]int)
	perIPCountByInstance1["remote-node-a"] = map[string]int{"192.168.1.1": 1}
	tracker.connections[account1] = &UserConnectionInfo{
		AccountID:            account1,
		Username:             "user1@example.com",
		FirstSeen:            time.Now(),
		LastUpdate:           time.Now(),
		PerIPCountByInstance: perIPCountByInstance1,
	}
	// Account 2: Connection on remote-node-a
	perIPCountByInstance2 := make(map[string]map[string]int)
	perIPCountByInstance2["remote-node-a"] = map[string]int{"192.168.1.2": 1}
	tracker.connections[account2] = &UserConnectionInfo{
		AccountID:            account2,
		Username:             "user2@example.com",
		FirstSeen:            time.Now(),
		LastUpdate:           time.Now(),
		PerIPCountByInstance: perIPCountByInstance2,
	}
	// Account 3: Connection on remote-node-a
	perIPCountByInstance3 := make(map[string]map[string]int)
	perIPCountByInstance3["remote-node-a"] = map[string]int{"192.168.1.3": 1}
	tracker.connections[account3] = &UserConnectionInfo{
		AccountID:            account3,
		Username:             "user3@example.com",
		FirstSeen:            time.Now(),
		LastUpdate:           time.Now(),
		PerIPCountByInstance: perIPCountByInstance3,
	}
	tracker.mu.Unlock()

	// Verify initial state
	if tracker.GetConnectionCount(account1) != 1 {
		t.Fatalf("Account 1 should have 1 connection, got %d", tracker.GetConnectionCount(account1))
	}
	if tracker.GetConnectionCount(account2) != 1 {
		t.Fatalf("Account 2 should have 1 connection, got %d", tracker.GetConnectionCount(account2))
	}
	if tracker.GetConnectionCount(account3) != 1 {
		t.Fatalf("Account 3 should have 1 connection, got %d", tracker.GetConnectionCount(account3))
	}

	// Receive state snapshot from remote-node-a
	// The snapshot only includes account2 (account1 and account3 connections were closed)
	snapshot := &ConnectionStateSnapshot{
		InstanceID: "remote-node-a",
		Timestamp:  time.Now(),
		Connections: map[int64]UserConnectionData{
			account2: {
				AccountID:  account2,
				Username:   "user2@example.com",
				PerIPCount: map[string]int{"192.168.1.2": 1}, // PerIPCount for this instance only
				LastUpdate: time.Now(),
			},
		},
	}

	// Reconcile the state
	tracker.reconcileState(snapshot)

	// Verify results:
	// - Account 1 should be removed (not in snapshot, was from remote-node-a)
	// - Account 2 should still exist (in snapshot)
	// - Account 3 should be removed (not in snapshot, was from remote-node-a)

	tracker.mu.RLock()
	info1 := tracker.connections[account1]
	info2 := tracker.connections[account2]
	info3 := tracker.connections[account3]
	tracker.mu.RUnlock()

	if info1 != nil {
		t.Errorf("FAIL: Account 1 should be removed (not in snapshot from remote-node-a), but still exists with TotalCount=%d, PerIPCountByInstance=%v",
			info1.GetTotalCount(), info1.PerIPCountByInstance)
	} else {
		t.Log("PASS: Account 1 correctly removed")
	}

	if info2 == nil {
		t.Error("FAIL: Account 2 should still exist (in snapshot)")
	} else if info2.GetTotalCount() != 1 {
		t.Errorf("FAIL: Account 2 should have TotalCount=1, got %d", info2.GetTotalCount())
	} else {
		t.Log("PASS: Account 2 correctly preserved")
	}

	if info3 != nil {
		t.Errorf("FAIL: Account 3 should be removed (not in snapshot from remote-node-a), but still exists with TotalCount=%d, PerIPCountByInstance=%v",
			info3.GetTotalCount(), info3.PerIPCountByInstance)
	} else {
		t.Log("PASS: Account 3 correctly removed")
	}
}

// TestStateSnapshotDoesNotAffectOtherInstances verifies that a state snapshot from
// one node doesn't remove entries from other nodes.
func TestStateSnapshotDoesNotAffectOtherInstances(t *testing.T) {
	tracker := NewConnectionTracker("LMTP", "local-node", nil, 0, 0, 10000, false)
	defer tracker.Stop()

	accountID := int64(100)

	// Set up state: Connection on both remote-node-a and remote-node-b
	tracker.mu.Lock()
	perIPCountByInstance := make(map[string]map[string]int)
	perIPCountByInstance["remote-node-a"] = map[string]int{"192.168.1.1": 1}
	perIPCountByInstance["remote-node-b"] = map[string]int{"192.168.1.2": 1}
	tracker.connections[accountID] = &UserConnectionInfo{
		AccountID:            accountID,
		Username:             "user@example.com",
		FirstSeen:            time.Now(),
		LastUpdate:           time.Now(),
		PerIPCountByInstance: perIPCountByInstance,
	}
	tracker.mu.Unlock()

	// Receive empty state snapshot from remote-node-a (connection closed on that node)
	snapshot := &ConnectionStateSnapshot{
		InstanceID:  "remote-node-a",
		Timestamp:   time.Now(),
		Connections: make(map[int64]UserConnectionData), // Empty
	}

	tracker.reconcileState(snapshot)

	// Verify: remote-node-a entry should be removed, but remote-node-b should remain
	tracker.mu.RLock()
	info := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if info == nil {
		t.Fatal("FAIL: Account should still exist (has connection on remote-node-b)")
	}

	if perIPMap, exists := info.PerIPCountByInstance["remote-node-a"]; exists && len(perIPMap) > 0 {
		t.Errorf("FAIL: remote-node-a entry should be removed, but PerIPCountByInstance[remote-node-a]=%v", perIPMap)
	} else {
		t.Log("PASS: remote-node-a entry correctly removed")
	}

	if perIPMap, exists := info.PerIPCountByInstance["remote-node-b"]; !exists || len(perIPMap) == 0 {
		t.Errorf("FAIL: remote-node-b entry should be preserved, but PerIPCountByInstance[remote-node-b]=%v (exists=%v)", perIPMap, exists)
	} else {
		t.Log("PASS: remote-node-b entry correctly preserved")
	}

	if info.GetTotalCount() != 1 {
		t.Errorf("FAIL: TotalCount should be 1 (only remote-node-b), got %d", info.GetTotalCount())
	}
}
