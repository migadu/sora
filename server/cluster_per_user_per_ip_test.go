package server

import (
	"context"
	"testing"
	"time"
)

// TestClusterPerUserPerIP_GossipPropagation tests that per-user-per-IP counts are gossiped across cluster
func TestClusterPerUserPerIP_GossipPropagation(t *testing.T) {
	// This test simulates 2 nodes in a cluster (without actual cluster manager)
	// by manually propagating events between them to verify gossip behavior

	ctx := context.Background()
	accountID := int64(123)
	username := "user@example.com"
	protocol := "IMAP"
	clientIP := "203.0.113.50"
	clientAddr1 := clientIP + ":10001"
	clientAddr2 := clientIP + ":10002"

	// Node 1 - local mode tracker (simulates cluster node)
	node1 := NewConnectionTracker("IMAP", "node-1", nil, 10, 3, 0, false)
	if node1 == nil {
		t.Fatal("Failed to create node1 tracker")
	}
	defer node1.Stop()

	// Node 2 - local mode tracker (simulates cluster node)
	node2 := NewConnectionTracker("IMAP", "node-2", nil, 10, 3, 0, false)
	if node2 == nil {
		t.Fatal("Failed to create node2 tracker")
	}
	defer node2.Stop()

	// Node 1: User opens 2 connections from same IP
	err := node1.RegisterConnection(ctx, accountID, username, protocol, clientAddr1)
	if err != nil {
		t.Fatalf("Node1 connection 1 should succeed: %v", err)
	}

	err = node1.RegisterConnection(ctx, accountID, username, protocol, clientAddr2)
	if err != nil {
		t.Fatalf("Node1 connection 2 should succeed: %v", err)
	}

	// Simulate gossip: manually propagate events to node 2
	node2.handleRegister(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   protocol,
		ClientAddr: clientAddr1,
		Timestamp:  time.Now(),
		NodeID:     "node-1",
		InstanceID: "node-1",
	})

	node2.handleRegister(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   protocol,
		ClientAddr: clientAddr2,
		Timestamp:  time.Now(),
		NodeID:     "node-1",
		InstanceID: "node-1",
	})

	// Node 2: Try to open connection from SAME IP - should see cluster-wide count
	// Cluster total from IP = 2 (from node 1)
	// Trying to add 3rd connection should fail (max = 3, but we're at limit after 3rd)
	err = node2.RegisterConnection(ctx, accountID, username, protocol, clientIP+":20001")
	if err != nil {
		t.Fatalf("Node2 connection 1 should succeed (cluster count = 2, adding 1 = 3, under limit): %v", err)
	}

	// Now cluster-wide per-IP count = 3 (2 from node1 + 1 from node2)
	// Next connection should fail
	err = node2.RegisterConnection(ctx, accountID, username, protocol, clientIP+":20002")
	if err == nil {
		t.Fatal("Node2 connection 2 should fail (cluster-wide per-IP limit = 3)")
	}

	if err.Error() != "user user@example.com has reached maximum connections from IP 203.0.113.50 (3/3)" {
		t.Errorf("Expected cluster-wide per-IP limit error, got: %v", err)
	}

	t.Log("✓ Per-user-per-IP counts are tracked cluster-wide via gossip")
}

// TestClusterPerUserPerIP_StateSnapshot tests that per-IP counts are included in state snapshots
func TestClusterPerUserPerIP_StateSnapshot(t *testing.T) {
	ctx := context.Background()
	accountID := int64(456)
	username := "testuser@example.com"
	protocol := "IMAP"
	ip1 := "192.168.1.100"
	ip2 := "192.168.1.101"

	// Create tracker and register connections from multiple IPs
	tracker := NewConnectionTracker("IMAP", "node-1", nil, 20, 5, 0, false)
	if tracker == nil {
		t.Fatal("Failed to create tracker")
	}
	defer tracker.Stop()

	// Register 2 connections from IP1
	tracker.RegisterConnection(ctx, accountID, username, protocol, ip1+":10001")
	tracker.RegisterConnection(ctx, accountID, username, protocol, ip1+":10002")

	// Register 3 connections from IP2
	tracker.RegisterConnection(ctx, accountID, username, protocol, ip2+":20001")
	tracker.RegisterConnection(ctx, accountID, username, protocol, ip2+":20002")
	tracker.RegisterConnection(ctx, accountID, username, protocol, ip2+":20003")

	// Create a state snapshot (this is what gets gossiped)
	tracker.mu.Lock()
	info := tracker.connections[accountID]

	// Verify PerIPCountByInstance is populated correctly for this instance
	if perIPMap := info.PerIPCountByInstance[tracker.instanceID]; perIPMap == nil {
		t.Fatal("PerIPCountByInstance should be initialized for this instance")
	} else {
		if perIPMap[ip1] != 2 {
			t.Errorf("Expected PerIPCountByInstance[%s][%s] = 2, got %d", tracker.instanceID, ip1, perIPMap[ip1])
		}
		if perIPMap[ip2] != 3 {
			t.Errorf("Expected PerIPCountByInstance[%s][%s] = 3, got %d", tracker.instanceID, ip2, perIPMap[ip2])
		}
	}

	// Get cluster-wide count (should match local since only one instance)
	if info.GetClusterWideIPCount(ip1) != 2 {
		t.Errorf("Cluster-wide count for IP1 should be 2, got %d", info.GetClusterWideIPCount(ip1))
	}
	if info.GetClusterWideIPCount(ip2) != 3 {
		t.Errorf("Cluster-wide count for IP2 should be 3, got %d", info.GetClusterWideIPCount(ip2))
	}

	// Simulate creating a snapshot (like stateSnapshotRoutine does)
	snapshot := &ConnectionStateSnapshot{
		InstanceID:  tracker.instanceID,
		Timestamp:   time.Now(),
		Connections: make(map[int64]UserConnectionData),
	}

	// Copy PerIPCount for THIS INSTANCE ONLY (authoritative)
	perIPCount := make(map[string]int)
	if perIPMap := info.PerIPCountByInstance[tracker.instanceID]; perIPMap != nil {
		for ip, count := range perIPMap {
			if count > 0 {
				perIPCount[ip] = count
			}
		}
	}

	snapshot.Connections[accountID] = UserConnectionData{
		AccountID:  accountID,
		Username:   username,
		PerIPCount: perIPCount,
		LastUpdate: info.LastUpdate,
	}
	tracker.mu.Unlock()

	// Verify snapshot contains PerIPCount for this instance
	snapshotData := snapshot.Connections[accountID]
	if snapshotData.PerIPCount[ip1] != 2 {
		t.Errorf("Snapshot should contain PerIPCount[%s] = 2, got %d", ip1, snapshotData.PerIPCount[ip1])
	}
	if snapshotData.PerIPCount[ip2] != 3 {
		t.Errorf("Snapshot should contain PerIPCount[%s] = 3, got %d", ip2, snapshotData.PerIPCount[ip2])
	}

	// Create a second tracker and reconcile with the snapshot
	tracker2 := NewConnectionTracker("IMAP", "node-2", nil, 20, 5, 0, false)
	if tracker2 == nil {
		t.Fatal("Failed to create tracker2")
	}
	defer tracker2.Stop()

	// Reconcile snapshot (simulates receiving gossip)
	tracker2.reconcileState(snapshot)

	// Verify tracker2 now has the per-IP counts from tracker1
	tracker2.mu.Lock()
	info2 := tracker2.connections[accountID]
	if info2 == nil {
		t.Fatal("Tracker2 should have user info after reconciliation")
	}

	// Verify PerIPCountByInstance has the data from node-1 (tracker.instanceID)
	if perIPMap := info2.PerIPCountByInstance[tracker.instanceID]; perIPMap == nil {
		t.Fatal("Tracker2 should have PerIPCountByInstance for node-1 after reconciliation")
	} else {
		if perIPMap[ip1] != 2 {
			t.Errorf("After reconciliation, PerIPCountByInstance[node-1][%s] should be 2, got %d", ip1, perIPMap[ip1])
		}
		if perIPMap[ip2] != 3 {
			t.Errorf("After reconciliation, PerIPCountByInstance[node-1][%s] should be 3, got %d", ip2, perIPMap[ip2])
		}
	}

	// Verify cluster-wide counts match
	if info2.GetClusterWideIPCount(ip1) != 2 {
		t.Errorf("After reconciliation, cluster-wide count for IP1 should be 2, got %d", info2.GetClusterWideIPCount(ip1))
	}
	if info2.GetClusterWideIPCount(ip2) != 3 {
		t.Errorf("After reconciliation, cluster-wide count for IP2 should be 3, got %d", info2.GetClusterWideIPCount(ip2))
	}
	tracker2.mu.Unlock()

	t.Log("✓ Per-user-per-IP counts are included in state snapshots and reconciled correctly")
}

// TestClusterPerUserPerIP_DifferentIPsAllowed tests that different IPs can each have their own limits
func TestClusterPerUserPerIP_DifferentIPsAllowed(t *testing.T) {
	ctx := context.Background()
	accountID := int64(789)
	username := "multiip@example.com"
	protocol := "IMAP"

	tracker := NewConnectionTracker("IMAP", "node-1", nil, 50, 3, 0, false)
	if tracker == nil {
		t.Fatal("Failed to create tracker")
	}
	defer tracker.Stop()

	// User connects from 3 different IPs, each can have up to 3 connections
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}

	for _, ip := range ips {
		// Each IP can have 3 connections
		for i := 1; i <= 3; i++ {
			err := tracker.RegisterConnection(ctx, accountID, username, protocol, ip+":1000"+string(rune('0'+i)))
			if err != nil {
				t.Fatalf("Connection %d from IP %s should succeed: %v", i, ip, err)
			}
		}

		// 4th connection from same IP should fail
		err := tracker.RegisterConnection(ctx, accountID, username, protocol, ip+":10004")
		if err == nil {
			t.Errorf("4th connection from IP %s should fail", ip)
		}
	}

	// Total connections = 9 (3 IPs × 3 connections each)
	count := tracker.GetConnectionCount(accountID)
	if count != 9 {
		t.Errorf("Expected total count = 9, got %d", count)
	}

	t.Log("✓ Different IPs each get their own per-user-per-IP limits")
}
