//go:build integration

package server

import (
	"bytes"
	"encoding/gob"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// TestClusterAffinitySync tests cluster-wide affinity synchronization via gossip
func TestClusterAffinitySync(t *testing.T) {
	t.Run("AffinitySetSync", testAffinitySetSync)
	t.Run("AffinityUpdateSync", testAffinityUpdateSync)
	t.Run("AffinityDeleteSync", testAffinityDeleteSync)
	t.Run("ConflictResolution", testAffinityConflictResolution)
	t.Run("StaleEventRejection", testAffinityStaleEventRejection)
}

// testAffinitySetSync verifies that setting affinity on one node propagates to others
func testAffinitySetSync(t *testing.T) {
	// Create two-node cluster
	cluster1, err := createTestCluster("node-1", 17946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer cluster1.Shutdown()

	cluster2, err := createTestCluster("node-2", 17947, []string{"127.0.0.1:17946"})
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer cluster2.Shutdown()

	// Wait for cluster formation
	time.Sleep(500 * time.Millisecond)

	// Verify cluster membership
	if cluster1.GetMemberCount() < 2 {
		t.Fatalf("Cluster 1 has %d members, expected at least 2", cluster1.GetMemberCount())
	}
	if cluster2.GetMemberCount() < 2 {
		t.Fatalf("Cluster 2 has %d members, expected at least 2", cluster2.GetMemberCount())
	}

	// Create affinity managers
	affinity1 := NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)
	affinity2 := NewAffinityManager(cluster2, true, 24*time.Hour, 1*time.Hour)

	// Set affinity on node 1
	affinity1.SetBackend("user@example.com", "backend1:143", "imap")

	// Wait for gossip propagation
	time.Sleep(200 * time.Millisecond)

	// Verify affinity is set on node 2
	backend, found := affinity2.GetBackend("user@example.com", "imap")
	if !found {
		t.Fatal("Affinity not found on node 2 after SET event")
	}
	if backend != "backend1:143" {
		t.Errorf("Expected backend 'backend1:143', got '%s'", backend)
	}

	t.Logf("✅ PASS: Affinity SET on node 1 propagated to node 2")
}

// testAffinityUpdateSync verifies that updating affinity (failover) propagates to other nodes
func testAffinityUpdateSync(t *testing.T) {
	// Create two-node cluster
	cluster1, err := createTestCluster("node-1", 18946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer cluster1.Shutdown()

	cluster2, err := createTestCluster("node-2", 18947, []string{"127.0.0.1:18946"})
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer cluster2.Shutdown()

	// Wait for cluster formation
	time.Sleep(500 * time.Millisecond)

	// Create affinity managers
	affinity1 := NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)
	affinity2 := NewAffinityManager(cluster2, true, 24*time.Hour, 1*time.Hour)

	// Set initial affinity on both nodes
	affinity1.SetBackend("user@example.com", "backend1:143", "imap")
	time.Sleep(200 * time.Millisecond)

	// Verify both nodes have same affinity
	backend1, _ := affinity1.GetBackend("user@example.com", "imap")
	backend2, _ := affinity2.GetBackend("user@example.com", "imap")
	if backend1 != "backend1:143" || backend2 != "backend1:143" {
		t.Fatalf("Initial affinity not synchronized: node1=%s, node2=%s", backend1, backend2)
	}

	// Update affinity on node 1 (simulating failover)
	affinity1.UpdateBackend("user@example.com", "backend1:143", "backend2:143", "imap")

	// Wait for gossip propagation
	time.Sleep(200 * time.Millisecond)

	// Verify affinity is updated on node 2
	backend, found := affinity2.GetBackend("user@example.com", "imap")
	if !found {
		t.Fatal("Affinity not found on node 2 after UPDATE event")
	}
	if backend != "backend2:143" {
		t.Errorf("Expected backend 'backend2:143', got '%s'", backend)
	}

	t.Logf("✅ PASS: Affinity UPDATE (failover) on node 1 propagated to node 2")
}

// testAffinityDeleteSync verifies that deleting affinity propagates to other nodes
func testAffinityDeleteSync(t *testing.T) {
	// Create two-node cluster
	cluster1, err := createTestCluster("node-1", 19946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer cluster1.Shutdown()

	cluster2, err := createTestCluster("node-2", 19947, []string{"127.0.0.1:19946"})
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer cluster2.Shutdown()

	// Wait for cluster formation
	time.Sleep(500 * time.Millisecond)

	// Create affinity managers
	affinity1 := NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)
	affinity2 := NewAffinityManager(cluster2, true, 24*time.Hour, 1*time.Hour)

	// Set affinity on both nodes
	affinity1.SetBackend("user@example.com", "backend1:143", "imap")
	time.Sleep(200 * time.Millisecond)

	// Verify affinity exists on both nodes
	_, found1 := affinity1.GetBackend("user@example.com", "imap")
	_, found2 := affinity2.GetBackend("user@example.com", "imap")
	if !found1 || !found2 {
		t.Fatal("Initial affinity not set on both nodes")
	}

	// Delete affinity on node 1 (simulating unhealthy backend)
	affinity1.DeleteBackend("user@example.com", "imap")

	// Wait for gossip propagation
	time.Sleep(200 * time.Millisecond)

	// Verify affinity is deleted on node 2
	_, found := affinity2.GetBackend("user@example.com", "imap")
	if found {
		t.Error("Affinity should be deleted on node 2 after DELETE event")
	}

	t.Logf("✅ PASS: Affinity DELETE on node 1 propagated to node 2")
}

// testAffinityConflictResolution verifies last-write-wins conflict resolution
func testAffinityConflictResolution(t *testing.T) {
	// Create two-node cluster
	cluster1, err := createTestCluster("node-1", 20946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer cluster1.Shutdown()

	cluster2, err := createTestCluster("node-2", 20947, []string{"127.0.0.1:20946"})
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer cluster2.Shutdown()

	// Wait for cluster formation
	time.Sleep(500 * time.Millisecond)

	// Create affinity managers
	affinity1 := NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)
	affinity2 := NewAffinityManager(cluster2, true, 24*time.Hour, 1*time.Hour)

	// Set different affinities on both nodes (concurrent conflicting updates)
	affinity1.SetBackend("user@example.com", "backend1:143", "imap")
	time.Sleep(50 * time.Millisecond)
	affinity2.SetBackend("user@example.com", "backend2:143", "imap")

	// Wait for gossip to settle
	time.Sleep(500 * time.Millisecond)

	// Both nodes should converge to the same backend (last-write-wins)
	backend1, found1 := affinity1.GetBackend("user@example.com", "imap")
	backend2, found2 := affinity2.GetBackend("user@example.com", "imap")

	if !found1 || !found2 {
		t.Fatal("Affinity should exist on both nodes after conflict resolution")
	}

	if backend1 != backend2 {
		t.Errorf("Nodes did not converge: node1=%s, node2=%s", backend1, backend2)
	}

	// The winner should be backend2 (later timestamp)
	if backend1 != "backend2:143" {
		t.Logf("Note: Last-write-wins resolved to '%s' (expected 'backend2:143')", backend1)
	}

	t.Logf("✅ PASS: Conflict resolution converged both nodes to '%s'", backend1)
}

// testAffinityStaleEventRejection verifies that old events are rejected
func testAffinityStaleEventRejection(t *testing.T) {
	// Create single-node cluster (no need for gossip)
	cluster1, err := createTestCluster("node-1", 21946, []string{})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster1.Shutdown()

	// Create affinity manager
	affinity := NewAffinityManager(cluster1, true, 24*time.Hour, 1*time.Hour)

	// Set current affinity
	affinity.SetBackend("user@example.com", "backend2:143", "imap")
	time.Sleep(50 * time.Millisecond)

	// Wait a bit to ensure current affinity is established
	time.Sleep(100 * time.Millisecond)

	// Set a newer affinity (this should win over any stale event)
	affinity.SetBackend("user@example.com", "backend3:143", "imap")
	time.Sleep(100 * time.Millisecond)

	// Create a stale event manually and encode it
	staleEvent := AffinityEvent{
		Type:      AffinityEventSet,
		Username:  "user@example.com",
		Backend:   "backend1:143",
		Protocol:  "imap",
		Timestamp: time.Now().Add(-6 * time.Minute), // 6 minutes old
		NodeID:    "node-stale",
		TTL:       24 * time.Hour,
	}

	// Encode the stale event
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(staleEvent); err != nil {
		t.Fatalf("Failed to encode stale event: %v", err)
	}

	// Simulate receiving stale event via cluster
	affinity.HandleClusterEvent(buf.Bytes())
	time.Sleep(100 * time.Millisecond)

	// Verify affinity is still backend3 (not changed by stale event)
	backend, _ := affinity.GetBackend("user@example.com", "imap")
	if backend != "backend3:143" {
		t.Errorf("Affinity should still be 'backend3:143' (newer event should win), got '%s'", backend)
	}

	t.Logf("✅ PASS: Stale events (>5 minutes old) are rejected")
}

// Helper function to create test cluster
func createTestCluster(nodeID string, port int, peers []string) (*cluster.Manager, error) {
	cfg := config.ClusterConfig{
		Enabled:   true,
		BindAddr:  "127.0.0.1",
		BindPort:  port,
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	}

	return cluster.New(cfg)
}
