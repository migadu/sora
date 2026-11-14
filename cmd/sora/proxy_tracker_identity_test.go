package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
)

// trackerSink stands in for a proxy server: startConnectionTrackerForProxy only
// hands it the tracker.
type trackerSink struct{ tracker *server.ConnectionTracker }

func (s *trackerSink) SetConnectionTracker(t *server.ConnectionTracker) { s.tracker = t }

// newLoopbackClusterNode starts a cluster member on a kernel-chosen loopback port.
func newLoopbackClusterNode(t *testing.T, nodeID string, peers []string) *cluster.Manager {
	t.Helper()
	mgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:0",
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("start cluster node %s: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown() })
	return mgr
}

// gossipAddr returns the host:port the node is reachable on.
func gossipAddr(t *testing.T, mgr *cluster.Manager) string {
	t.Helper()
	for _, m := range mgr.GetMembers() {
		if m.Name == mgr.GetNodeID() {
			return fmt.Sprintf("%s:%d", m.Addr, m.Port)
		}
	}
	t.Fatalf("node %s is not among its own members", mgr.GetNodeID())
	return ""
}

// TestProxyTrackersOnNodesSharingAHostnameCountEachOther covers two cluster nodes
// whose operating systems report the same hostname (containers, cloned VMs) and
// that run a proxy listener under the same name. Each tracker skips events and
// snapshots that carry its own instance ID as "from self", so the ID has to
// differ between the two nodes or each one ignores the other's connections and
// max_connections_per_user is enforced per node.
func TestProxyTrackersOnNodesSharingAHostnameCountEachOther(t *testing.T) {
	const (
		hostname   = "mail"
		serverName = "imap-proxy"
		accountID  = int64(4242)
		username   = "anna@example.com"
	)

	nodeA := newLoopbackClusterNode(t, "node-a", nil)
	nodeB := newLoopbackClusterNode(t, "node-b", []string{gossipAddr(t, nodeA)})

	deadline := time.Now().Add(10 * time.Second)
	for nodeA.GetMemberCount() < 2 || nodeB.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", nodeA.GetMemberCount(), nodeB.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	clusterCfg := &config.ClusterConfig{}
	trackerA, keyA := startConnectionTrackerForProxy("IMAP", serverName, hostname, 2, 0, nodeA, clusterCfg, &trackerSink{})
	if trackerA == nil {
		t.Fatal("no tracker on node A")
	}
	defer trackerA.Stop()
	trackerB, keyB := startConnectionTrackerForProxy("IMAP", serverName, hostname, 2, 0, nodeB, clusterCfg, &trackerSink{})
	if trackerB == nil {
		t.Fatal("no tracker on node B")
	}
	defer trackerB.Stop()

	ctx := context.Background()
	for i := range 2 {
		if err := trackerA.RegisterConnection(ctx, accountID, username, "IMAP", fmt.Sprintf("192.0.2.10:%d", 40000+i)); err != nil {
			t.Fatalf("register connection %d on node A: %v", i+1, err)
		}
	}

	deadline = time.Now().Add(5 * time.Second)
	for trackerB.GetConnectionCount(accountID) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("node B counts %d of node A's 2 connections (instance IDs: A=%q B=%q, map keys: A=%q B=%q)",
				trackerB.GetConnectionCount(accountID), trackerA.GetInstanceID(), trackerB.GetInstanceID(), keyA, keyB)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := trackerB.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.11:40000"); err == nil {
		t.Fatal("node B accepted a third connection although max_connections_per_user = 2 is reached cluster-wide")
	}
}
