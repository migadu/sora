package main

import (
	"context"
	"fmt"
	"sync"
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
		accountID = int64(4242)
		username  = "anna@example.com"
	)

	trackerA, trackerB := startProxyTrackersSharingAHostname(t, 2)

	ctx := context.Background()
	for i := range 2 {
		if err := trackerA.RegisterConnection(ctx, accountID, username, "IMAP", fmt.Sprintf("192.0.2.10:%d", 40000+i)); err != nil {
			t.Fatalf("register connection %d on node A: %v", i+1, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for trackerB.GetConnectionCount(accountID) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("node B counts %d of node A's 2 connections (instance IDs: A=%q B=%q)",
				trackerB.GetConnectionCount(accountID), trackerA.GetInstanceID(), trackerB.GetInstanceID())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := trackerB.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.11:40000"); err == nil {
		t.Fatal("node B accepted a third connection although max_connections_per_user = 2 is reached cluster-wide")
	}
}

// invalidationRecorder stands in for a proxy's lookup cache.
type invalidationRecorder struct {
	mu       sync.Mutex
	accounts map[int64]bool
}

func (r *invalidationRecorder) InvalidateUser(serverName, username string) {}

func (r *invalidationRecorder) InvalidateAccount(accountID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts[accountID] = true
}

func (r *invalidationRecorder) invalidated(accountID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accounts[accountID]
}

// TestProxyTrackersOnNodesSharingAHostnameReceiveAccountEvents covers the kick
// the Admin API issues (POST /admin/connections/kick, account delete or purge)
// and the forget-logins it sends after a password change. Both go out tagged
// with the sender's instance ID and are discarded by a receiver with the same
// ID before their type is looked at, so with colliding IDs the peer keeps the
// sessions open and keeps accepting the old password from its lookup cache.
func TestProxyTrackersOnNodesSharingAHostnameReceiveAccountEvents(t *testing.T) {
	const username = "anna@example.com"

	trackerA, trackerB := startProxyTrackersSharingAHostname(t, 0)
	cacheB := &invalidationRecorder{accounts: make(map[int64]bool)}
	trackerB.SetLookupCache(cacheB)

	t.Run("kick", func(t *testing.T) {
		const accountID = int64(4343)
		session := trackerB.RegisterSession(accountID)
		defer trackerB.UnregisterSession(accountID, session)

		if err := trackerA.KickUser(accountID, "IMAP"); err != nil {
			t.Fatalf("kick on node A: %v", err)
		}
		select {
		case <-session:
		case <-time.After(5 * time.Second):
			t.Fatalf("node B kept the session open after node A's kick (instance IDs: A=%q B=%q)",
				trackerA.GetInstanceID(), trackerB.GetInstanceID())
		}
	})

	t.Run("forget-logins", func(t *testing.T) {
		const accountID = int64(4444)
		if err := trackerA.ForgetLogins(accountID, username); err != nil {
			t.Fatalf("forget logins on node A: %v", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !cacheB.invalidated(accountID) {
			if time.Now().After(deadline) {
				t.Fatalf("node B kept its cached logins after node A's forget-logins (instance IDs: A=%q B=%q)",
					trackerA.GetInstanceID(), trackerB.GetInstanceID())
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// startProxyTrackersSharingAHostname starts two cluster members with distinct
// node IDs on loopback and an IMAP proxy tracker on each, both started with the
// same hostname and the same listener name.
func startProxyTrackersSharingAHostname(t *testing.T, maxPerUser int) (trackerA, trackerB *server.ConnectionTracker) {
	t.Helper()
	const (
		hostname   = "mail"
		serverName = "imap-proxy"
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
	trackerA, _ = startConnectionTrackerForProxy("IMAP", serverName, hostname, maxPerUser, 0, nodeA, clusterCfg, nil, &trackerSink{})
	if trackerA == nil {
		t.Fatal("no tracker on node A")
	}
	t.Cleanup(trackerA.Stop)
	trackerB, _ = startConnectionTrackerForProxy("IMAP", serverName, hostname, maxPerUser, 0, nodeB, clusterCfg, nil, &trackerSink{})
	if trackerB == nil {
		t.Fatal("no tracker on node B")
	}
	t.Cleanup(trackerB.Stop)
	return trackerA, trackerB
}
