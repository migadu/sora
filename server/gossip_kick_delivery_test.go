package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

func newKickTestCluster(nodeID string, port int, peers []string) (*cluster.Manager, error) {
	return cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", port),
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	})
}

// TestKickReachesAPeerSession is the end-to-end kick path: an operator kicks on
// one node and a session held on another node is closed.
//
// The tracker names the event with its own protocol. Callers pass whatever they
// index the tracker by - the admin API passes "IMAP-hostname-listener" - and
// receivers discard any event whose protocol is not exactly their own, so a
// kick tagged with the caller's key would be dropped by every peer.
func TestKickReachesAPeerSession(t *testing.T) {
	const accountID int64 = 42

	clusterA, err := newKickTestCluster("kick-node-1", 25946, nil)
	if err != nil {
		t.Fatalf("create cluster A: %v", err)
	}
	defer clusterA.Shutdown()

	clusterB, err := newKickTestCluster("kick-node-2", 25947, []string{"127.0.0.1:25946"})
	if err != nil {
		t.Fatalf("create cluster B: %v", err)
	}
	defer clusterB.Shutdown()

	deadline := time.Now().Add(10 * time.Second)
	for clusterA.GetMemberCount() < 2 || clusterB.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", clusterA.GetMemberCount(), clusterB.GetMemberCount())
		}
		time.Sleep(50 * time.Millisecond)
	}

	trackerA := NewConnectionTracker("IMAP", "listener-a", "host-a", "host-a-listener-a", clusterA, 0, 0, 100, false)
	defer trackerA.Stop()
	trackerB := NewConnectionTracker("IMAP", "listener-b", "host-b", "host-b-listener-b", clusterB, 0, 0, 100, false)
	defer trackerB.Stop()

	kicked := trackerB.RegisterSession(accountID)

	if err := trackerA.KickUser(accountID, "IMAP-host-a-listener-a"); err != nil {
		t.Fatalf("KickUser: %v", err)
	}

	select {
	case <-kicked:
	case <-time.After(10 * time.Second):
		t.Fatal("a session on the peer node was never kicked")
	}
}

// TestKickClosesSessionsOnTheIssuingNode covers the node the operator issued the
// kick from. Gossip never loops a broadcast back, the reliable fan-out skips
// self, and HandleClusterEvent discards events from this instance, so nothing
// closes the sessions held here unless KickUser does it directly.
func TestKickClosesSessionsOnTheIssuingNode(t *testing.T) {
	const accountID int64 = 42

	clusterMgr, err := newKickTestCluster("kick-node-local", 25948, nil)
	if err != nil {
		t.Fatalf("create cluster: %v", err)
	}
	defer clusterMgr.Shutdown()

	tracker := NewConnectionTracker("IMAP", "listener-a", "host-a", "host-a-listener-a", clusterMgr, 0, 0, 100, false)
	defer tracker.Stop()

	kicked := tracker.RegisterSession(accountID)

	if err := tracker.KickUser(accountID, "IMAP-host-a-listener-a"); err != nil {
		t.Fatalf("KickUser: %v", err)
	}

	select {
	case <-kicked:
	case <-time.After(5 * time.Second):
		t.Fatal("a session on the node that issued the kick was never closed")
	}
}
