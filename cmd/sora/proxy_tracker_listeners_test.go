package main

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
)

// TestProxyListenersOfANodeShareTheUserLimit covers two cluster nodes that each
// run two IMAP proxy listeners (143 and 993), started the way main starts them,
// with max_connections_per_user = 3. A tracker hears of the sessions of both
// listeners of every other node, but memberlist does not deliver gossip back to
// the node that sent it, so it never heard of the other listener of its own
// node: an account could hold the limit on each listener of a node, and a
// session counted against the limit on the other node was not counted on its own.
// The other node's sessions must also be counted once, not once per listener.
func TestProxyListenersOfANodeShareTheUserLimit(t *testing.T) {
	const (
		accountID = int64(6382)
		username  = "anna@example.com"
	)
	ctx := context.Background()

	nodeA := newLoopbackClusterNode(t, "node-a", nil)
	nodeB := newLoopbackClusterNode(t, "node-b", []string{gossipAddr(t, nodeA)})
	deadline := time.Now().Add(10 * time.Second)
	for nodeA.GetMemberCount() < 2 || nodeB.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", nodeA.GetMemberCount(), nodeB.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	startListener := func(node *cluster.Manager, serverName string) *server.ConnectionTracker {
		t.Helper()
		tracker, _ := startConnectionTrackerForProxy("IMAP", serverName, "mail", 3, 0, node, &config.ClusterConfig{}, &trackerSink{})
		if tracker == nil {
			t.Fatalf("no tracker for %s on %s", serverName, node.GetNodeID())
		}
		t.Cleanup(tracker.Stop)
		return tracker
	}
	imapA, imapsA := startListener(nodeA, "imap-proxy"), startListener(nodeA, "imaps-proxy")
	imapB, imapsB := startListener(nodeB, "imap-proxy"), startListener(nodeB, "imaps-proxy")

	register := func(tracker *server.ConnectionTracker, clientAddr string) error {
		return tracker.RegisterConnection(ctx, accountID, username, "IMAP", clientAddr)
	}
	// waitForCount waits until tracker counts n of the account's sessions on its
	// own listener and on other nodes.
	waitForCount := func(tracker *server.ConnectionTracker, n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for tracker.GetConnectionCount(accountID) < n {
			if time.Now().After(deadline) {
				t.Fatalf("%s counts %d of the account's sessions, want %d", tracker.GetInstanceID(), tracker.GetConnectionCount(accountID), n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Node A: one session on each listener.
	if err := register(imapA, "192.0.2.10:40000"); err != nil {
		t.Fatalf("session 1 on node A:143: %v", err)
	}
	if err := register(imapsA, "192.0.2.10:40001"); err != nil {
		t.Fatalf("session 2 on node A:993: %v", err)
	}
	waitForCount(imapB, 2)
	waitForCount(imapsB, 2)

	// Node B counts node A's two sessions once, not once per listener of its own.
	if err := register(imapB, "192.0.2.11:40000"); err != nil {
		t.Fatalf("node B:143 refused the account's third session (limit 3): %v", err)
	}
	// ...and its own listener's session as well.
	if err := register(imapsB, "192.0.2.11:40001"); err == nil {
		t.Fatal("node B:993 accepted a fourth session: node A holds 2 and node B:143 holds 1, max_connections_per_user = 3")
	}

	// Node A, once node B's session reaches it, counts its own other listener too.
	waitForCount(imapA, 2)
	if err := register(imapA, "192.0.2.10:40002"); err == nil {
		t.Fatal("node A:143 accepted a fourth session: it holds 1, node A:993 holds 1 and node B:143 holds 1, max_connections_per_user = 3")
	}
}
