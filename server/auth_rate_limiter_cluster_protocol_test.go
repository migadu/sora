package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// startRateLimitTestMember starts a cluster member on a kernel-chosen loopback port.
func startRateLimitTestMember(t *testing.T, nodeID string, peers []string) *cluster.Manager {
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

func rateLimitTestGossipAddr(t *testing.T, mgr *cluster.Manager) string {
	t.Helper()
	for _, m := range mgr.GetMembers() {
		if m.Name == mgr.GetNodeID() {
			return net.JoinHostPort(m.Addr, fmt.Sprint(m.Port))
		}
	}
	t.Fatalf("node %s is not among its own members", mgr.GetNodeID())
	return ""
}

func newClusteredTestLimiter(t *testing.T, protocol string, mgr *cluster.Manager) *AuthRateLimiter {
	t.Helper()
	limiter := NewAuthRateLimiter(protocol, "", "", AuthRateLimiterConfig{
		Enabled:             true,
		MaxAttemptsPerIP:    2,
		IPBlockDuration:     time.Minute,
		DelayStartThreshold: 100,
		CleanupInterval:     time.Hour,
	})
	t.Cleanup(limiter.Stop)
	limiter.SetClusterLimiter(NewClusterRateLimiter(limiter, mgr, true, true))
	return limiter
}

// TestClusterRateLimitEventsStayWithinTheirProtocol: every limiter on a node
// receives every rate-limit event of the cluster, as the gossip channel is shared.
// A node's limiters are independent of each other (an IMAP failure does not count
// against POP3 on the same node), so a peer's limiter of another protocol must
// not apply the event either; otherwise an IMAP block lands on POP3 everywhere
// but on the node that saw the failures.
func TestClusterRateLimitEventsStayWithinTheirProtocol(t *testing.T) {
	nodeA := startRateLimitTestMember(t, "rl-protocol-a", nil)
	nodeB := startRateLimitTestMember(t, "rl-protocol-b", []string{rateLimitTestGossipAddr(t, nodeA)})

	deadline := time.Now().Add(10 * time.Second)
	for nodeA.GetMemberCount() < 2 || nodeB.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", nodeA.GetMemberCount(), nodeB.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	imapA := newClusteredTestLimiter(t, "IMAP-PROXY", nodeA)
	imapB := newClusteredTestLimiter(t, "IMAP-PROXY", nodeB)
	pop3B := newClusteredTestLimiter(t, "POP3-PROXY", nodeB)

	client := &StringAddr{Addr: "192.0.2.20:40000"}
	ctx := context.Background()
	for range 2 {
		imapA.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	if !imapA.IsIPBlocked(client) {
		t.Fatal("node A's IMAP limiter did not block the address after 2 failures")
	}

	deadline = time.Now().Add(5 * time.Second)
	for !imapB.IsIPBlocked(client) {
		if time.Now().After(deadline) {
			t.Fatal("node A's IMAP block never reached node B's IMAP limiter")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if pop3B.IsIPBlocked(client) {
		t.Error("node A's IMAP block was applied to node B's POP3 limiter")
	}
	if got := pop3B.getUsernameFailureCount("anna@example.com"); got != 0 {
		t.Errorf("node B's POP3 limiter counts %d IMAP login failures from node A", got)
	}
}
