package server

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// newNodeLimiter builds a proxy listener's connection limiter on node the way
// the proxies do in cluster mode.
func newNodeLimiter(t *testing.T, node *cluster.Manager, protocol, instanceID string, maxPerIP int) *ConnectionLimiter {
	t.Helper()
	cl := NewConnectionLimiterWithCluster(protocol, instanceID, node, 0, maxPerIP, nil)
	if cl.ipTracker == nil {
		t.Fatalf("%s: no cluster-wide per-IP tracker", instanceID)
	}
	t.Cleanup(cl.ipTracker.Stop)
	return cl
}

// TestConnectionLimitersOfAProtocolOnOneNodeCountEachOther covers two proxy
// listeners of one protocol on one node (an IMAP proxy on 143 and one on 993).
// Each has its own per-IP tracker, and memberlist delivers neither gossip nor
// push/pull state to the node that sent it, so neither tracker heard of the
// other's connections, although both count every other node's:
// max_connections_per_ip held per listener on the node and cluster-wide
// everywhere else.
func TestConnectionLimitersOfAProtocolOnOneNodeCountEachOther(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
	loadBalancer := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 50000}

	t.Run("max_connections_per_ip", func(t *testing.T) {
		node := newSingleNodeCluster(t, "node-1")
		imap := newNodeLimiter(t, node, "IMAP-PROXY", "imap-proxy-node-1-1", 1)
		imaps := newNodeLimiter(t, node, "IMAP-PROXY", "imap-proxy-node-1-2", 1)
		pop3 := newNodeLimiter(t, node, "POP3-PROXY", "pop3-proxy-node-1-1", 1)

		release, err := imap.AcceptWithRealIP(client, "")
		if err != nil {
			t.Fatalf("imap-proxy refused the first connection from 192.0.2.1: %v", err)
		}
		if err := imaps.CanAcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
			t.Fatalf("imaps-proxy pre-check = %v, want %v: imap-proxy on the same node holds one connection from 192.0.2.1", err, ErrMaxConnectionsPerIP)
		}
		if _, err := imaps.AcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
			t.Fatalf("imaps-proxy accept = %v, want %v: imap-proxy on the same node holds one connection from 192.0.2.1 and max_connections_per_ip = 1", err, ErrMaxConnectionsPerIP)
		}
		// The same client named by a PROXY header, in another spelling.
		if _, err := imaps.AcceptWithRealIP(loadBalancer, "::ffff:192.0.2.1"); !errors.Is(err, ErrMaxConnectionsPerIP) {
			t.Fatalf("imaps-proxy accept for PROXY client ::ffff:192.0.2.1 = %v, want %v", err, ErrMaxConnectionsPerIP)
		}

		// Another IP has its own place, and another protocol its own count.
		if _, err := imaps.AcceptWithRealIP(&net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40001}, ""); err != nil {
			t.Fatalf("imaps-proxy refused the first connection from 192.0.2.2: %v", err)
		}
		if _, err := pop3.AcceptWithRealIP(client, ""); err != nil {
			t.Fatalf("pop3-proxy refused the first POP3 connection from 192.0.2.1: %v", err)
		}

		// A connection that ends on one listener frees its place on the other.
		release()
		if _, err := imaps.AcceptWithRealIP(client, ""); err != nil {
			t.Fatalf("imaps-proxy refused 192.0.2.1 after imap-proxy released its connection: %v", err)
		}
		if _, err := imap.AcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
			t.Fatalf("imap-proxy accept = %v, want %v: imaps-proxy on the same node now holds the connection from 192.0.2.1", err, ErrMaxConnectionsPerIP)
		}
	})

	// Another node's connections reach each listener of this node once over
	// gossip, so they count once, and this node's listeners count on top.
	t.Run("with another node", func(t *testing.T) {
		node := newSingleNodeCluster(t, "node-1")
		imap := newNodeLimiter(t, node, "IMAP-PROXY", "imap-proxy-node-1-1", 3)
		imaps := newNodeLimiter(t, node, "IMAP-PROXY", "imap-proxy-node-1-2", 3)
		for _, cl := range []*ConnectionLimiter{imap, imaps} {
			deliverIncrement(t, cl.ipTracker, "imap-proxy-node-2-1", "IMAP-PROXY", "192.0.2.1", time.Now())
		}

		if _, err := imap.AcceptWithRealIP(client, ""); err != nil {
			t.Fatalf("imap-proxy refused the second connection from 192.0.2.1 (limit 3): %v", err)
		}
		if _, err := imaps.AcceptWithRealIP(client, ""); err != nil {
			t.Fatalf("imaps-proxy refused the third connection from 192.0.2.1 (limit 3): %v", err)
		}
		for name, cl := range map[string]*ConnectionLimiter{"imap-proxy": imap, "imaps-proxy": imaps} {
			if got := cl.ipTracker.GetIPCount("192.0.2.1"); got != 3 {
				t.Errorf("%s counts %d connections from 192.0.2.1, want 3 (node-2: 1, imap-proxy: 1, imaps-proxy: 1)", name, got)
			}
			if _, err := cl.AcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
				t.Errorf("%s accept = %v, want %v: node-2, imap-proxy and imaps-proxy hold one connection each from 192.0.2.1, max_connections_per_ip = 3", name, err, ErrMaxConnectionsPerIP)
			}
		}
	})
}

// TestConnectionLimitersOfAProtocolOnOneNodeSerializeLastPlace races two
// listeners of one protocol on one node for the last place of an IP: exactly
// one may take it, and the shared count must not keep a closed connection.
func TestConnectionLimitersOfAProtocolOnOneNodeSerializeLastPlace(t *testing.T) {
	node := newSingleNodeCluster(t, "last-ip-place")
	a := newNodeLimiter(t, node, "IMAP-PROXY", "a", 1)
	b := newNodeLimiter(t, node, "IMAP-PROXY", "b", 1)
	loadBalancer := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 50000}

	type result struct {
		release func()
		err     error
	}
	for i := range 100 {
		start := make(chan struct{})
		results := make(chan result, 2)
		for j, cl := range []*ConnectionLimiter{a, b} {
			client := []string{"2001:db8::1", "2001:0DB8:0:0:0:0:0:1"}[j]
			go func() {
				<-start
				release, err := cl.AcceptWithRealIP(loadBalancer, client)
				results <- result{release, err}
			}()
		}
		close(start)
		first, second := <-results, <-results
		if (first.err == nil) == (second.err == nil) {
			t.Fatalf("round %d: the last place must go to exactly one listener: %v, %v", i, first.err, second.err)
		}
		for _, r := range []result{first, second} {
			if r.err == nil {
				r.release()
			} else if !errors.Is(r.err, ErrMaxConnectionsPerIP) {
				t.Fatalf("round %d: refusal = %v, want %v", i, r.err, ErrMaxConnectionsPerIP)
			}
		}
	}

	for name, cl := range map[string]*ConnectionLimiter{"a": a, "b": b} {
		if got := cl.ipTracker.GetIPCount("2001:db8::1"); got != 0 {
			t.Errorf("%s counts %d connections from 2001:db8::1 after every one closed", name, got)
		}
	}
}

// TestConnectionLimitersOfAProtocolOnTwoNodesShareTheLimit runs two cluster
// nodes over real gossip, each with two IMAP proxy listeners and
// max_connections_per_ip = 3. Each node must count the other node's
// connections once, not once per listener of its own, and its own other
// listener's on top.
func TestConnectionLimitersOfAProtocolOnTwoNodesShareTheLimit(t *testing.T) {
	nodeA := newSingleNodeCluster(t, "node-a")
	var addrA string
	for _, m := range nodeA.GetMembers() {
		addrA = net.JoinHostPort(m.Addr, strconv.Itoa(int(m.Port)))
	}
	nodeB, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:0",
		NodeID:    "node-b",
		Peers:     []string{addrA},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("start cluster node node-b: %v", err)
	}
	t.Cleanup(func() { _ = nodeB.Shutdown() })
	for deadline := time.Now().Add(10 * time.Second); nodeA.GetMemberCount() < 2 || nodeB.GetMemberCount() < 2; {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", nodeA.GetMemberCount(), nodeB.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	imapA := newNodeLimiter(t, nodeA, "IMAP-PROXY", "imap-proxy-a-1", 3)
	imapsA := newNodeLimiter(t, nodeA, "IMAP-PROXY", "imap-proxy-a-2", 3)
	imapB := newNodeLimiter(t, nodeB, "IMAP-PROXY", "imap-proxy-b-1", 3)
	imapsB := newNodeLimiter(t, nodeB, "IMAP-PROXY", "imap-proxy-b-2", 3)

	const ip = "192.0.2.1"
	client := &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}
	waitForCount := func(name string, cl *ConnectionLimiter, n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for cl.ipTracker.GetIPCount(ip) < n {
			if time.Now().After(deadline) {
				t.Fatalf("%s counts %d connections from %s, want %d", name, cl.ipTracker.GetIPCount(ip), ip, n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Node A: one connection on each listener.
	if _, err := imapA.AcceptWithRealIP(client, ""); err != nil {
		t.Fatalf("connection 1 on node A:143: %v", err)
	}
	if _, err := imapsA.AcceptWithRealIP(client, ""); err != nil {
		t.Fatalf("connection 2 on node A:993: %v", err)
	}
	waitForCount("node B:143", imapB, 2)
	waitForCount("node B:993", imapsB, 2)

	// Node B counts node A's two connections once, not once per listener of its own.
	if _, err := imapB.AcceptWithRealIP(client, ""); err != nil {
		t.Fatalf("node B:143 refused the third connection from %s (limit 3): %v", ip, err)
	}
	// ...and its own other listener's connection as well.
	if _, err := imapsB.AcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
		t.Fatalf("node B:993 accept = %v, want %v: node A holds 2 and node B:143 holds 1, max_connections_per_ip = 3", err, ErrMaxConnectionsPerIP)
	}

	// Node A, once node B's connection reaches it, refuses on both listeners.
	// Each listener's tracker applies gossip on a goroutine of its own, so the
	// event can reach one listener before the other: wait for both.
	waitForCount("node A:143", imapA, 3)
	waitForCount("node A:993", imapsA, 3)
	for name, cl := range map[string]*ConnectionLimiter{"node A:143": imapA, "node A:993": imapsA} {
		if _, err := cl.AcceptWithRealIP(client, ""); !errors.Is(err, ErrMaxConnectionsPerIP) {
			t.Errorf("%s accept = %v, want %v: node A:143, node A:993 and node B:143 hold one each, max_connections_per_ip = 3", name, err, ErrMaxConnectionsPerIP)
		}
	}
}
