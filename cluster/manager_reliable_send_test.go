package cluster

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/migadu/sora/config"
)

// A kick must not be left to the epidemic. TransmitLimitedQueue retires a
// broadcast after retransmitMult*log10(N+1) transmissions with no
// acknowledgement, so in a cluster of a dozen nodes a given peer has a real
// chance of never being handed the message - and a peer that misses a kick
// keeps a session alive that was supposed to be closed everywhere.

func TestFanOutReliableSkipsSelfAndCountsOutcomes(t *testing.T) {
	members := []*memberlist.Node{
		{Name: "node-1"},
		{Name: "node-2"},
		{Name: "node-3"},
	}

	var mu sync.Mutex
	var targets []string
	delivered, failed := fanOutReliable(members, "node-1", func(node *memberlist.Node, msg []byte) error {
		mu.Lock()
		targets = append(targets, node.Name)
		mu.Unlock()

		if node.Name == "node-3" {
			return errors.New("connection refused")
		}
		if string(msg) != "kick" {
			t.Errorf("peer %s received %q, want %q", node.Name, msg, "kick")
		}
		return nil
	}, []byte("kick"))

	if delivered != 1 || failed != 1 {
		t.Errorf("delivered=%d failed=%d, want 1 and 1", delivered, failed)
	}
	for _, target := range targets {
		if target == "node-1" {
			t.Error("the sender sent the message to itself")
		}
	}
}

// TestSendConnectionEventReliableReachesEveryMember runs the real path: TCP to
// each peer, the connection marker, and the peer's registered handler.
func TestSendConnectionEventReliableReachesEveryMember(t *testing.T) {
	nodeA, err := newTestClusterNode("reliable-node-1", 26946, nil)
	if err != nil {
		t.Fatalf("create node A: %v", err)
	}
	defer nodeA.Shutdown()

	nodeB, err := newTestClusterNode("reliable-node-2", 26947, []string{"127.0.0.1:26946"})
	if err != nil {
		t.Fatalf("create node B: %v", err)
	}
	defer nodeB.Shutdown()

	waitForMembers(t, nodeA, 2)
	waitForMembers(t, nodeB, 2)

	received := make(chan []byte, 4)
	nodeB.RegisterConnectionHandler(func(data []byte) { received <- data })

	delivered, failed := nodeA.SendConnectionEventReliable([]byte("kick account 42"))
	if delivered != 1 || failed != 0 {
		t.Errorf("delivered=%d failed=%d, want 1 and 0", delivered, failed)
	}

	select {
	case got := <-received:
		if string(got) != "kick account 42" {
			t.Errorf("peer received %q, want %q", got, "kick account 42")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the kick never reached the peer's connection handler")
	}
}

func newTestClusterNode(nodeID string, port int, peers []string) (*Manager, error) {
	return New(config.ClusterConfig{
		Enabled:   true,
		Addr:      fmt.Sprintf("127.0.0.1:%d", port),
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	})
}

func waitForMembers(t *testing.T, m *Manager, want int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m.GetMemberCount() >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("cluster did not reach %d members (have %d)", want, m.GetMemberCount())
}
