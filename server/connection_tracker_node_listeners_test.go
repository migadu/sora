package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// newSingleNodeCluster starts a one-member cluster on a kernel-chosen loopback port.
func newSingleNodeCluster(t *testing.T, nodeID string) *cluster.Manager {
	t.Helper()
	mgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:0",
		NodeID:    nodeID,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("start cluster node %s: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown() })
	return mgr
}

// TestTrackersOfAProtocolOnOneNodeCountEachOther covers two proxy listeners of
// one protocol on one node (an IMAP proxy on 143 and one on 993). Each has its
// own tracker, and memberlist delivers neither gossip nor push/pull state to the
// node that sent it, so neither tracker heard of the other's sessions, although
// both count every other node's: the per-user limits held per listener on the
// node and cluster-wide everywhere else.
func TestTrackersOfAProtocolOnOneNodeCountEachOther(t *testing.T) {
	const (
		accountID = int64(6381)
		username  = "anna@example.com"
	)
	ctx := context.Background()

	t.Run("max_connections_per_user", func(t *testing.T) {
		node := newSingleNodeCluster(t, "node-1")
		imap := NewConnectionTracker("IMAP", "imap-proxy", "mail", "node-1-imap-proxy", node, 2, 0, 0, false)
		defer imap.Stop()
		imaps := NewConnectionTracker("IMAP", "imaps-proxy", "mail", "node-1-imaps-proxy", node, 2, 0, 0, false)
		defer imaps.Stop()
		pop3 := NewConnectionTracker("POP3", "pop3-proxy", "mail", "node-1-pop3-proxy", node, 2, 0, 0, false)
		defer pop3.Stop()

		for i := range 2 {
			if err := imap.RegisterConnection(ctx, accountID, username, "IMAP", fmt.Sprintf("192.0.2.1:%d", 40000+i)); err != nil {
				t.Fatalf("session %d on imap-proxy: %v", i+1, err)
			}
		}
		if err := imaps.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.1:41000"); err == nil {
			t.Fatal("imaps-proxy accepted a third IMAP session although imap-proxy on the same node holds 2 and max_connections_per_user = 2")
		}

		// Another protocol keeps its own count.
		if err := pop3.RegisterConnection(ctx, accountID, username, "POP3", "192.0.2.1:42000"); err != nil {
			t.Fatalf("pop3-proxy refused the account's first POP3 session: %v", err)
		}

		// A session that ends on one listener frees its place on the other.
		if err := imap.UnregisterConnection(ctx, accountID, "IMAP", "192.0.2.1:40000"); err != nil {
			t.Fatalf("unregister on imap-proxy: %v", err)
		}
		if err := imaps.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.1:41001"); err != nil {
			t.Fatalf("imaps-proxy refused a session after imap-proxy released one: %v", err)
		}
		if err := imap.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.1:40002"); err == nil {
			t.Fatal("imap-proxy accepted a third IMAP session although imaps-proxy on the same node holds 1 and it holds 1")
		}
	})

	t.Run("max_connections_per_user_per_ip", func(t *testing.T) {
		node := newSingleNodeCluster(t, "node-1")
		imap := NewConnectionTracker("IMAP", "imap-proxy", "mail", "node-1-imap-proxy", node, 0, 1, 0, false)
		defer imap.Stop()
		imaps := NewConnectionTracker("IMAP", "imaps-proxy", "mail", "node-1-imaps-proxy", node, 0, 1, 0, false)
		defer imaps.Stop()

		if err := imap.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.1:40000"); err != nil {
			t.Fatalf("first session on imap-proxy: %v", err)
		}
		if err := imaps.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.1:41000"); err == nil {
			t.Fatal("imaps-proxy accepted a second session from 192.0.2.1 although imap-proxy on the same node holds one and max_connections_per_user_per_ip = 1")
		}
		if err := imaps.RegisterConnection(ctx, accountID, username, "IMAP", "192.0.2.2:41000"); err != nil {
			t.Fatalf("imaps-proxy refused the first session from 192.0.2.2: %v", err)
		}
	})
}

func TestTrackersOfAProtocolOnOneNodeSerializeLastSlot(t *testing.T) {
	for _, perIP := range []bool{false, true} {
		t.Run(fmt.Sprintf("perIP=%t", perIP), func(t *testing.T) {
			node := newSingleNodeCluster(t, "last-slot")
			maxUser, maxIP := 1, 0
			if perIP {
				maxUser, maxIP = 0, 1
			}
			a := NewConnectionTracker("IMAP", "a", "mail", "a", node, maxUser, maxIP, 0, false)
			defer a.Stop()
			b := NewConnectionTracker("IMAP", "b", "mail", "b", node, maxUser, maxIP, 0, false)
			defer b.Stop()
			for accountID := int64(1); accountID <= 100; accountID++ {
				start := make(chan struct{})
				type result struct {
					tracker *ConnectionTracker
					addr    string
					err     error
				}
				results := make(chan result, 2)
				for i, tracker := range []*ConnectionTracker{a, b} {
					addr := []string{"[2001:db8::1]:40000", "[2001:0DB8:0:0:0:0:0:1]:40001"}[i]
					go func() {
						<-start
						results <- result{tracker, addr, tracker.RegisterConnection(context.Background(), accountID,
							"user@example.com", "IMAP", addr)}
					}()
				}
				close(start)
				first, second := <-results, <-results
				if (first.err == nil) == (second.err == nil) {
					t.Fatalf("last slot must admit exactly one listener: %v, %v", first.err, second.err)
				}
				for _, r := range []result{first, second} {
					if r.err == nil {
						if err := r.tracker.UnregisterConnection(context.Background(), accountID, "IMAP", r.addr); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			a.node.mu.Lock()
			defer a.node.mu.Unlock()
			if len(a.node.counts) != 0 {
				t.Fatalf("shared counts retain closed sessions: %v", a.node.counts)
			}
		})
	}
}
