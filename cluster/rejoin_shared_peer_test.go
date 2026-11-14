package cluster

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// TestSharedPeerEntryRejoinsLatePeer covers a peers entry that resolves to this
// node's own address alongside other nodes (such as localhost on a dual-stack
// host, or a single DNS name for the whole cluster). When the other node starts
// after this node (missing both startup Join and the first rejoinLoop round that
// caches resolved[peer]), rejoinLoop must not treat this node's own membership
// as satisfying the peer entry.
func TestSharedPeerEntryRejoinsLatePeer(t *testing.T) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
	hasAddr := func(want string) bool {
		return slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == netip.MustParseAddr(want) })
	}
	if err != nil || !hasAddr("127.0.0.1") || !hasAddr("::1") {
		t.Skipf("localhost resolves to %v (%v), want both 127.0.0.1 and ::1", addrs, err)
	}

	prev := rejoinInterval
	rejoinInterval = 60 * time.Millisecond
	t.Cleanup(func() { rejoinInterval = prev })

	port := freeDualLoopbackPort(t)
	// Start the node that lists localhost:<port> FIRST, before the ::1 peer exists,
	// and let at least two rejoinLoop ticks populate resolved[peer] while ::1 is down.
	node := startMembershipTestNode(t, "shared-v4", fmt.Sprintf("127.0.0.1:%d", port), []string{fmt.Sprintf("localhost:%d", port)})
	time.Sleep(150 * time.Millisecond)

	latePeer := startMembershipTestNode(t, "shared-v6", fmt.Sprintf("[::1]:%d", port), nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(node.GetMembers()) == 2 && len(latePeer.GetMembers()) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("shared peer entry never joined late peer: node=%+v, latePeer=%+v",
		node.GetMembers(), latePeer.GetMembers())
}

func TestPeerSatisfiedAndMissingAddrs(t *testing.T) {
	ap := netip.MustParseAddrPort

	// 4-node headless Service partitioned into {node1, node2} vs {node3, node4}.
	headless := []netip.AddrPort{
		ap("10.0.0.1:7946"),
		ap("10.0.0.2:7946"),
		ap("10.0.0.3:7946"),
		ap("10.0.0.4:7946"),
	}
	self := ap("10.0.0.1:7946")
	partitioned := map[netip.AddrPort]bool{
		ap("10.0.0.1:7946"): true,
		ap("10.0.0.2:7946"): true,
	}
	if peerSatisfied(headless, self, partitioned) {
		t.Fatal("2v2 partitioned headless DNS entry was treated as satisfied")
	}
	wantMissing := []netip.AddrPort{ap("10.0.0.3:7946"), ap("10.0.0.4:7946")}
	if got := missingPeerAddrs(headless, self, partitioned); !slices.Equal(got, wantMissing) {
		t.Fatalf("missingPeerAddrs = %v, want %v", got, wantMissing)
	}

	healed := map[netip.AddrPort]bool{
		ap("10.0.0.1:7946"): true,
		ap("10.0.0.2:7946"): true,
		ap("10.0.0.3:7946"): true,
		ap("10.0.0.4:7946"): true,
	}
	if !peerSatisfied(headless, self, healed) {
		t.Fatal("complete headless DNS entry was not treated as satisfied")
	}

	// Single dual-stack peer hostname advertising only its IPv4 address.
	dualStackPeer := []netip.AddrPort{ap("10.0.0.2:7946"), ap("[2001:db8::2]:7946")}
	if !peerSatisfied(dualStackPeer, self, partitioned) {
		t.Fatal("dual-stack single peer joined on IPv4 should be treated as satisfied")
	}
}

