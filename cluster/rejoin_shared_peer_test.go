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
