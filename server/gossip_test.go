package server

import (
	"context"
	"testing"
	"time"
)

// TestGossipDedupSuppressesRetransmittedEvents covers the consequence of
// retransmission: memberlist hands the same broadcast to several targets and
// may pick the same peer twice, so a counting event that arrives more than once
// must only be applied for the first copy.
func TestGossipDedupSuppressesRetransmittedEvents(t *testing.T) {
	tracker := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer tracker.Stop()

	event := ConnectionEvent{
		Type:       ConnectionEventRegister,
		EventID:    "event-1",
		AccountID:  7,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  time.Now(),
		InstanceID: "inst-b",
	}
	encoded, err := encodeConnectionEvent(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	for i := 0; i < 3; i++ {
		tracker.HandleClusterEvent(encoded)
	}

	if got := tracker.GetConnectionCount(7); got != 1 {
		t.Errorf("retransmitted register event counted %d times, want 1", got)
	}

	// A genuinely new connection still counts.
	event.EventID = "event-2"
	event.ClientAddr = "203.0.113.5:44322"
	encoded, err = encodeConnectionEvent(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tracker.HandleClusterEvent(encoded)

	if got := tracker.GetConnectionCount(7); got != 2 {
		t.Errorf("distinct register event was suppressed: count = %d, want 2", got)
	}
}

// TestConnectionTrackerPushPullRoundTrip exercises the anti-entropy path that
// replaced the oversized gossip snapshot: a peer's full state is encoded by
// localState and applied by mergeRemoteState, including retiring connections
// the peer no longer holds.
func TestConnectionTrackerPushPullRoundTrip(t *testing.T) {
	ctx := context.Background()

	nodeA := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer nodeA.Stop()
	nodeB := NewConnectionTracker("IMAP", "", "", "inst-b", nil, 0, 0, 100, false)
	defer nodeB.Stop()

	for i := 0; i < 3; i++ {
		if err := nodeA.RegisterConnection(ctx, 42, "user@example.com", "IMAP", "203.0.113.5:44321"); err != nil {
			t.Fatalf("RegisterConnection: %v", err)
		}
	}

	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetConnectionCount(42); got != 3 {
		t.Fatalf("after push/pull nodeB has %d connections for the account, want 3", got)
	}

	// Two connections close and both unregister events are lost.
	for i := 0; i < 2; i++ {
		if err := nodeA.UnregisterConnection(ctx, 42, "IMAP", "203.0.113.5:44321"); err != nil {
			t.Fatalf("UnregisterConnection: %v", err)
		}
	}

	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetConnectionCount(42); got != 1 {
		t.Errorf("after the next push/pull nodeB has %d connections, want 1", got)
	}

	// The last one closes: an empty snapshot must retire the account entirely.
	if err := nodeA.UnregisterConnection(ctx, 42, "IMAP", "203.0.113.5:44321"); err != nil {
		t.Fatalf("UnregisterConnection: %v", err)
	}

	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetConnectionCount(42); got != 0 {
		t.Errorf("after nodeA dropped to zero, nodeB still reports %d connections", got)
	}
}

// TestPushPullStateIsFilteredByProtocol covers what replaced matching providers
// by name. A provider is registered under a name that is only unique on its own
// node, so push/pull dispatches by kind and hands every connection payload to
// every connection tracker on the receiving node. The protocol inside the
// payload is what decides whose state it is; without that filter one protocol's
// counts would land in another protocol's tracker.
func TestPushPullStateIsFilteredByProtocol(t *testing.T) {
	ctx := context.Background()

	remoteIMAP := NewConnectionTracker("IMAP", "", "", "inst-b", nil, 0, 0, 100, false)
	defer remoteIMAP.Stop()
	if err := remoteIMAP.RegisterConnection(ctx, 42, "user@example.com", "IMAP", "203.0.113.5:44321"); err != nil {
		t.Fatalf("RegisterConnection: %v", err)
	}
	state := remoteIMAP.localState()

	localIMAP := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer localIMAP.Stop()
	localPOP3 := NewConnectionTracker("POP3", "", "", "inst-a", nil, 0, 0, 100, false)
	defer localPOP3.Stop()

	localIMAP.mergeRemoteState(state)
	localPOP3.mergeRemoteState(state)

	if got := localIMAP.GetConnectionCount(42); got != 1 {
		t.Errorf("the IMAP tracker did not take the IMAP state: count = %d, want 1", got)
	}
	if got := localPOP3.GetConnectionCount(42); got != 0 {
		t.Errorf("IMAP connections were counted against POP3: count = %d, want 0", got)
	}

	remoteIPs := NewIPLimitTracker("IMAP", "inst-b", nil, 0)
	defer remoteIPs.Stop()
	remoteIPs.IncrementIP("203.0.113.9")
	ipState := remoteIPs.localState()

	localIMAPIPs := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
	defer localIMAPIPs.Stop()
	localPOP3IPs := NewIPLimitTracker("POP3", "inst-a", nil, 0)
	defer localPOP3IPs.Stop()

	localIMAPIPs.mergeRemoteState(ipState)
	localPOP3IPs.mergeRemoteState(ipState)

	if got := localIMAPIPs.GetIPCount("203.0.113.9"); got != 1 {
		t.Errorf("the IMAP tracker did not take the IMAP per-IP state: count = %d, want 1", got)
	}
	if got := localPOP3IPs.GetIPCount("203.0.113.9"); got != 0 {
		t.Errorf("IMAP per-IP counts were counted against POP3: count = %d, want 0", got)
	}
}

// TestIPLimitTrackerPushPullRoundTrip is the per-IP equivalent: a peer's own
// counts are authoritative and an IP it stops reporting is retired.
func TestIPLimitTrackerPushPullRoundTrip(t *testing.T) {
	const ip = "203.0.113.9"

	nodeA := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
	defer nodeA.Stop()
	nodeB := NewIPLimitTracker("IMAP", "inst-b", nil, 0)
	defer nodeB.Stop()

	nodeA.IncrementIP(ip)
	nodeA.IncrementIP(ip)

	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetIPCount(ip); got != 2 {
		t.Fatalf("after push/pull nodeB reports %d connections for %s, want 2", got, ip)
	}

	nodeA.DecrementIP(ip)
	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetIPCount(ip); got != 1 {
		t.Errorf("after the next push/pull nodeB reports %d for %s, want 1", got, ip)
	}

	nodeA.DecrementIP(ip)
	nodeB.mergeRemoteState(nodeA.localState())
	if got := nodeB.GetIPCount(ip); got != 0 {
		t.Errorf("after nodeA dropped to zero, nodeB still reports %d for %s", got, ip)
	}
}
