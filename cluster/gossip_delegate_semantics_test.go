package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
)

// Companion to server/gossip_broadcast_fanout_test.go, which asserts the same
// contract on the production broadcast sources.
//
// These tests pin down that
// (a) memberlist's own queue replays a broadcast across many GetBroadcasts calls,
// (b) sora's clusterDelegate is a stateless pass-through, so the replay layer has
//     to live in each registered broadcast source (see
//     server/gossip_broadcast_fanout_test.go, which asserts that it does), and
// (c) the push/pull anti-entropy hooks carry the state of registered providers,
//     so a peer's full state is reconciled over TCP rather than over gossip.

// oneShotBroadcast is a memberlist.Broadcast holding a single payload.
type oneShotBroadcast struct{ msg []byte }

func (b *oneShotBroadcast) Invalidates(memberlist.Broadcast) bool { return false }
func (b *oneShotBroadcast) Message() []byte                       { return b.msg }
func (b *oneShotBroadcast) Finished()                             {}

// TestMemberlistTransmitLimitedQueue_ReplaysAcrossCallsInARound documents the
// contract every broadcast source on this bus has to honour.
//
// memberlist calls Delegate.GetBroadcasts once per gossip TARGET NODE
// (state.go gossip(): `for _, node := range kNodes { msgs := m.getBroadcasts(...) }`,
// kNodes = GossipNodes, LAN default 3), plus opportunistically from sendMsg() to
// piggyback on pings. A correct broadcast source must therefore be replayable:
// TransmitLimitedQueue returns the same message on every call until its transmit
// counter exceeds RetransmitMult * log(NumNodes+1).
func TestMemberlistTransmitLimitedQueue_ReplaysAcrossCallsInARound(t *testing.T) {
	q := &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return 3 },
		RetransmitMult: 4,
	}
	q.QueueBroadcast(&oneShotBroadcast{msg: []byte("kick user 42")})

	const gossipNodes = 3
	counts := make([]int, gossipNodes)
	for i := range counts {
		counts[i] = len(q.GetBroadcasts(2, 65535))
	}

	for i, got := range counts {
		if got != 1 {
			t.Errorf("TransmitLimitedQueue: call #%d returned %d messages, want 1 "+
				"(memberlist retransmits until the transmit counter is exhausted)", i+1, got)
		}
	}
	t.Logf("TransmitLimitedQueue messages per target node in one round: %v", counts)
}

// TestClusterDelegate_IsStatelessPassThrough shows there is no retransmission
// layer between memberlist and the per-tracker queues: the delegate pulls from
// its registered broadcasters once per call and keeps no copy of what it handed
// out. Whatever a source drains on the first call is therefore gone for every
// subsequent target node in the same gossip round, which is why each source has
// to count transmissions itself.
func TestClusterDelegate_IsStatelessPassThrough(t *testing.T) {
	m, d := newTestDelegate(t)

	// A source that empties itself when read - the semantics the production
	// broadcasters must NOT have.
	queue := [][]byte{[]byte("event-1")}
	calls := 0
	m.RegisterRateLimitBroadcaster(func(overhead, limit int) [][]byte {
		calls++
		out := queue
		queue = nil
		return out
	})

	first := d.GetBroadcasts(2, 65535)
	second := d.GetBroadcasts(2, 65535)

	if calls != 2 {
		t.Fatalf("delegate called its broadcaster %d times for 2 GetBroadcasts calls, want 2", calls)
	}
	if len(first) != 1 {
		t.Fatalf("first GetBroadcasts returned %d messages, want 1", len(first))
	}
	if len(second) != 0 {
		t.Errorf("second GetBroadcasts returned %d messages, want 0: the delegate must stay a "+
			"pass-through, retransmission is the source's job", len(second))
	}
	t.Logf("clusterDelegate messages per target node in one round: [%d %d] (no replay layer above the trackers)",
		len(first), len(second))
}

// TestClusterDelegate_AntiEntropyCarriesApplicationState asserts that the
// push/pull state-sync hooks reconcile application state. memberlist runs
// push/pull every PushPullInterval over TCP and hands LocalState/MergeRemoteState
// the full state of each side — that is the mechanism that repairs a peer which
// missed an event, and the only one that can carry a payload too large for a
// gossip datagram.
func TestClusterDelegate_AntiEntropyCarriesApplicationState(t *testing.T) {
	m, d := newTestDelegate(t)

	// With nothing registered there is no state to exchange.
	if state := d.LocalState(true); state != nil {
		t.Errorf("LocalState(join=true) returned %d bytes, want nil with no providers", len(state))
	}

	merged := make(chan []byte, 4)
	m.RegisterStateProvider("test-subsystem", "instance-1",
		func() []byte { return []byte("full-state") },
		func(b []byte) { merged <- b },
	)

	state := d.LocalState(false)
	if len(state) == 0 {
		t.Fatal("LocalState returned nothing for a registered provider")
	}

	d.MergeRemoteState(state, false)
	select {
	case got := <-merged:
		if string(got) != "full-state" {
			t.Errorf("MergeRemoteState delivered %q, want %q", got, "full-state")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MergeRemoteState did not reach the registered state provider")
	}

	received := make(chan []byte, 4)
	m.RegisterRateLimitHandler(func(b []byte) { received <- b })

	payload := []byte{0x52, 0x4C, 'b', 'l', 'o', 'c', 'k'} // 'R''L' + body

	// Positive control: the normal gossip path reaches the gossip handler.
	d.NotifyMsg(payload)
	select {
	case got := <-received:
		if string(got) != "block" {
			t.Fatalf("NotifyMsg delivered %q, want %q", got, "block")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("setup problem: NotifyMsg did not reach the registered rate limit handler")
	}

	// The two paths stay separate: a marker-framed gossip message is not a
	// push/pull payload and must not be fed to gossip handlers.
	d.MergeRemoteState(payload, true)
	select {
	case got := <-received:
		t.Errorf("MergeRemoteState delivered gossip payload %q to a gossip handler", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// newTestDelegate builds the real clusterDelegate over a Manager that has no
// memberlist attached, so no gossip port is bound.
func newTestDelegate(t *testing.T) (*Manager, *clusterDelegate) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := &Manager{nodeID: "test-node", ctx: ctx, cancel: cancel}
	d := &clusterDelegate{meta: []byte("test-node"), manager: m}
	return m, d
}
