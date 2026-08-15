package cluster

import "testing"

// The cluster half of the datagram budget: every message a broadcast source
// hands up has to survive both Manager.getConnectionBroadcasts and
// clusterDelegate.GetBroadcasts, because nothing below them - memberlist frames
// and sends what the delegate returns - checks the size again.
//
// Budget numbers are the real memberlist v0.6.0 values for the config sora
// builds (DefaultLANConfig, UDPBufferSize=1400, mandatory SecretKey ->
// encryptOverhead(v1)=29): limit=1400-2-29=1369, overhead=2+1=3.
const (
	gossipUDPLimit       = 1400 - 2 - 29 // 1369
	gossipPerMsgOverhead = 2 + 1         // 3
)

// TestGetConnectionBroadcastsHonorsSizeLimit asserts that the cluster manager
// never forwards a broadcast larger than the limit it was given.
func TestGetConnectionBroadcastsHonorsSizeLimit(t *testing.T) {
	m := &Manager{nodeID: "node-1"}

	// A single oversized connection message, as a ConnectionTracker with ~500
	// tracked users would produce (measured: 29821 bytes of gob).
	oversized := make([]byte, 29821)
	m.RegisterConnectionBroadcaster(func(overhead, limit int) [][]byte {
		return [][]byte{oversized}
	})

	msgs := m.getConnectionBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)

	for i, msg := range msgs {
		wire := gossipPerMsgOverhead + len(msg)
		if wire > gossipUDPLimit {
			t.Errorf("Manager.getConnectionBroadcasts(overhead=%d, limit=%d) returned message[%d] of %d wire bytes, "+
				"%d bytes OVER the limit",
				gossipPerMsgOverhead, gossipUDPLimit, i, wire, wire-gossipUDPLimit)
		}
	}
}

// TestDelegateGetBroadcastsHonorsSizeLimit exercises the full memberlist
// delegate entry point, which is what memberlist itself calls.
func TestDelegateGetBroadcastsHonorsSizeLimit(t *testing.T) {
	m := &Manager{nodeID: "node-1"}
	d := &clusterDelegate{meta: []byte("node-1"), manager: m}

	oversized := make([]byte, 29821)
	m.RegisterConnectionBroadcaster(func(overhead, limit int) [][]byte {
		return [][]byte{oversized}
	})

	msgs := d.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)

	total := 0
	for i, msg := range msgs {
		wire := gossipPerMsgOverhead + len(msg)
		total += wire
		if wire > gossipUDPLimit {
			t.Errorf("clusterDelegate.GetBroadcasts(overhead=%d, limit=%d) returned message[%d] of %d wire bytes, "+
				"%d bytes OVER the limit; memberlist frames and sends this without any further size check "+
				"(memberlist/broadcast.go:98-104, state.go:626)",
				gossipPerMsgOverhead, gossipUDPLimit, i, wire, wire-gossipUDPLimit)
		}
	}
	if total > gossipUDPLimit {
		t.Errorf("delegate returned %d bytes total for a %d-byte UDP budget (%d over)",
			total, gossipUDPLimit, total-gossipUDPLimit)
	}
}

// TestGetConnectionBroadcastsGuardWorksAfterFirstMessage is the control on the
// running total: two messages that each fit but do not fit together, of which
// only the first may be returned.
func TestGetConnectionBroadcastsGuardWorksAfterFirstMessage(t *testing.T) {
	m := &Manager{nodeID: "node-1"}

	small := make([]byte, 800) // +2 marker +3 overhead = 805 wire bytes
	m.RegisterConnectionBroadcaster(func(overhead, limit int) [][]byte {
		return [][]byte{small, small}
	})

	msgs := m.getConnectionBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
	if len(msgs) != 1 {
		t.Fatalf("control: expected the guard to stop after 1 of 2 x 805-byte messages under a %d-byte limit, got %d",
			gossipUDPLimit, len(msgs))
	}
	t.Logf("control OK: guard withheld the 2nd message (limit=%d)", gossipUDPLimit)
}
