package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/server/idgen"
)

// ---------------------------------------------------------------------------
// GOSSIP-2 proof.
//
// Claim under test: full-state gossip snapshots produced by ConnectionTracker
// exceed the memberlist UDP budget, and GetBroadcasts handed them to memberlist
// anyway because the size guard at connection_tracker.go:723 was
//
//	if totalSize+msgSize > limit && len(broadcasts) > 0 { ... }
//
// so the FIRST message of a batch was never size-checked.
//
// The numbers below are the real memberlist v0.6.0 numbers for the config sora
// builds in cluster.New (DefaultLANConfig + a mandatory SecretKey):
//
//	memberlist/config.go:336   UDPBufferSize          = 1400
//	memberlist/net.go:84-86    compoundHeaderOverhead = 2
//	                           compoundOverhead       = 2
//	                           userMsgOverhead        = 1
//	memberlist/security.go:65  encryptOverhead(v1)    = 29
//
//	memberlist/state.go:614  bytesAvail := UDPBufferSize - compoundHeaderOverhead
//	                                      - labelOverhead(0) - encryptOverhead
//	                        => 1400 - 2 - 0 - 29 = 1369
//	memberlist/broadcast.go:96  d.GetBroadcasts(overhead+userMsgOverhead, avail)
//	                        => overhead = compoundOverhead + userMsgOverhead = 3
//
// memberlist performs NO size validation on what the delegate returns
// (broadcast.go:98-104 just frames it and state.go:626 sends it), so an
// oversized message goes straight onto the wire.
//
// A full-state snapshot cannot be made to fit: it grows with the number of
// tracked connections and crosses the budget at 16 of them (see the table in
// TestGossipSnapshotFitsUDPBudget). Full state is therefore no longer offered
// to the gossip path at all - it is exchanged through memberlist push/pull,
// which runs over TCP - and the gossip path carries only per-event deltas,
// every one of which must fit the budget it was handed.
// ---------------------------------------------------------------------------

const (
	// gossipUDPLimit is the `limit` memberlist actually passes to the delegate.
	gossipUDPLimit = 1400 - 2 - 29 // = 1369
	// gossipPerMsgOverhead is the `overhead` memberlist actually passes.
	gossipPerMsgOverhead = 2 + 1 // = 3
	// udpMaxPayload is the hard ceiling for a single UDP datagram over IPv4.
	// Above this, WriteTo fails with EMSGSIZE; memberlist's own read buffer
	// (udpPacketBufSize) is 65536, so it could not be received either.
	udpMaxPayload = 65507
)

// newSizingTracker builds a real ConnectionTracker in local mode (no cluster
// manager) so that RegisterConnection does not queue per-connection events.
// The snapshot path and the gob encoding path are the real ones.
func newSizingTracker(t *testing.T) *ConnectionTracker {
	t.Helper()
	ct := NewConnectionTracker("IMAP", "proxy-1", "proxy-1.example.com", "instance-aaaaaaaaaaaa", nil, 0, 0, 100000, true)
	t.Cleanup(ct.Stop)
	return ct
}

// registerN registers n distinct users, one connection each, from distinct IPs.
func registerN(t *testing.T, ct *ConnectionTracker, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		addr := fmt.Sprintf("10.%d.%d.%d:44321", (i/65536)%256, (i/256)%256, i%256)
		if err := ct.RegisterConnection(ctx, int64(i+1), user, "IMAP", addr); err != nil {
			t.Fatalf("RegisterConnection(%d): %v", i, err)
		}
	}
}

// snapshotWireSize builds a full-state snapshot for n connections through the
// real localState (gob) path and returns the number of bytes it occupies in a
// push/pull exchange.
func snapshotWireSize(t *testing.T, n int) int {
	t.Helper()
	ct := newSizingTracker(t)
	registerN(t, ct, n)

	state := ct.localState()
	if len(state) == 0 {
		t.Fatalf("n=%d: expected a non-empty state payload", n)
	}
	return len(state)
}

// TestGossipSnapshotFitsUDPBudget is part (a): it quantifies how the encoded
// full-state snapshot grows with the number of tracked connections, and asserts
// that a state of that size is never offered to the gossip path, whose messages
// must fit the budget memberlist hands the delegate.
func TestGossipSnapshotFitsUDPBudget(t *testing.T) {
	sizes := []int{1, 2, 3, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000}

	firstOverUDP := 0
	firstOver64K := 0

	t.Logf("memberlist budget handed to the delegate: limit=%d bytes, overhead=%d bytes/msg", gossipUDPLimit, gossipPerMsgOverhead)
	t.Logf("%8s  %12s  %s", "conns", "state bytes", "verdict")
	for _, n := range sizes {
		sz := snapshotWireSize(t, n)
		verdict := "would fit a datagram"
		if sz > gossipUDPLimit {
			verdict = fmt.Sprintf("OVER UDP budget by %d bytes", sz-gossipUDPLimit)
			if firstOverUDP == 0 {
				firstOverUDP = n
			}
		}
		if sz > udpMaxPayload {
			verdict = fmt.Sprintf("OVER 64KB UDP MAX by %d bytes", sz-udpMaxPayload)
			if firstOver64K == 0 {
				firstOver64K = n
			}
		}
		t.Logf("%8d  %12d  %s", n, sz, verdict)
	}

	// Narrow down the exact crossing points for the report.
	if firstOverUDP > 0 {
		t.Logf("exact crossing of the %d-byte memberlist budget: %d connections", gossipUDPLimit, exactCrossing(t, gossipUDPLimit))
	}
	if firstOver64K > 0 {
		t.Logf("exact crossing of the %d-byte UDP maximum: %d connections", udpMaxPayload, exactCrossing(t, udpMaxPayload))
	} else {
		t.Logf("64KB UDP maximum not crossed within the sampled range (max sampled n=%d)", sizes[len(sizes)-1])
	}

	// The invariant: a proxy tracking a realistic number of users must not put
	// its full state on the gossip path, because no datagram can carry it.
	const realistic = 500
	ct := newSizingTracker(t)
	registerN(t, ct, realistic)

	if msgs := ct.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit); len(msgs) != 0 {
		t.Errorf("GOSSIP-2(a): a tracker holding %d connections offered %d message(s) to the gossip path; "+
			"its full state is %d bytes, %d bytes past the %d-byte budget memberlist hands the delegate "+
			"(UDPBufferSize=1400), so it must travel over push/pull instead",
			realistic, len(msgs), snapshotWireSize(t, realistic), snapshotWireSize(t, realistic)-gossipUDPLimit, gossipUDPLimit)
	}
}

// exactCrossing binary-searches the smallest connection count whose encoded
// snapshot exceeds the given byte threshold.
func exactCrossing(t *testing.T, threshold int) int {
	t.Helper()
	// Find an upper bound.
	hi := 1
	for snapshotWireSize(t, hi) <= threshold {
		hi *= 2
		if hi > 1<<20 {
			return -1
		}
	}
	lo := hi / 2
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if snapshotWireSize(t, mid) > threshold {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

// TestGetBroadcastsHonorsSizeLimit is part (b), the crisp defect: an oversized
// message that is FIRST in the queue used to bypass the size guard entirely and
// was returned to memberlist, which sends it without further validation. The
// event queued here is the exact payload the periodic full-state snapshot used
// to put on that path.
func TestGetBroadcastsHonorsSizeLimit(t *testing.T) {
	ct := newSizingTracker(t)

	// 500 tracked users -> a snapshot far larger than the 1369-byte budget.
	registerN(t, ct, 500)
	ct.queueEvent(ConnectionEvent{
		Type:          ConnectionEventStateSnapshot,
		Protocol:      "IMAP",
		Timestamp:     time.Now(),
		InstanceID:    ct.instanceID,
		StateSnapshot: ct.stateSnapshot(),
	})

	// Ordinary traffic behind it, which does fit and must still be delivered.
	for i := 0; i < 5; i++ {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventRegister,
			AccountID:  int64(i + 1),
			Username:   fmt.Sprintf("user%d@example.com", i),
			Protocol:   "IMAP",
			ClientAddr: "10.0.0.1:44321",
			Timestamp:  time.Now(),
			InstanceID: ct.instanceID,
		})
	}

	msgs := ct.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)

	total := 0
	for i, m := range msgs {
		wire := gossipPerMsgOverhead + len(m)
		total += wire
		if wire > gossipUDPLimit {
			t.Errorf("GOSSIP-2(b): GetBroadcasts(overhead=%d, limit=%d) returned message[%d] of %d wire bytes, "+
				"%d bytes OVER the limit it was given; memberlist does not re-check this and will hand it to the UDP transport",
				gossipPerMsgOverhead, gossipUDPLimit, i, wire, wire-gossipUDPLimit)
		}
	}
	if total > gossipUDPLimit {
		t.Errorf("GOSSIP-2(b): GetBroadcasts returned %d bytes total for a %d-byte limit (%d bytes over)",
			total, gossipUDPLimit, total-gossipUDPLimit)
	}
	if len(msgs) == 0 {
		t.Error("GOSSIP-2(b): dropping the oversized event must not stop the events behind it from being broadcast")
	}
}

// TestGetBroadcastsGuardWorksAfterFirstMessage is the control: it proves the
// guard is functional for messages that do fit, so the failure above is
// specifically about oversized messages and not a mis-measurement of the limit.
func TestGetBroadcastsGuardWorksAfterFirstMessage(t *testing.T) {
	ct := newSizingTracker(t)

	// Two small register events; give a limit that only fits the first.
	for i := 0; i < 2; i++ {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventRegister,
			AccountID:  int64(i + 1),
			Username:   fmt.Sprintf("user%d@example.com", i),
			Protocol:   "IMAP",
			ClientAddr: "10.0.0.1:44321",
			InstanceID: ct.instanceID,
		})
	}

	// Size of one encoded event.
	one, err := encodeConnectionEvent(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  1,
		Username:   "user0@example.com",
		Protocol:   "IMAP",
		ClientAddr: "10.0.0.1:44321",
		InstanceID: ct.instanceID,
		EventID:    idgen.New(),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	oneWire := gossipPerMsgOverhead + len(one)

	// Limit that fits exactly one message but not two.
	limit := oneWire + 1
	msgs := ct.GetBroadcasts(gossipPerMsgOverhead, limit)
	if len(msgs) != 1 {
		t.Fatalf("control: expected the guard to stop after 1 message with limit=%d (one msg = %d wire bytes), got %d messages",
			limit, oneWire, len(msgs))
	}
	// memberlist asks once per gossip target, so both events stay queued: the
	// one that was sent still owes the cluster its remaining transmissions.
	if queued := ct.queue.numQueued(); queued != 2 {
		t.Fatalf("control: expected both events to remain queued for retransmission, got %d", queued)
	}
	t.Logf("control OK: guard correctly withheld the 2nd message (limit=%d, per-msg wire size=%d)", limit, oneWire)
}
