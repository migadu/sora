package server

import (
	"bytes"
	"encoding/gob"
	"testing"
	"time"
)

// TestGossipQueueEncodesOnce pins the property that made the hand-rolled queues
// expensive: memberlist calls GetBroadcasts once per gossip target, about
// fifteen times a second, and the source must not re-encode its backlog for
// each call. Handing back the identical backing array proves the bytes were
// produced once, when the event was queued.
func TestGossipQueueEncodesOnce(t *testing.T) {
	tracker := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer tracker.Stop()

	tracker.queueEvent(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  7,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  time.Now(),
		InstanceID: "inst-a",
	})

	first := tracker.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
	second := tracker.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected the event on both calls, got %d and %d messages", len(first), len(second))
	}
	if &first[0][0] != &second[0][0] {
		t.Error("the event was re-encoded for the second gossip target; encoding belongs at enqueue time")
	}
}

// TestGossipQueueRetiresMessageAfterTransmitLimit shows retransmission is
// memberlist's own accounting: with one node the limit is
// RetransmitMult * ceil(log10(N+1)) = 4, after which the message is retired
// instead of being handed out forever.
func TestGossipQueueRetiresMessageAfterTransmitLimit(t *testing.T) {
	queue := newGossipQueue("test", nil, 100)
	if !queue.enqueue([]byte("event")) {
		t.Fatal("enqueue rejected a small message")
	}

	transmits := 0
	for i := 0; i < 100 && queue.numQueued() > 0; i++ {
		transmits += len(queue.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit))
	}

	if transmits != 4 {
		t.Errorf("message was transmitted %d times, want 4 (RetransmitMult=4, NumNodes=1)", transmits)
	}
	if queued := queue.numQueued(); queued != 0 {
		t.Errorf("queue still holds %d messages after the transmit limit was reached", queued)
	}
}

// TestGossipQueueRejectsOversizedMessage covers the wedge: a message too large
// for a datagram can never be transmitted, and a broadcast is only retired once
// it has been transmitted, so it would sit in the queue and be reconsidered on
// every call forever. It has to be refused where it is produced.
func TestGossipQueueRejectsOversizedMessage(t *testing.T) {
	queue := newGossipQueue("test", nil, 100)

	oversized := make([]byte, 29821) // a full-state snapshot of ~500 connections
	if queue.enqueue(oversized) {
		t.Error("enqueue accepted a message larger than a gossip datagram")
	}
	if queued := queue.numQueued(); queued != 0 {
		t.Errorf("oversized message was queued anyway: %d messages queued", queued)
	}

	// Traffic behind it still flows.
	if !queue.enqueue([]byte("event")) {
		t.Fatal("enqueue rejected a small message after an oversized one")
	}
	if msgs := queue.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit); len(msgs) != 1 {
		t.Errorf("expected the small message to be broadcast, got %d messages", len(msgs))
	}
}

// TestConnectionTrackerHeartbeatKeepsQuietInstanceAlive covers the anti-entropy
// half: peers retire the counts of an instance they stop hearing from, and an
// instance whose sessions are all idle emits no other gossip. The heartbeat is
// what keeps its counts alive; without it they are purged.
func TestConnectionTrackerHeartbeatKeepsQuietInstanceAlive(t *testing.T) {
	const accountID = 42

	tracker := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer tracker.Stop()

	register, err := encodeConnectionEvent(ConnectionEvent{
		Type:       ConnectionEventRegister,
		EventID:    "register-1",
		AccountID:  accountID,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  time.Now(),
		InstanceID: "inst-b",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tracker.HandleClusterEvent(register)

	if got := tracker.GetConnectionCount(accountID); got != 1 {
		t.Fatalf("precondition: expected 1 connection, got %d", got)
	}

	// The session goes idle for longer than the staleness threshold.
	silenceConnectionInstance(tracker, "inst-b")

	heartbeat, err := encodeConnectionEvent(ConnectionEvent{
		Type:       ConnectionEventStateSnapshot,
		EventID:    "heartbeat-1",
		Protocol:   "IMAP",
		Timestamp:  time.Now(),
		InstanceID: "inst-b",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tracker.HandleClusterEvent(heartbeat)

	tracker.cleanup()
	if got := tracker.GetConnectionCount(accountID); got != 1 {
		t.Errorf("a heartbeating instance lost its counts: got %d, want 1", got)
	}

	// The instance dies: no heartbeat, and the counts are retired.
	silenceConnectionInstance(tracker, "inst-b")
	tracker.cleanup()
	if got := tracker.GetConnectionCount(accountID); got != 0 {
		t.Errorf("counts of a silent instance survived cleanup: got %d, want 0", got)
	}
}

// TestIPLimitTrackerHeartbeatKeepsQuietInstanceAlive is the per-IP equivalent.
func TestIPLimitTrackerHeartbeatKeepsQuietInstanceAlive(t *testing.T) {
	const ip = "203.0.113.9"

	tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
	defer tracker.Stop()

	deliverIncrement(t, tracker, "inst-b", "IMAP", ip, time.Now())
	if got := tracker.GetIPCount(ip); got != 1 {
		t.Fatalf("precondition: expected 1 connection for %s, got %d", ip, got)
	}

	silence(tracker, "inst-b")
	tracker.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventStateSnapshot,
		EventID:    "heartbeat-1",
		Protocol:   "IMAP",
		Timestamp:  time.Now(),
		NodeID:     "inst-b",
		InstanceID: "inst-b",
	}))

	tracker.performCleanup()
	if got := tracker.GetIPCount(ip); got != 1 {
		t.Errorf("a heartbeating instance lost its per-IP counts: got %d, want 1", got)
	}

	silence(tracker, "inst-b")
	tracker.performCleanup()
	if got := tracker.GetIPCount(ip); got != 0 {
		t.Errorf("per-IP counts of a silent instance survived cleanup: got %d, want 0", got)
	}
}

// silenceConnectionInstance ages an instance's last-seen mark past the
// staleness threshold, the state a peer reaches when it stops heartbeating.
func silenceConnectionInstance(ct *ConnectionTracker, instanceID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.instanceLastSeen[instanceID] = time.Now().Add(-2 * staleInstanceThreshold)
}

// TestHeartbeatIsSmallAndCarriesNoState checks what the heartbeat routine puts
// on the wire: proof of life that a peer can attribute to one instance and one
// protocol, small enough to never be the reason a datagram overflows, and
// carrying no state - the counts travel over push/pull.
func TestHeartbeatIsSmallAndCarriesNoState(t *testing.T) {
	t.Run("ConnectionTracker", func(t *testing.T) {
		tracker := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
		defer tracker.Stop()

		tracker.queueHeartbeat()

		msgs := tracker.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
		if len(msgs) != 1 {
			t.Fatalf("heartbeat produced %d messages, want 1", len(msgs))
		}

		event, err := decodeConnectionEvent(msgs[0])
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if event.Type != ConnectionEventStateSnapshot || event.StateSnapshot != nil {
			t.Errorf("heartbeat is %s with payload %v, want a payload-less state snapshot", event.Type, event.StateSnapshot)
		}
		if event.Protocol != "IMAP" || event.InstanceID != "inst-a" {
			t.Errorf("heartbeat is not attributable: protocol=%q instance=%q", event.Protocol, event.InstanceID)
		}
	})

	t.Run("IPLimitTracker", func(t *testing.T) {
		tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
		defer tracker.Stop()

		tracker.queueHeartbeat()

		msgs := tracker.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
		if len(msgs) != 1 {
			t.Fatalf("heartbeat produced %d messages, want 1", len(msgs))
		}

		var event IPLimitEvent
		if err := gob.NewDecoder(bytes.NewReader(msgs[0])).Decode(&event); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if event.Type != IPLimitEventStateSnapshot || event.StateSnapshot != nil {
			t.Errorf("heartbeat is %s with payload %v, want a payload-less state snapshot", event.Type, event.StateSnapshot)
		}
		if event.Protocol != "IMAP" || event.InstanceID != "inst-a" {
			t.Errorf("heartbeat is not attributable: protocol=%q instance=%q", event.Protocol, event.InstanceID)
		}
	})
}
