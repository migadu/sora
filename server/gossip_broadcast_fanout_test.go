package server

import (
	"testing"
	"time"
)

// memberlist calls the user Delegate's GetBroadcasts once per TARGET NODE, not
// once per gossip round. From memberlist@v0.6.0 state.go gossip():
//
//	for _, node := range kNodes {                      // kNodes = GossipNodes (LAN default: 3)
//	        msgs := m.getBroadcasts(compoundOverhead, bytesAvail)
//	        ...rawSendMsgPacket(node, msgs)
//	}
//
// and broadcast.go getBroadcasts() forwards to d.GetBroadcasts(...) on every one
// of those iterations. The same call is also made from sendMsg() to piggyback
// broadcasts on ordinary pings/acks.
//
// That API therefore requires the source to be replayable: a source that empties
// itself on the first call puts the event in the packet for whichever node
// memberlist happens to ask about first, and every other node gets an empty
// payload and never learns of it. memberlist's own TransmitLimitedQueue is
// replayable - it returns a queued broadcast on every call until its transmit
// counter reaches retransmitMult * log(N+1), which is what makes the epidemic
// converge - and every source registered with cluster.Manager is one of those
// queues. See cluster/gossip_delegate_semantics_test.go for an executable
// demonstration of that behaviour.
//
// Each subtest below queues exactly ONE event into a real production queue and
// then makes TWO GetBroadcasts calls with a generous byte limit - memberlist
// asking "what should I send to node B?" and then "what should I send to node
// C?" inside a single gossip round. Both calls must carry the event.
func TestGossipBroadcastQueues_DeliverEventToEveryTargetNodeInARound(t *testing.T) {
	// Overhead/limit values in the same ballpark as memberlist's UDP budget so
	// the size-based partial-drain branch is never the reason for a short read.
	const overhead = 2
	const limit = 65535

	t.Run("ConnectionTracker/kick", func(t *testing.T) {
		// A kick event is the highest-stakes payload on this bus: an admin
		// "kick user" must reach every proxy node holding that user's sessions.
		tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 100, false)
		defer tracker.Stop()

		tracker.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  42,
			Username:   "victim@example.com",
			Protocol:   "IMAP",
			Timestamp:  time.Now(),
			NodeID:     "node-a",
			InstanceID: "instance-1",
		})

		assertReplayedToEveryTarget(t, "ConnectionTracker", tracker.GetBroadcasts, overhead, limit)
	})

	t.Run("ClusterRateLimiter/block-ip", func(t *testing.T) {
		// An IP block that reaches only one node leaves the attacker free to
		// keep hammering every other node in the cluster.
		limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 3,
			MaxAttemptsPerIP:         10,
			IPUsernameBlockDuration:  5 * time.Minute,
			IPBlockDuration:          15 * time.Minute,
			CleanupInterval:          time.Hour,
		})
		defer limiter.Stop()

		crl := &ClusterRateLimiter{
			limiter: limiter,
			queue:   newGossipQueue("rate-limit:test", nil, maxRateLimitEventQueueSize),
		}
		crl.queueEvent(RateLimitEvent{
			Type:         RateLimitEventBlockIP,
			IP:           "203.0.113.7",
			Timestamp:    time.Now(),
			NodeID:       "node-a",
			BlockedUntil: time.Now().Add(time.Hour),
			Protocol:     "imap",
		})

		assertReplayedToEveryTarget(t, "ClusterRateLimiter", crl.GetBroadcasts, overhead, limit)
	})

	t.Run("AffinityManager/set", func(t *testing.T) {
		am := &AffinityManager{
			affinityMap: make(map[string]*AffinityInfo),
			enabled:     true,
			defaultTTL:  time.Hour,
			queue:       newGossipQueue("affinity", nil, maxAffinityEventQueueSize),
		}
		am.queueEvent(AffinityEvent{
			Type:      AffinityEventSet,
			Username:  "user@example.com",
			Backend:   "backend1:143",
			Protocol:  "imap",
			Timestamp: time.Now(),
			NodeID:    "node-a",
			TTL:       time.Hour,
		})

		assertReplayedToEveryTarget(t, "AffinityManager", am.GetBroadcasts, overhead, limit)
	})

	t.Run("IPLimitTracker/increment", func(t *testing.T) {
		tracker := &IPLimitTracker{
			protocol:          "IMAP",
			instanceID:        "instance-1",
			connections:       make(map[string]*IPConnectionInfo),
			maxEventQueueSize: 100,
			queue:             newGossipQueue("ip-limit:IMAP", nil, 100),
			heartbeatQueue:    newGossipQueue("ip-limit-heartbeat:IMAP", nil, maxHeartbeatQueued),
		}
		tracker.queueEvent(IPLimitEvent{
			Type:       IPLimitEventIncrement,
			IP:         "203.0.113.9",
			Protocol:   "IMAP",
			Timestamp:  time.Now(),
			NodeID:     "node-a",
			InstanceID: "instance-1",
		})

		assertReplayedToEveryTarget(t, "IPLimitTracker", tracker.GetBroadcasts, overhead, limit)
	})
}

// assertReplayedToEveryTarget models one memberlist gossip round with three
// target nodes: memberlist asks the delegate (and thus this broadcast source)
// once per node. A source with correct retransmission semantics answers all
// three calls with the queued event.
func assertReplayedToEveryTarget(t *testing.T, name string, getBroadcasts func(overhead, limit int) [][]byte, overhead, limit int) {
	t.Helper()

	const gossipNodes = 3 // memberlist DefaultLANConfig().GossipNodes

	counts := make([]int, gossipNodes)
	for i := 0; i < gossipNodes; i++ {
		counts[i] = len(getBroadcasts(overhead, limit))
	}

	if counts[0] != 1 {
		t.Fatalf("%s: setup problem — first GetBroadcasts (packet for node #1) returned %d messages, want 1", name, counts[0])
	}

	for i := 1; i < gossipNodes; i++ {
		if counts[i] != 1 {
			t.Errorf("%s: GetBroadcasts call #%d (packet for gossip target node #%d in the SAME round) returned %d messages, want 1: "+
				"the queue was destructively drained by the first call, so only one peer ever receives this event "+
				"(memberlist.TransmitLimitedQueue would return it retransmitMult*log(N+1) times)",
				name, i+1, i+1, counts[i])
		}
	}
	t.Logf("%s: messages returned per target node in one gossip round: %v (want [1 1 1])", name, counts)
}
