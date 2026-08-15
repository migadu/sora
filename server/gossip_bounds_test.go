package server

import (
	"fmt"
	"testing"
	"time"
)

// The gossip bus has three tiers and every one of them must stay bounded on a
// node whose peers are unreachable: memberlist only asks for broadcasts once it
// has a gossip target, so on a partitioned or single-node instance nothing
// drains any queue while the heartbeat keeps enqueueing.

// tombstoneSize reports how many keys a tombstone map holds across both of its
// generations.
func tombstoneSize(g *gossipTombstones) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.current) + len(g.previous)
}

// dedupSize reports how many event IDs the dedup ledger holds across both of
// its generations.
func dedupSize(d *gossipDedup) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.current) + len(d.previous)
}

// deferredHeldCount reports how many decrements the ledger is holding, counting
// every one of them, not just the keys they are filed under.
func deferredHeldCount(d *deferredDecrements) int {
	total := 0
	for _, entry := range d.held {
		total += entry.count
	}
	return total
}

// TestDedupLedgerIsBounded covers the map on the attacker-driven path: an event
// ID is minted per event, and the auth-failure events that carry them are
// produced at whatever rate someone is hammering the cluster. A ledger that
// grows one-for-one with that rate is unbounded.
func TestDedupLedgerIsBounded(t *testing.T) {
	const events = 200000

	var dedup gossipDedup
	for i := 0; i < events; i++ {
		dedup.seenBefore(fmt.Sprintf("event-%d", i))
	}

	if got := dedupSize(&dedup); got >= events {
		t.Errorf("dedup ledger holds %d event IDs after %d events - one entry per event, with no ceiling: "+
			"whoever drives the event rate drives this node's memory", got, events)
	}
}

// TestDeferredDecrementsAreBounded covers the other gossip-driven map: a
// decrement delivered before its increment is held until the increment shows
// up. A peer that sends decrements whose increments never come - a partition
// that healed the wrong way round, a replay, a hostile node - has that ledger
// grow for as long as it keeps sending.
func TestDeferredDecrementsAreBounded(t *testing.T) {
	const events = 200000

	t.Run("distinct keys", func(t *testing.T) {
		var held deferredDecrements
		for i := 0; i < events; i++ {
			held.hold(fmt.Sprintf("inst-b|%d|203.0.113.5", i), time.Now())
		}

		if got := len(held.held); got >= events {
			t.Errorf("deferred ledger holds %d keys after %d unmatched decrements, one per key with no ceiling", got, events)
		}
	})

	t.Run("one key hammered", func(t *testing.T) {
		var held deferredDecrements
		for i := 0; i < events; i++ {
			held.hold("inst-b|42|203.0.113.5", time.Now())
			held.prune(gossipDedupWindow)
		}

		if got := deferredHeldCount(&held); got >= events {
			t.Errorf("deferred ledger holds %d decrements for one key after %d unmatched decrements: "+
				"ageing runs from local arrival, so continuous traffic on a key keeps refreshing it and it never ages out", got, events)
		}
	})
}

// TestUsernameSuccessTombstonesAreBounded covers the auth hot path: every
// successful authentication anywhere in the cluster broadcasts a
// USERNAME_SUCCESS, and every peer marks a tombstone for it before any other
// check. The tombstone shadows usernameFailureCounts, so it has to respect the
// same cap - otherwise successful logins alone grow it without limit.
func TestUsernameSuccessTombstonesAreBounded(t *testing.T) {
	const maxUsernames = 100

	clusterMgr, err := newKickTestCluster("tombstone-node", 25949, nil)
	if err != nil {
		t.Fatalf("create cluster: %v", err)
	}
	defer clusterMgr.Shutdown()

	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         10,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPBlockDuration:          15 * time.Minute,
		CleanupInterval:          time.Hour,
		MaxUsernameEntries:       maxUsernames,
	})
	defer limiter.Stop()

	crl := NewClusterRateLimiter(limiter, clusterMgr, true, true)
	if crl == nil {
		t.Fatal("NewClusterRateLimiter returned nil")
	}

	for i := 0; i < 50*maxUsernames; i++ {
		encoded, err := encodeRateLimitEvent(RateLimitEvent{
			Type:      RateLimitEventUsernameSuccess,
			EventID:   fmt.Sprintf("success-%d", i),
			Username:  fmt.Sprintf("user%d@example.com", i),
			Timestamp: time.Now(),
			NodeID:    "node-b",
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		crl.HandleClusterEvent(encoded)
	}

	if got := tombstoneSize(&crl.succeeded); got > maxUsernames {
		t.Errorf("success tombstones hold %d usernames, past the %d-entry cap of the map they shadow: "+
			"successful logins grow this map without limit on every node in the cluster", got, maxUsernames)
	}
}

// TestHeartbeatIsNotStarvedByAKickBacklog covers the tier the heartbeat needs.
// Sharing a queue with kicks is not enough: within a transmit tier memberlist
// hands out the largest message that fits, and a heartbeat is the smallest
// message the tracker produces, so a kick backlog delays it by one round per
// couple of kicks - past the staleness threshold at a few thousand.
func TestHeartbeatIsNotStarvedByAKickBacklog(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 50000, false)
	defer ct.Stop()

	for i := 0; i < 500; i++ {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  int64(i),
			Username:   "a-fairly-long-username@customer.example.com",
			Protocol:   "IMAP",
			Timestamp:  time.Now(),
			NodeID:     "node-a",
			InstanceID: "inst-a",
		})
	}
	ct.queueHeartbeat()

	// Twenty gossip rounds, ~1.3 seconds of real gossip.
	for round := 0; round < 20; round++ {
		for _, msg := range ct.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
			event, err := decodeConnectionEvent(msg)
			if err != nil {
				t.Fatalf("decode broadcast: %v", err)
			}
			if isHeartbeat(event) {
				return // heartbeat transmitted
			}
		}
	}

	t.Error("the liveness heartbeat was never transmitted in 20 gossip rounds behind a backlog of kicks: " +
		"peers will purge this instance's connection counts after the staleness threshold")
}

// TestHeartbeatQueueStaysBoundedWithoutPeers covers a node with no reachable
// peers: memberlist never asks for broadcasts, so nothing drains the queue
// while the heartbeat routine keeps enqueueing every 30 seconds. A heartbeat is
// superseded by the next one, so only the newest is worth keeping.
func TestHeartbeatQueueStaysBoundedWithoutPeers(t *testing.T) {
	t.Run("ConnectionTracker", func(t *testing.T) {
		ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
		defer ct.Stop()

		for i := 0; i < 1000; i++ {
			ct.queueHeartbeat()
		}

		if queued := ct.heartbeatQueue.numQueued(); queued > maxHeartbeatQueued {
			t.Errorf("heartbeat queue holds %d messages after 1000 undrained heartbeats, cap is %d", queued, maxHeartbeatQueued)
		}
	})

	t.Run("IPLimitTracker", func(t *testing.T) {
		tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 100)
		defer tracker.Stop()

		for i := 0; i < 1000; i++ {
			tracker.queueHeartbeat()
		}

		if queued := tracker.heartbeatQueue.numQueued(); queued > maxHeartbeatQueued {
			t.Errorf("heartbeat queue holds %d messages after 1000 undrained heartbeats, cap is %d", queued, maxHeartbeatQueued)
		}
	})
}

// TestKickQueueStaysBoundedWithoutPeers is the same property for the tier that
// carries kicks. The cap is generous enough that no operator reaches it; what
// it removes is the unbounded case. Which kick it drops there is memberlist's
// choice and not one this queue can influence - see maxCriticalQueued.
func TestKickQueueStaysBoundedWithoutPeers(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer ct.Stop()

	for i := 0; i < maxCriticalQueued+100; i++ {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  int64(i),
			Username:   "kicked@example.com",
			Protocol:   "IMAP",
			Timestamp:  time.Now(),
			NodeID:     "node-a",
			InstanceID: "inst-a",
		})
	}

	if queued := ct.criticalQueue.numQueued(); queued > maxCriticalQueued {
		t.Errorf("kick queue holds %d messages, past its %d-message cap: a partitioned node grows it without limit",
			queued, maxCriticalQueued)
	}
}
