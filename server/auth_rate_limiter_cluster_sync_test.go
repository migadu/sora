package server

import (
	"context"
	"testing"
	"time"
)

// deliverRateLimitEvent hands crl an event as a peer's gossip would.
func deliverRateLimitEvent(t *testing.T, crl *ClusterRateLimiter, event RateLimitEvent) {
	t.Helper()
	encoded, err := encodeRateLimitEvent(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	crl.HandleClusterEvent(encoded)
}

// queuedRateLimitEventTypes returns the types of the few events queued in crl's
// outgoing gossip, which one datagram carries, and empties the queue.
func queuedRateLimitEventTypes(t *testing.T, crl *ClusterRateLimiter) []RateLimitEventType {
	t.Helper()
	var types []RateLimitEventType
	for _, msg := range crl.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
		event, err := decodeRateLimitEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		types = append(types, event.Type)
	}
	// A message is handed out until its retransmit budget is spent.
	for range 100 {
		if len(crl.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)) == 0 {
			return types
		}
	}
	t.Fatal("outgoing gossip never drained")
	return nil
}

// TestPeerFailureCountNeverLowersTheLocalCount: both nodes count failures of the
// same address, so a peer's count says the address failed at least that often.
// It may raise this node's count but never lower it. With the newest count
// winning, a peer that had seen fewer failures reset the count of a node close to
// blocking the address, so an attack spread over two nodes could stay under
// max_attempts_per_ip on both: weaker than with no sync at all.
func TestPeerFailureCountNeverLowersTheLocalCount(t *testing.T) {
	crl := newTestClusterRateLimiter(t) // MaxAttemptsPerIP: 10
	crl.syncFailureCounts = true

	ctx := context.Background()
	client := &StringAddr{Addr: "192.0.2.30:40000"}
	for range 8 {
		crl.limiter.RecordAuthAttempt(ctx, client, "", false)
	}

	// The peer's own second failure, broadcast after ours.
	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		EventID:      "peer-failure-count",
		IP:           "192.0.2.30",
		Timestamp:    time.Now().Add(time.Second),
		NodeID:       "node-b",
		Protocol:     crl.limiter.protocol,
		FailureCount: 2,
		FirstFailure: time.Now(),
	})

	crl.limiter.ipMu.RLock()
	got := crl.limiter.ipFailureCounts["192.0.2.30"].FailureCount
	crl.limiter.ipMu.RUnlock()
	if got != 8 {
		t.Errorf("a peer's count of 2 changed this node's count of 8 to %d", got)
	}

	for range 2 {
		crl.limiter.RecordAuthAttempt(ctx, client, "", false)
	}
	if !crl.limiter.IsIPBlocked(client) {
		t.Error("10 local failures did not block the address once a peer had reported fewer")
	}

	// A higher count from a peer still raises ours.
	other := &StringAddr{Addr: "192.0.2.31:40000"}
	crl.limiter.RecordAuthAttempt(ctx, other, "", false)
	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		EventID:      "peer-failure-count-high",
		IP:           "192.0.2.31",
		Timestamp:    time.Now().Add(time.Second),
		NodeID:       "node-b",
		Protocol:     crl.limiter.protocol,
		FailureCount: 9,
		FirstFailure: time.Now(),
	})
	crl.limiter.RecordAuthAttempt(ctx, other, "", false)
	if !crl.limiter.IsIPBlocked(other) {
		t.Error("a peer's count of 9 plus a local failure did not block the address")
	}
}
