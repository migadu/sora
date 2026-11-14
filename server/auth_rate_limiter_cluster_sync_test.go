package server

import (
	"context"
	"fmt"
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

// TestClusterBlockIsNotStarvedByFailureEvents: during a credential-stuffing run
// every failed login queues a username failure, and memberlist hands out the
// largest message of a transmit tier first. Username failures for long
// addresses outsize a block, so the one event that makes the block cluster-wide
// waited behind every one of them, and was the first fresh event pruned once
// the queue overflowed.
func TestClusterBlockIsNotStarvedByFailureEvents(t *testing.T) {
	crl := newTestClusterRateLimiter(t)
	crl.syncBlocks = true
	crl.syncFailureCounts = true

	now := time.Now()
	crl.BroadcastBlockIP("192.0.2.40", now.Add(time.Minute), 10, now)
	for i := range 200 {
		crl.BroadcastUsernameFailure(fmt.Sprintf("a-rather-long-mailbox-name-%04d@customer-domain.example.com", i))
	}

	for _, msg := range crl.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
		event, err := decodeRateLimitEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		if event.Type == RateLimitEventBlockIP {
			return
		}
	}
	t.Error("the first datagram carried username failures and left the IP block queued behind them")
}

// TestLoginWithoutFailuresSendsNoGossip: username failures are statistics only
// and a peer holds them only for a username some node reported, so a successful
// login with nothing to clear has nothing to tell the cluster. Broadcasting it
// anyway cost one gossip event per login, the most frequent event a proxy sees.
func TestLoginWithoutFailuresSendsNoGossip(t *testing.T) {
	crl := newTestClusterRateLimiter(t)
	crl.limiter.SetClusterLimiter(crl)

	ctx := context.Background()
	client := &StringAddr{Addr: "192.0.2.50:40000"}

	crl.limiter.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	if types := queuedRateLimitEventTypes(t, crl); len(types) != 0 {
		t.Errorf("a login with no failures to clear queued %v", types)
	}

	// Failures this node saw are cleared on the peers.
	crl.limiter.RecordAuthAttempt(ctx, client, "bob@example.com", false)
	queuedRateLimitEventTypes(t, crl)
	crl.limiter.RecordAuthAttempt(ctx, client, "bob@example.com", true)
	if types := queuedRateLimitEventTypes(t, crl); len(types) != 1 || types[0] != RateLimitEventUsernameSuccess {
		t.Errorf("a login after a local failure queued %v, want one %s", types, RateLimitEventUsernameSuccess)
	}

	// So are failures a peer reported.
	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		EventID:   "peer-username-failure",
		Username:  "carol@example.com",
		Timestamp: time.Now().Add(-time.Second),
		NodeID:    "node-b",
		Protocol:  crl.limiter.protocol,
	})
	crl.limiter.RecordAuthAttempt(ctx, client, "carol@example.com", true)
	if types := queuedRateLimitEventTypes(t, crl); len(types) != 1 || types[0] != RateLimitEventUsernameSuccess {
		t.Errorf("a login after a peer's failure queued %v, want one %s", types, RateLimitEventUsernameSuccess)
	}
}

// TestPeerEventsRespectTheLimiterSizeCaps: max_ip_entries and
// max_username_entries bound what a limiter holds however the entries arrive.
// Entries a peer reported bypassed the cap, so every node held the union of the
// whole cluster's attack traffic for the length of the window.
func TestPeerEventsRespectTheLimiterSizeCaps(t *testing.T) {
	crl := newTestClusterRateLimiter(t)
	crl.syncFailureCounts = true
	crl.limiter.config.MaxIPEntries = 10
	crl.limiter.config.MaxUsernameEntries = 10

	now := time.Now()
	for i := range 50 {
		deliverRateLimitEvent(t, crl, RateLimitEvent{
			Type:         RateLimitEventFailureCount,
			EventID:      fmt.Sprintf("peer-failure-count-%d", i),
			IP:           fmt.Sprintf("192.0.2.%d", i+1),
			Timestamp:    now,
			NodeID:       "node-b",
			Protocol:     crl.limiter.protocol,
			FailureCount: 3,
			FirstFailure: now.Add(time.Duration(i) * time.Millisecond),
		})
		deliverRateLimitEvent(t, crl, RateLimitEvent{
			Type:      RateLimitEventUsernameFailure,
			EventID:   fmt.Sprintf("peer-username-failure-%d", i),
			Username:  fmt.Sprintf("user%d@example.com", i),
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			NodeID:    "node-b",
			Protocol:  crl.limiter.protocol,
		})
	}

	crl.limiter.ipMu.RLock()
	ips := len(crl.limiter.ipFailureCounts)
	crl.limiter.ipMu.RUnlock()
	crl.limiter.usernameMu.RLock()
	usernames := len(crl.limiter.usernameFailureCounts)
	crl.limiter.usernameMu.RUnlock()

	if ips > 10 {
		t.Errorf("peers' failure counts grew the IP map to %d entries, over max_ip_entries = 10", ips)
	}
	if usernames > 10 {
		t.Errorf("peers' username failures grew the username map to %d entries, over max_username_entries = 10", usernames)
	}
}
