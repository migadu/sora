package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
)

// memberlist's TransmitLimitedQueue is not FIFO. Within a transmit tier it
// hands out the LARGEST message that still fits the datagram and breaks ties by
// newest id, so two related events - a SET and the DELETE that removes it, a
// failure and the success that clears it - can be delivered in either order.
// The tests below deliver every such pair BOTH ways round and require the same
// final state, which is the property that replaces the FIFO the slice queues
// used to provide.

// ---------------------------------------------------------------------------
// Heartbeat starvation: the liveness heartbeat is what keeps a peer from
// purging this instance's counts, so it must go out even while the ordinary
// queue is saturated - which is exactly when peers would otherwise purge it.
// ---------------------------------------------------------------------------

// TestConnectionHeartbeatSurvivesSaturatedQueue models a busy proxy: ordinary
// register events keep arriving faster than a datagram can carry them, and each
// is larger than a heartbeat, so under msgLen-descending order the heartbeat
// loses every tie.
func TestConnectionHeartbeatSurvivesSaturatedQueue(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 50000, false)
	defer ct.Stop()

	ct.queueHeartbeat()

	// Twenty gossip rounds of sustained load, ~1.3 seconds of real gossip.
	for round := 0; round < 20; round++ {
		for i := 0; i < 200; i++ {
			ct.queueEvent(ConnectionEvent{
				Type:       ConnectionEventRegister,
				AccountID:  int64(round*200 + i),
				Username:   "a-fairly-long-username@customer.example.com",
				Protocol:   "IMAP",
				ClientAddr: "203.0.113.44:44321",
				Timestamp:  time.Now(),
				InstanceID: "inst-a",
			})
		}

		for _, msg := range ct.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
			event, err := decodeConnectionEvent(msg)
			if err != nil {
				t.Fatalf("decode broadcast: %v", err)
			}
			if event.Type == ConnectionEventStateSnapshot {
				return // heartbeat transmitted
			}
		}
	}

	t.Error("the liveness heartbeat was never transmitted in 20 gossip rounds of ordinary load: " +
		"peers will purge this instance's connection counts after the staleness threshold")
}

// TestIPLimitHeartbeatSurvivesSaturatedQueue is the per-IP equivalent.
func TestIPLimitHeartbeatSurvivesSaturatedQueue(t *testing.T) {
	tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 50000)
	defer tracker.Stop()

	tracker.queueEvent(IPLimitEvent{
		Type:       IPLimitEventStateSnapshot,
		Protocol:   "IMAP",
		Timestamp:  time.Now(),
		InstanceID: "inst-a",
	})

	for round := 0; round < 20; round++ {
		for i := 0; i < 200; i++ {
			tracker.queueEvent(IPLimitEvent{
				Type:       IPLimitEventIncrement,
				IP:         fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:dddd:%04x:%04x", round, i),
				Protocol:   "IMAP",
				Timestamp:  time.Now(),
				InstanceID: "inst-a",
			})
		}

		for _, msg := range tracker.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
			event, err := decodeIPLimitEvent(msg)
			if err != nil {
				t.Fatalf("decode broadcast: %v", err)
			}
			if event.Type == IPLimitEventStateSnapshot {
				return // heartbeat transmitted
			}
		}
	}

	t.Error("the liveness heartbeat was never transmitted in 20 gossip rounds of ordinary load: " +
		"peers will purge this instance's per-IP counts after the staleness threshold")
}

// TestCriticalQueueTakesAtMostHalfTheBudget pins the other half of the same
// trade: kicks are drained first, but a burst of them must not take the whole
// datagram and stall ordinary events - including the heartbeat - behind it.
func TestCriticalQueueTakesAtMostHalfTheBudget(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 1000, false)
	defer ct.Stop()

	for i := 0; i < 100; i++ {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  int64(i),
			Username:   "kicked@example.com",
			Protocol:   "IMAP",
			Timestamp:  time.Now(),
			InstanceID: "inst-a",
		})
	}
	ct.queueEvent(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  9999,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  time.Now(),
		InstanceID: "inst-a",
	})

	kickBytes := 0
	sawRegister := false
	for _, msg := range ct.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
		event, err := decodeConnectionEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		if event.Type == ConnectionEventKick {
			kickBytes += gossipPerMsgOverhead + len(msg)
			continue
		}
		sawRegister = true
	}

	if kickBytes > gossipUDPLimit/2 {
		t.Errorf("a kick burst took %d of the %d-byte datagram budget, more than the half it may claim",
			kickBytes, gossipUDPLimit)
	}
	if !sawRegister {
		t.Error("a kick burst head-of-line-blocked ordinary traffic out of the datagram entirely")
	}
}

// ---------------------------------------------------------------------------
// Affinity: a DELETE and a later SET may be delivered either way round, and a
// SET applied after the DELETE silently wipes an affinity that is in use.
// Affinity has no push/pull provider, so nothing repairs it afterwards.
// ---------------------------------------------------------------------------

func newTestAffinityManager() *AffinityManager {
	return &AffinityManager{
		affinityMap: make(map[string]*AffinityInfo),
		enabled:     true,
		defaultTTL:  time.Hour,
		queue:       newGossipQueue("affinity", nil, maxAffinityEventQueueSize),
	}
}

func TestAffinityDeleteAndSetConvergeInEitherOrder(t *testing.T) {
	const user = "user@example.com"

	setAt := time.Now().Add(-2 * time.Second)
	deleteAt := setAt.Add(time.Second)

	set := AffinityEvent{
		Type:      AffinityEventSet,
		EventID:   "set-1",
		Username:  user,
		Backend:   "backend1:143",
		Protocol:  "imap",
		Timestamp: setAt,
		NodeID:    "node-b",
		TTL:       time.Hour,
	}
	del := AffinityEvent{
		Type:      AffinityEventDelete,
		EventID:   "delete-1",
		Username:  user,
		Protocol:  "imap",
		Timestamp: deleteAt,
		NodeID:    "node-b",
	}

	for _, tc := range []struct {
		name  string
		order []AffinityEvent
	}{
		{"in order", []AffinityEvent{set, del}},
		{"reordered by the transmit queue", []AffinityEvent{del, set}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			am := newTestAffinityManager()
			for _, event := range tc.order {
				encoded, err := encodeAffinityEvent(event)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				am.HandleClusterEvent(encoded)
			}

			if backend, found := am.GetBackend(user, "imap"); found {
				t.Errorf("the delete was the newer event, yet the affinity survived as %q", backend)
			}
		})
	}
}

// TestAffinityLocalDeleteIsNotResurrectedByAnOlderSet covers the production
// path: connection_manager deletes an affinity whose backend went unhealthy,
// and a peer's older SET for the same user must not bring it back.
func TestAffinityLocalDeleteIsNotResurrectedByAnOlderSet(t *testing.T) {
	const user = "user@example.com"

	am := newTestAffinityManager()

	older := time.Now().Add(-time.Second)
	am.affinityMap[user+":imap"] = &AffinityInfo{
		Backend:    "backend1:143",
		Protocol:   "imap",
		AssignedAt: older,
		ExpiresAt:  older.Add(time.Hour),
		NodeID:     "node-b",
	}
	am.DeleteBackend(user, "imap")

	encoded, err := encodeAffinityEvent(AffinityEvent{
		Type:      AffinityEventSet,
		EventID:   "set-late",
		Username:  user,
		Backend:   "backend1:143",
		Protocol:  "imap",
		Timestamp: older,
		NodeID:    "node-b",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	am.HandleClusterEvent(encoded)

	if backend, found := am.GetBackend(user, "imap"); found {
		t.Errorf("a SET older than this node's delete resurrected the affinity as %q", backend)
	}
}

// TestAffinityRetransmissionIsAppliedOnce covers LOW 6: memberlist hands the
// same broadcast out several times, and without an event ID every copy is
// re-applied and re-persisted.
func TestAffinityRetransmissionIsAppliedOnce(t *testing.T) {
	store := &countingAffinityStore{}
	am := newTestAffinityManager()
	am.SetPersistStore(store)

	encoded, err := encodeAffinityEvent(AffinityEvent{
		Type:      AffinityEventSet,
		EventID:   "set-1",
		Username:  "user@example.com",
		Backend:   "backend1:143",
		Protocol:  "imap",
		Timestamp: time.Now(),
		NodeID:    "node-b",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	for i := 0; i < 5; i++ {
		am.HandleClusterEvent(encoded)
	}
	am.wg.Wait()

	if sets := store.setCount(); sets != 1 {
		t.Errorf("a retransmitted affinity event was persisted %d times, want 1", sets)
	}
}

// TestAffinityQueuedEventCarriesEventID is the enqueue-side half of LOW 6.
func TestAffinityQueuedEventCarriesEventID(t *testing.T) {
	am := newTestAffinityManager()
	am.queueEvent(AffinityEvent{
		Type:      AffinityEventSet,
		Username:  "user@example.com",
		Backend:   "backend1:143",
		Protocol:  "imap",
		Timestamp: time.Now(),
		NodeID:    "node-a",
		TTL:       time.Hour,
	})

	msgs := am.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 queued affinity event, got %d", len(msgs))
	}
	event, err := decodeAffinityEvent(msgs[0])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.EventID == "" {
		t.Error("affinity events carry no event ID, so receivers cannot suppress retransmissions")
	}
}

// ---------------------------------------------------------------------------
// Rate limiter: USERNAME_FAILURE and USERNAME_SUCCESS encode to the same length
// (both type strings are 16 characters), so the pair is a coin flip; the same
// applies to BLOCK_IP and UNBLOCK_IP.
// ---------------------------------------------------------------------------

func TestUsernameFailureAndSuccessConvergeInEitherOrder(t *testing.T) {
	const username = "user@example.com"

	failedAt := time.Now().Add(-2 * time.Second)
	succeededAt := failedAt.Add(time.Second)

	failure := RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		EventID:   "failure-1",
		Username:  username,
		Timestamp: failedAt,
		NodeID:    "node-b",
	}
	success := RateLimitEvent{
		Type:      RateLimitEventUsernameSuccess,
		EventID:   "success-1",
		Username:  username,
		Timestamp: succeededAt,
		NodeID:    "node-b",
	}

	for _, tc := range []struct {
		name  string
		order []RateLimitEvent
	}{
		{"in order", []RateLimitEvent{failure, success}},
		{"reordered by the transmit queue", []RateLimitEvent{success, failure}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crl := newTestClusterRateLimiter(t)
			crl.syncBlocks = true
			crl.syncFailureCounts = true

			for _, event := range tc.order {
				encoded, err := encodeRateLimitEvent(event)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				crl.HandleClusterEvent(encoded)
			}

			if got := crl.limiter.getUsernameFailureCount(username); got != 0 {
				t.Errorf("the success was the newer event, yet %d failure(s) remain", got)
			}
		})
	}
}

func TestBlockAndUnblockConvergeInEitherOrder(t *testing.T) {
	const ip = "203.0.113.7"

	blockedAt := time.Now().Add(-2 * time.Second)
	unblockedAt := blockedAt.Add(time.Second)

	block := RateLimitEvent{
		Type:         RateLimitEventBlockIP,
		EventID:      "block-1",
		IP:           ip,
		Timestamp:    blockedAt,
		NodeID:       "node-b",
		BlockedUntil: blockedAt.Add(15 * time.Minute),
		FailureCount: 10,
		Protocol:     "test",
	}
	unblock := RateLimitEvent{
		Type:      RateLimitEventUnblockIP,
		EventID:   "unblock-1",
		IP:        ip,
		Timestamp: unblockedAt,
		NodeID:    "node-b",
	}

	for _, tc := range []struct {
		name  string
		order []RateLimitEvent
	}{
		{"in order", []RateLimitEvent{block, unblock}},
		{"reordered by the transmit queue", []RateLimitEvent{unblock, block}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crl := newTestClusterRateLimiter(t)
			crl.syncBlocks = true

			for _, event := range tc.order {
				encoded, err := encodeRateLimitEvent(event)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				crl.HandleClusterEvent(encoded)
			}

			crl.limiter.ipMu.RLock()
			_, blocked := crl.limiter.blockedIPs[ip]
			crl.limiter.ipMu.RUnlock()

			if blocked {
				t.Error("the unblock was the newer event, yet the IP is still blocked")
			}
		})
	}
}

// TestUsernameSuccessDoesNotClearANewerFailure is the other direction: a
// success delivered after a failure that actually happened later must not wipe
// the failure that is still current.
func TestUsernameSuccessDoesNotClearANewerFailure(t *testing.T) {
	const username = "user@example.com"

	crl := newTestClusterRateLimiter(t)
	succeededAt := time.Now().Add(-2 * time.Second)

	for _, event := range []RateLimitEvent{
		{
			Type:      RateLimitEventUsernameFailure,
			EventID:   "failure-late",
			Username:  username,
			Timestamp: succeededAt.Add(time.Second),
			NodeID:    "node-b",
		},
		{
			Type:      RateLimitEventUsernameSuccess,
			EventID:   "success-early",
			Username:  username,
			Timestamp: succeededAt,
			NodeID:    "node-b",
		},
	} {
		encoded, err := encodeRateLimitEvent(event)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		crl.HandleClusterEvent(encoded)
	}

	if got := crl.limiter.getUsernameFailureCount(username); got != 1 {
		t.Errorf("an older success cleared a newer failure: count = %d, want 1", got)
	}
}

// TestUsernameFailureDoesNotRewindTheLastFailureTimestamp covers the three-event
// interleaving the pairwise guard misses: a failure delivered out of order used
// to overwrite LastFailure with its own older stamp, after which a success older
// than the newest failure passed the guard and wiped the whole count.
//
// The handler cannot separate the two failures - it keeps a count, not a ledger -
// so the older one stays counted; what it must never do is lose the newer one.
func TestUsernameFailureDoesNotRewindTheLastFailureTimestamp(t *testing.T) {
	const username = "user@example.com"

	crl := newTestClusterRateLimiter(t)

	first := time.Now().Add(-3 * time.Second)
	succeeded := first.Add(time.Second)
	newest := succeeded.Add(time.Second)

	// Delivered newest failure, older failure, then the success between them.
	for _, event := range []RateLimitEvent{
		{
			Type:      RateLimitEventUsernameFailure,
			EventID:   "failure-newest",
			Username:  username,
			Timestamp: newest,
			NodeID:    "node-b",
		},
		{
			Type:      RateLimitEventUsernameFailure,
			EventID:   "failure-first",
			Username:  username,
			Timestamp: first,
			NodeID:    "node-b",
		},
		{
			Type:      RateLimitEventUsernameSuccess,
			EventID:   "success-1",
			Username:  username,
			Timestamp: succeeded,
			NodeID:    "node-b",
		},
	} {
		encoded, err := encodeRateLimitEvent(event)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		crl.HandleClusterEvent(encoded)
	}

	if got := crl.limiter.getUsernameFailureCount(username); got == 0 {
		t.Error("a success older than the newest failure wiped the count: an out-of-order failure rewound LastFailure")
	}
}

// ---------------------------------------------------------------------------
// Connection and per-IP counters: register/unregister and increment/decrement
// are a pair from one instance, so their timestamps are comparable. Reversed
// delivery must not leave a phantom connection, which would count against the
// per-user and per-IP limits until push/pull happened to repair it.
// ---------------------------------------------------------------------------

func TestConnectionRegisterAndUnregisterConvergeInEitherOrder(t *testing.T) {
	const accountID int64 = 42

	registeredAt := time.Now().Add(-2 * time.Second)
	unregisteredAt := registeredAt.Add(time.Second)

	register := ConnectionEvent{
		Type:       ConnectionEventRegister,
		EventID:    "register-1",
		AccountID:  accountID,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  registeredAt,
		InstanceID: "inst-b",
	}
	unregister := ConnectionEvent{
		Type:       ConnectionEventUnregister,
		EventID:    "unregister-1",
		AccountID:  accountID,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		ClientAddr: "203.0.113.5:44321",
		Timestamp:  unregisteredAt,
		InstanceID: "inst-b",
	}

	for _, tc := range []struct {
		name  string
		order []ConnectionEvent
	}{
		{"in order", []ConnectionEvent{register, unregister}},
		{"reordered by the transmit queue", []ConnectionEvent{unregister, register}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
			defer ct.Stop()

			for _, event := range tc.order {
				encoded, err := encodeConnectionEvent(event)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				ct.HandleClusterEvent(encoded)
			}

			if got := ct.GetConnectionCount(accountID); got != 0 {
				t.Errorf("the connection closed, yet %d phantom connection(s) remain", got)
			}
		})
	}
}

// TestConnectionUnregisterDoesNotCancelALaterConnection is the guard against
// over-correcting: a decrement held for a reordered pair must only cancel the
// register it is paired with, never a genuinely newer connection.
func TestConnectionUnregisterDoesNotCancelALaterConnection(t *testing.T) {
	const accountID int64 = 42

	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 100, false)
	defer ct.Stop()

	unregisteredAt := time.Now().Add(-time.Second)

	for _, event := range []ConnectionEvent{
		{
			Type:       ConnectionEventUnregister,
			EventID:    "unregister-1",
			AccountID:  accountID,
			Username:   "user@example.com",
			Protocol:   "IMAP",
			ClientAddr: "203.0.113.5:44321",
			Timestamp:  unregisteredAt,
			InstanceID: "inst-b",
		},
		{
			Type:       ConnectionEventRegister,
			EventID:    "register-new",
			AccountID:  accountID,
			Username:   "user@example.com",
			Protocol:   "IMAP",
			ClientAddr: "203.0.113.5:44321",
			Timestamp:  unregisteredAt.Add(time.Second),
			InstanceID: "inst-b",
		},
	} {
		encoded, err := encodeConnectionEvent(event)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		ct.HandleClusterEvent(encoded)
	}

	if got := ct.GetConnectionCount(accountID); got != 1 {
		t.Errorf("a connection opened after the unregister was cancelled by it: count = %d, want 1", got)
	}
}

func TestIPIncrementAndDecrementConvergeInEitherOrder(t *testing.T) {
	const ip = "203.0.113.9"

	incrementedAt := time.Now().Add(-2 * time.Second)
	decrementedAt := incrementedAt.Add(time.Second)

	increment := IPLimitEvent{
		Type:       IPLimitEventIncrement,
		EventID:    "increment-1",
		IP:         ip,
		Protocol:   "IMAP",
		Timestamp:  incrementedAt,
		NodeID:     "inst-b",
		InstanceID: "inst-b",
	}
	decrement := IPLimitEvent{
		Type:       IPLimitEventDecrement,
		EventID:    "decrement-1",
		IP:         ip,
		Protocol:   "IMAP",
		Timestamp:  decrementedAt,
		NodeID:     "inst-b",
		InstanceID: "inst-b",
	}

	for _, tc := range []struct {
		name  string
		order []IPLimitEvent
	}{
		{"in order", []IPLimitEvent{increment, decrement}},
		{"reordered by the transmit queue", []IPLimitEvent{decrement, increment}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
			defer tracker.Stop()

			for _, event := range tc.order {
				tracker.HandleClusterEvent(gossipEncode(t, event))
			}

			if got := tracker.GetIPCount(ip); got != 0 {
				t.Errorf("the connection closed, yet %d phantom per-IP connection(s) remain", got)
			}
		})
	}
}

func TestIPDecrementDoesNotCancelALaterConnection(t *testing.T) {
	const ip = "203.0.113.9"

	tracker := NewIPLimitTracker("IMAP", "inst-a", nil, 0)
	defer tracker.Stop()

	decrementedAt := time.Now().Add(-time.Second)

	tracker.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventDecrement,
		EventID:    "decrement-1",
		IP:         ip,
		Protocol:   "IMAP",
		Timestamp:  decrementedAt,
		NodeID:     "inst-b",
		InstanceID: "inst-b",
	}))
	tracker.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventIncrement,
		EventID:    "increment-new",
		IP:         ip,
		Protocol:   "IMAP",
		Timestamp:  decrementedAt.Add(time.Second),
		NodeID:     "inst-b",
		InstanceID: "inst-b",
	}))

	if got := tracker.GetIPCount(ip); got != 1 {
		t.Errorf("a connection opened after the decrement was cancelled by it: count = %d, want 1", got)
	}
}

// TestDeferredDecrementAgesOnArrivalNotOnTheRemoteClock covers a peer whose
// clock lags: its events carry timestamps older than anything this node's clock
// produces, so ageing a held decrement against the local clock retires it the
// moment it is stored and the increment it was waiting for becomes a phantom
// connection counted against the per-user and per-IP limits.
func TestDeferredDecrementAgesOnArrivalNotOnTheRemoteClock(t *testing.T) {
	var held deferredDecrements

	// Well inside the staleness threshold that admits the event, well outside
	// the window the ledger prunes against.
	remoteNow := time.Now().Add(-90 * time.Second)

	held.hold("inst-b|42|203.0.113.5", remoteNow)
	held.prune(gossipDedupWindow)

	if !held.consume("inst-b|42|203.0.113.5", remoteNow) {
		t.Error("a decrement that had just arrived was pruned because the sending node's clock lags: " +
			"its increment will now be applied as a phantom connection")
	}
}

// countingAffinityStore counts write-throughs to the persistent store.
type countingAffinityStore struct {
	mu      sync.Mutex
	sets    int
	deletes int
}

func (s *countingAffinityStore) LoadAll(ctx context.Context) ([]affinitycache.AffinityEntry, error) {
	return nil, nil
}

func (s *countingAffinityStore) Set(ctx context.Context, entry affinitycache.AffinityEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets++
	return nil
}

func (s *countingAffinityStore) Delete(ctx context.Context, username, protocol string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	return nil
}

func (s *countingAffinityStore) Cleanup(ctx context.Context) (int64, error) { return 0, nil }
func (s *countingAffinityStore) Close() error                               { return nil }

func (s *countingAffinityStore) setCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sets
}
