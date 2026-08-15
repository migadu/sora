package server

import (
	"bytes"
	"encoding/gob"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// IPLIM-1: IPLimitTracker must converge - no phantom per-IP counts.
//
// These tests drive the real server.IPLimitTracker through the two entry points
// the cluster manager uses in production:
//
//   - per-event gossip: cluster/manager.go notifyIPLimitHandlers(msg[2:]) ->
//     the func([]byte) registered by RegisterIPLimitHandler, i.e.
//     HandleClusterEvent with the 2-byte 'IP' marker already stripped;
//   - full state: memberlist push/pull -> MergeRemoteState -> the merge func
//     registered by RegisterStateProvider, i.e. mergeRemoteState.
//
// Full state travels over push/pull, so the snapshot scenarios below are
// delivered there; the properties asserted (staleness guard, removal pass,
// liveness purge, no phantom lockout) are the same ones the gossip-delivered
// snapshots used to assert.
//
// The trackers are built with a nil cluster.Manager, which only skips the
// outbound broadcast/goroutines; every piece of state-mutation logic under test
// (handleRemoteIncrement, handleRemoteDecrement, reconcileState,
// performCleanup) is identical.
// ---------------------------------------------------------------------------

// gossipEncode encodes an IPLimitEvent the way queueEvent does.
func gossipEncode(t *testing.T, ev IPLimitEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(ev); err != nil {
		t.Fatalf("failed to gob-encode gossip event: %v", err)
	}
	return buf.Bytes()
}

// deliverIncrement simulates a peer's IP_INCREMENT arriving over gossip.
func deliverIncrement(t *testing.T, tr *IPLimitTracker, fromInstance, protocol, ip string, ts time.Time) {
	t.Helper()
	tr.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventIncrement,
		IP:         ip,
		Protocol:   protocol,
		Timestamp:  ts,
		NodeID:     fromInstance,
		InstanceID: fromInstance,
	}))
}

// deliverDecrement simulates a peer's IP_DECREMENT arriving over gossip.
func deliverDecrement(t *testing.T, tr *IPLimitTracker, fromInstance, protocol, ip string, ts time.Time) {
	t.Helper()
	tr.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventDecrement,
		IP:         ip,
		Protocol:   protocol,
		Timestamp:  ts,
		NodeID:     fromInstance,
		InstanceID: fromInstance,
	}))
}

// deliverSnapshot simulates a peer's full state arriving over memberlist
// push/pull, which is the transport full state uses: it outgrows a gossip
// datagram, and push/pull runs over TCP.
func deliverSnapshot(t *testing.T, tr *IPLimitTracker, fromInstance, protocol string, sentAt time.Time, snap *IPLimitStateSnapshot) {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(snap); err != nil {
		t.Fatalf("failed to gob-encode push/pull state: %v", err)
	}
	tr.mergeRemoteState(buf.Bytes())
}

// silence ages an instance's last-seen mark past the staleness threshold, the
// state a peer reaches when it stops heartbeating.
func silence(tr *IPLimitTracker, instanceID string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.instanceLastSeen[instanceID] = time.Now().Add(-2 * staleInstanceThreshold)
}

// snapshotOf projects a tracker's state the way (*IPLimitTracker).stateSnapshot
// does, and is used to produce the payload a peer node would legitimately send.
func snapshotOf(tr *IPLimitTracker, at time.Time) *IPLimitStateSnapshot {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	connections := make(map[string]IPConnectionData)
	for ip, info := range tr.connections {
		if info.TotalCount == 0 {
			continue
		}
		localInstances := make(map[string]int)
		for instanceID, count := range info.LocalInstances {
			if count > 0 {
				localInstances[instanceID] = count
			}
		}
		connections[ip] = IPConnectionData{
			IP:             ip,
			LocalInstances: localInstances,
			TotalCount:     info.TotalCount,
			LastUpdate:     info.LastUpdate,
		}
	}

	return &IPLimitStateSnapshot{
		InstanceID:  tr.instanceID,
		Timestamp:   at,
		Connections: connections,
	}
}

// instanceCounts returns a copy of the per-instance attribution for an IP.
func instanceCounts(tr *IPLimitTracker, ip string) map[string]int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	out := map[string]int{}
	if info, ok := tr.connections[ip]; ok {
		for k, v := range info.LocalInstances {
			out[k] = v
		}
	}
	return out
}

// ===========================================================================
// (1) A received snapshot must not overwrite this node's fresher view of a
//     third-party instance, resurrecting counts already decremented to zero.
// ===========================================================================

func TestIPLimitTrackerSnapshotResurrectsDecrementedThirdPartyCount(t *testing.T) {
	const proto = "IMAP"
	const ip = "203.0.113.7"

	now := time.Now()
	tenMinAgo := now.Add(-10 * time.Minute)

	// --- Peer B builds a legitimate view of the cluster at T-10m -----------
	// B owns 1 connection from this IP and has learned (via gossip from C)
	// that C owns 3 more.
	peerB := NewIPLimitTracker(proto, "inst-b", nil, 0)
	defer peerB.Stop()
	peerB.IncrementIP(ip)
	for i := 0; i < 3; i++ {
		deliverIncrement(t, peerB, "inst-c", proto, ip, tenMinAgo)
	}
	staleSnapshotFromB := snapshotOf(peerB, tenMinAgo) // what B gossips at T-10m

	// --- Node A (the tracker under test) -----------------------------------
	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	// A learns the same thing B knows.
	deliverIncrement(t, nodeA, "inst-b", proto, ip, tenMinAgo)
	for i := 0; i < 3; i++ {
		deliverIncrement(t, nodeA, "inst-c", proto, ip, tenMinAgo)
	}
	if got := nodeA.GetIPCount(ip); got != 4 {
		t.Fatalf("precondition: expected cluster count 4 for %s, got %d", ip, got)
	}

	// C's three connections close. A receives all three IP_DECREMENTs and its
	// view of the third party C is now the FRESHEST in the cluster.
	for i := 0; i < 3; i++ {
		deliverDecrement(t, nodeA, "inst-c", proto, ip, now)
	}
	if got := nodeA.GetIPCount(ip); got != 1 {
		t.Fatalf("precondition: after C's decrements expected 1, got %d (instances=%v)",
			got, instanceCounts(nodeA, ip))
	}

	// B's OLD snapshot (10 minutes stale, and stale w.r.t. A's per-instance
	// view of C) is delivered late / out of order. Gossip reorders freely.
	deliverSnapshot(t, nodeA, "inst-b", proto, tenMinAgo, staleSnapshotFromB)

	// Correct behaviour: a stale snapshot must not clobber a fresher view of a
	// third-party instance. The real cluster count is still 1 (B's connection).
	if got := nodeA.GetIPCount(ip); got != 1 {
		t.Errorf("IPLIM-1(1): stale snapshot from inst-b (age %v) resurrected already-decremented "+
			"third-party counts: GetIPCount(%s) = %d, want 1 (instances=%v)",
			time.Since(tenMinAgo).Round(time.Second), ip, got, instanceCounts(nodeA, ip))
	}
}

// ===========================================================================
// (2) An IP absent from a later snapshot must be retired: a snapshot has to
//     remove what the sender no longer reports, not only add and raise.
// ===========================================================================

func TestIPLimitTrackerSnapshotHasNoRemovalPass(t *testing.T) {
	const proto = "IMAP"
	const goneIP = "203.0.113.10"
	const liveIP = "203.0.113.11"

	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	t0 := time.Now().Add(-2 * time.Minute)

	// Snapshot #1 from B: B owns 2 conns from goneIP and 1 from liveIP.
	deliverSnapshot(t, nodeA, "inst-b", proto, t0, &IPLimitStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  t0,
		Connections: map[string]IPConnectionData{
			goneIP: {IP: goneIP, LocalInstances: map[string]int{"inst-b": 2}, TotalCount: 2, LastUpdate: t0},
			liveIP: {IP: liveIP, LocalInstances: map[string]int{"inst-b": 1}, TotalCount: 1, LastUpdate: t0},
		},
	})
	if got := nodeA.GetIPCount(goneIP); got != 2 {
		t.Fatalf("precondition: expected 2 for %s, got %d", goneIP, got)
	}

	// goneIP's two connections close on B. A misses both IP_DECREMENTs
	// (packet loss / queue overflow — the exact reason snapshots exist).
	// B's NEXT snapshot therefore no longer mentions goneIP at all.
	t1 := time.Now()
	deliverSnapshot(t, nodeA, "inst-b", proto, t1, &IPLimitStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  t1,
		Connections: map[string]IPConnectionData{
			liveIP: {IP: liveIP, LocalInstances: map[string]int{"inst-b": 1}, TotalCount: 1, LastUpdate: t1},
		},
	})

	// Even the periodic janitor gets a chance.
	nodeA.performCleanup()

	if got := nodeA.GetIPCount(goneIP); got != 0 {
		t.Errorf("IPLIM-1(2): IP absent from the newer snapshot kept its stale count: "+
			"GetIPCount(%s) = %d, want 0 (instances=%v)", goneIP, got, instanceCounts(nodeA, goneIP))
	}
	if got := nodeA.GetIPCount(liveIP); got != 1 {
		t.Errorf("sanity: live IP count = %d, want 1", got)
	}
}

// ===========================================================================
// (3) Counts attributed to an instance must not survive that instance's
//     restart or silence: liveness is what retires them.
// ===========================================================================

func TestIPLimitTrackerNoLivenessPurgeForDeadInstance(t *testing.T) {
	const proto = "IMAP"
	const ip = "203.0.113.20"

	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	fresh := time.Now()
	deliverSnapshot(t, nodeA, "inst-b", proto, fresh, &IPLimitStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  fresh,
		Connections: map[string]IPConnectionData{
			ip: {IP: ip, LocalInstances: map[string]int{"inst-b": 5}, TotalCount: 5, LastUpdate: fresh},
		},
	})
	if got := nodeA.GetIPCount(ip); got != 5 {
		t.Fatalf("precondition: expected 5 for %s, got %d", ip, got)
	}

	// inst-b is hard-killed: its 5 connections die with it and it never
	// heartbeats, gossips a decrement or exchanges state again. Simulate the
	// passage of time by ageing its last-seen mark and the entry's clock (a
	// CLOCK simulation only — no tracker logic is bypassed).
	silence(nodeA, "inst-b")
	nodeA.mu.Lock()
	nodeA.connections[ip].LastUpdate = time.Now().Add(-24 * time.Hour)
	nodeA.mu.Unlock()

	// Run the janitor 288 times == 24h at the 5-minute cleanupRoutine interval.
	for i := 0; i < 288; i++ {
		nodeA.performCleanup()
	}

	if got := nodeA.GetIPCount(ip); got != 0 {
		t.Errorf("IPLIM-1(3): counts from a dead/restarted instance survived 24h of silence "+
			"and 288 cleanup cycles: GetIPCount(%s) = %d, want 0 (instances=%v)",
			ip, got, instanceCounts(nodeA, ip))
	}
}

// ===========================================================================
// (4) performCleanup must reap an entry with a positive count whose owner has
//     gone silent, not only the entries that already sit at zero.
// ===========================================================================

func TestIPLimitTrackerCleanupOnlyRemovesAlreadyZeroEntries(t *testing.T) {
	const proto = "IMAP"
	const zeroIP = "203.0.113.30"    // control: arrives already at zero
	const phantomIP = "203.0.113.31" // phantom: positive count, no owner alive

	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	old := time.Now().Add(-6 * time.Hour)
	deliverSnapshot(t, nodeA, "inst-b", proto, time.Now(), &IPLimitStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  time.Now(),
		Connections: map[string]IPConnectionData{
			zeroIP:    {IP: zeroIP, LocalInstances: map[string]int{"inst-b": 0}, TotalCount: 0, LastUpdate: old},
			phantomIP: {IP: phantomIP, LocalInstances: map[string]int{"inst-b": 7}, TotalCount: 7, LastUpdate: old},
		},
	})

	// inst-b then goes silent: its counts have nobody to retire them.
	silence(nodeA, "inst-b")

	nodeA.performCleanup()

	// Control: proves performCleanup actually ran and does reap zero entries.
	nodeA.mu.RLock()
	_, zeroStillThere := nodeA.connections[zeroIP]
	_, phantomStillThere := nodeA.connections[phantomIP]
	nodeA.mu.RUnlock()

	if zeroStillThere {
		t.Fatalf("harness check failed: performCleanup did not even reap the zero-count entry %s", zeroIP)
	}
	t.Logf("control: performCleanup reaped the already-zero entry %s (so cleanup definitely ran)", zeroIP)

	if phantomStillThere || nodeA.GetIPCount(phantomIP) != 0 {
		t.Errorf("IPLIM-1(4): performCleanup left a phantom entry with TotalCount>0 owned by a "+
			"silent instance in place: GetIPCount(%s) = %d, want 0 (instances=%v)",
			phantomIP, nodeA.GetIPCount(phantomIP), instanceCounts(nodeA, phantomIP))
	}
}

// ===========================================================================
// (5) The practical consequence of the four above, through the real
//     ConnectionLimiter: an IP with zero connections anywhere in the cluster
//     must not be refused because of a count no instance still owns.
// ===========================================================================

func TestIPLimitTrackerPhantomCountLocksOutInnocentIP(t *testing.T) {
	const proto = "IMAP"
	const victimIP = "198.51.100.9"
	const maxPerIP = 3

	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	// A quiet accumulation of phantoms, all through the normal cluster API:
	//   - inst-b bounced while holding 2 connections (state, then silence)
	//   - inst-c's decrements were lost, then a stale state exchange re-raised it
	t0 := time.Now().Add(-3 * time.Minute)
	deliverSnapshot(t, nodeA, "inst-b", proto, t0, &IPLimitStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  t0,
		Connections: map[string]IPConnectionData{
			victimIP: {IP: victimIP, LocalInstances: map[string]int{"inst-b": 2, "inst-c": 2}, TotalCount: 4, LastUpdate: t0},
		},
	})
	// inst-c honestly reports it has nothing left...
	deliverSnapshot(t, nodeA, "inst-c", proto, time.Now(), &IPLimitStateSnapshot{
		InstanceID:  "inst-c",
		Timestamp:   time.Now(),
		Connections: map[string]IPConnectionData{}, // no connections at all
	})
	// ...inst-b stops heartbeating after its bounce...
	silence(nodeA, "inst-b")
	// ...and the janitor gets its chance.
	nodeA.performCleanup()

	// Ground truth: nobody anywhere in the cluster holds a connection from this IP.
	phantom := nodeA.GetIPCount(victimIP)
	local := 0
	nodeA.mu.RLock()
	if info, ok := nodeA.connections[victimIP]; ok {
		local = info.LocalCount
	}
	nodeA.mu.RUnlock()
	if local != 0 {
		t.Fatalf("precondition: this node should own 0 local connections, got %d", local)
	}
	t.Logf("tracker reports cluster-wide count %d for %s (real connections: 0, instances=%v)",
		phantom, victimIP, instanceCounts(nodeA, victimIP))

	// Wire the tracker into a real ConnectionLimiter exactly as
	// NewConnectionLimiterWithCluster does.
	cl := NewConnectionLimiter(proto, 1000, maxPerIP)
	cl.ipTracker = nodeA
	cl.instanceID = "inst-a"

	addr := &net.TCPAddr{IP: net.ParseIP(victimIP), Port: 44444}
	if err := cl.CanAcceptWithRealIP(addr, ""); err != nil {
		t.Errorf("IPLIM-1(5): a first, genuine connection from %s was rejected because of phantom "+
			"gossip state: %v (tracker count %d against max_per_ip %d, with no connection anywhere "+
			"in the cluster) - the limiter trusts GetIPCount verbatim, so this is a permanent per-IP ban",
			victimIP, err, phantom, maxPerIP)
	}
}

// ===========================================================================
// The same scenarios against ConnectionTracker.reconcileState, the other
// tracker on this bus: the two must converge the same way, since a per-user
// count and a per-IP count are repaired by the same push/pull exchange.
// ===========================================================================

func TestConnectionTrackerReconcileStateConverges(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "", "", "inst-a", nil, 0, 0, 10000, false)
	defer ct.Stop()

	const accountID int64 = 4242

	// Peer inst-b reports 2 connections for the account.
	ct.reconcileState(&ConnectionStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  time.Now(),
		Connections: map[int64]UserConnectionData{
			accountID: {AccountID: accountID, Username: "u@example.com",
				PerIPCount: map[string]int{"203.0.113.50": 2}, LastUpdate: time.Now()},
		},
	})
	if got := ct.GetConnectionCount(accountID); got != 2 {
		t.Fatalf("precondition: expected 2, got %d", got)
	}

	// A 10-minute-old snapshot is rejected outright.
	ct.reconcileState(&ConnectionStateSnapshot{
		InstanceID: "inst-b",
		Timestamp:  time.Now().Add(-10 * time.Minute),
		Connections: map[int64]UserConnectionData{
			accountID: {AccountID: accountID, Username: "u@example.com",
				PerIPCount: map[string]int{"203.0.113.50": 99}, LastUpdate: time.Now()},
		},
	})
	if got := ct.GetConnectionCount(accountID); got != 2 {
		t.Errorf("contrast: stale snapshot should have been ignored, count = %d, want 2", got)
	}

	// The connections close and the unregister events are lost; inst-b's next
	// snapshot simply omits the account. reconcileState's first pass removes it.
	ct.reconcileState(&ConnectionStateSnapshot{
		InstanceID:  "inst-b",
		Timestamp:   time.Now(),
		Connections: map[int64]UserConnectionData{},
	})
	if got := ct.GetConnectionCount(accountID); got != 0 {
		t.Errorf("contrast: reconcileState should have removed the stale entry, count = %d, want 0", got)
	}
}

// ===========================================================================
// (6) Rolling upgrade: a node running a build that still gossips full state
//     sends IP_STATE_SNAPSHOT with no Protocol, so it reaches every protocol's
//     tracker. Applying it would inject one protocol's counts into another and
//     retire the counts this tracker legitimately holds for the sender. Such an
//     event may only be read as proof that the sender is alive.
// ===========================================================================

func TestIPLimitTrackerIgnoresGossipedFullStateFromOldBuild(t *testing.T) {
	const proto = "IMAP"
	const heldIP = "203.0.113.40"
	const foreignIP = "203.0.113.41"

	nodeA := NewIPLimitTracker(proto, "inst-a", nil, 0)
	defer nodeA.Stop()

	deliverIncrement(t, nodeA, "inst-b", proto, heldIP, time.Now())
	if got := nodeA.GetIPCount(heldIP); got != 1 {
		t.Fatalf("precondition: expected 1 for %s, got %d", heldIP, got)
	}

	// The old build's snapshot has an empty Protocol and carries the counts of
	// whichever protocol that instance serves - here POP3 connections from a
	// different IP, and no mention of the IMAP connection this tracker knows.
	now := time.Now()
	nodeA.HandleClusterEvent(gossipEncode(t, IPLimitEvent{
		Type:       IPLimitEventStateSnapshot,
		Timestamp:  now,
		NodeID:     "inst-b",
		InstanceID: "inst-b",
		StateSnapshot: &IPLimitStateSnapshot{
			InstanceID: "inst-b",
			Timestamp:  now,
			Connections: map[string]IPConnectionData{
				foreignIP: {IP: foreignIP, LocalInstances: map[string]int{"inst-b": 9}, TotalCount: 9, LastUpdate: now},
			},
		},
	}))

	if got := nodeA.GetIPCount(foreignIP); got != 0 {
		t.Errorf("counts from another protocol were injected: GetIPCount(%s) = %d, want 0", foreignIP, got)
	}
	if got := nodeA.GetIPCount(heldIP); got != 1 {
		t.Errorf("this protocol's counts were retired by a foreign snapshot: GetIPCount(%s) = %d, want 1", heldIP, got)
	}

	// It still proves the sender is alive, so the janitor must not purge it.
	nodeA.performCleanup()
	if got := nodeA.GetIPCount(heldIP); got != 1 {
		t.Errorf("after cleanup GetIPCount(%s) = %d, want 1: the event marks inst-b as alive", heldIP, got)
	}
}
