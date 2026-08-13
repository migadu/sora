package proxy

import (
	"fmt"
	"testing"
)

// TestConsistentHash_SameHostDifferentPorts proves PROXY-6.
//
// A pool may legitimately contain two backend instances on the SAME machine
// listening on DIFFERENT ports (e.g. two sora IMAP backends on 10.0.0.1:143
// and 10.0.0.1:144). ConsistentHash.hash() strips the port via
// net.SplitHostPort, so both backends produce the IDENTICAL set of 150 virtual
// node hashes. AddBackend then does ring[hash] = backend, so the second
// AddBackend silently OVERWRITES every virtual node of the first.
//
// Observable consequences, all via the exported API:
//   - Size() reports 1 instead of 2
//   - GetAllBackends() returns only the last-added backend
//   - GetBackend() never routes any key to the first backend (0% of traffic)
//   - RemoveBackend("10.0.0.1:144") empties the ring entirely, evicting
//     "10.0.0.1:143" which was never removed
func TestConsistentHash_SameHostDifferentPorts(t *testing.T) {
	const (
		backendA = "10.0.0.1:143"
		backendB = "10.0.0.1:144"
	)

	ch := NewConsistentHash(150)
	ch.AddBackend(backendA)
	ch.AddBackend(backendB)

	// --- 1. Size() must count both distinct pool members -------------------
	if got := ch.Size(); got != 2 {
		t.Errorf("PROXY-6: Size() = %d, want 2 after adding %q and %q; "+
			"the port-stripping hash collapsed both backends onto identical ring positions",
			got, backendA, backendB)
	}

	// --- 2. GetAllBackends() must list both --------------------------------
	all := ch.GetAllBackends()
	seen := make(map[string]bool, len(all))
	for _, b := range all {
		seen[b] = true
	}
	if !seen[backendA] || !seen[backendB] {
		t.Errorf("PROXY-6: GetAllBackends() = %v, want both %q and %q present",
			all, backendA, backendB)
	}

	// --- 3. Routing must actually reach both backends ----------------------
	// With a correct ring each backend owns roughly half the keyspace.
	// With the collision, backendA owns ZERO virtual nodes and is unreachable.
	const keys = 2000
	counts := map[string]int{}
	for i := 0; i < keys; i++ {
		counts[ch.GetBackend(fmt.Sprintf("user%d@example.com", i))]++
	}
	if counts[backendA] == 0 {
		t.Errorf("PROXY-6: GetBackend() routed 0 of %d keys to %q (all traffic went to %q, count=%d); "+
			"the first backend owns no virtual nodes and receives no traffic",
			keys, backendA, backendB, counts[backendB])
	}
	if counts[backendB] == 0 {
		t.Errorf("PROXY-6: GetBackend() routed 0 of %d keys to %q", keys, backendB)
	}

	// --- 4. Removing one backend must not evict the other ------------------
	ch.RemoveBackend(backendB)

	if got := ch.Size(); got != 1 {
		t.Errorf("PROXY-6: after RemoveBackend(%q), Size() = %d, want 1 (%q must survive)",
			backendB, got, backendA)
	}
	if got := ch.GetBackend("user0@example.com"); got != backendA {
		t.Errorf("PROXY-6: after RemoveBackend(%q), GetBackend() = %q, want %q; "+
			"removing one backend deleted the other's ring entries, leaving no route",
			backendB, got, backendA)
	}
}
