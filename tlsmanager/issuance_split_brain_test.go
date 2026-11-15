package tlsmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// cluster.electLeader picks the lexicographically smallest node id among the members THIS
// node can see, with no quorum. A network partition therefore elects a leader on BOTH
// sides, and each side's leader believes it is the only one. Gossip leadership alone
// cannot fence certificate issuance: two leaders order the same domain, they race for the
// HTTP-01 challenge, and only the node actually answering port 80 can serve the token -
// so the other's validation FAILS, against Let's Encrypt's 5-failures-per-hostname-per-hour.
//
// The fence is a store that cannot be partitioned into two writable copies.

// fakeFence is one shared claim store, standing in for the database both partitions
// still reach. Like the database's locks, it lets a claim go at its expiry whatever its
// holder is still doing, and a release gives back only the claim it was granted with.
type fakeFence struct {
	mu     sync.Mutex
	held   map[string]fakeClaim
	ahead  time.Duration // how far the fence's clock runs ahead of this process's
	err    error
	grants int
	asks   int // TryHoldIssuance calls
}

// fakeClaim is a claim the fence holds: grant is its fencing token, and a zero expires
// never lapses.
type fakeClaim struct {
	grant   int
	expires time.Time
}

func newFakeFence() *fakeFence { return &fakeFence{held: map[string]fakeClaim{}} }

// now is the fence's clock. mu must be held.
func (f *fakeFence) now() time.Time { return time.Now().Add(f.ahead) }

func (f *fakeFence) TryHoldIssuance(_ context.Context, domain string, ttl time.Duration) (func(context.Context), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks++
	if f.err != nil {
		return nil, f.err
	}
	if claim, held := f.held[domain]; held && (claim.expires.IsZero() || f.now().Before(claim.expires)) {
		return nil, nil
	}
	f.grants++
	grant := f.grants
	f.held[domain] = fakeClaim{grant: grant, expires: f.now().Add(ttl)}
	return func(context.Context) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.held[domain].grant == grant {
			delete(f.held, domain)
		}
	}, nil
}

// at sets the fence's clock to read t now, which is how a test lets time pass for the
// claims the fence holds.
func (f *fakeFence) at(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ahead = time.Until(t)
}

func (f *fakeFence) askCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asks
}

func (f *fakeFence) grantCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants
}

// splitBrainNode builds a manager that believes it is the cluster leader, which is what
// every node on every side of a partition believes.
func splitBrainNode(fence CertificateFence) *Manager {
	coordinator := &fakeCoordinator{}
	coordinator.leader.Store(true)
	return &Manager{
		clusterManager: coordinator,
		rateLimitMap:   map[string]time.Time{},
		certFence:      fence,
	}
}

func TestOnlyOneOfTwoPartitionedLeadersMayIssue(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()

	nodeA := splitBrainNode(fence)
	nodeB := splitBrainNode(fence)

	if err := nodeA.refuseIssuance(domain); err != nil {
		t.Fatalf("the first leader must be allowed to issue: %v", err)
	}

	err := nodeB.refuseIssuance(domain)
	if err == nil {
		t.Fatal("both partitioned leaders were allowed to order a certificate for the same domain: " +
			"they race for the HTTP-01 challenge and the loser burns a failed validation")
	}
	if !errors.Is(err, errIssuanceDeferred) {
		t.Errorf("second leader refused with %v, want an errIssuanceDeferred", err)
	}
}

// TestClaimIsReleasedWhenTheCertificateLands keeps the fence from becoming a lock-out: a
// renewal must not have to wait out issuanceClaimTTL after a successful order.
func TestClaimIsReleasedWhenTheCertificateLands(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()

	node := splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, node)

	if err := node.refuseIssuance(domain); err != nil {
		t.Fatalf("first order refused: %v", err)
	}
	if err := gate.Put(context.Background(), domain, []byte("cert")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A later renewal on another node must find the claim free.
	other := splitBrainNode(fence)
	if err := other.refuseIssuance(domain); err != nil {
		t.Errorf("claim was not released when the certificate landed: %v", err)
	}
	if got := fence.grantCount(); got != 2 {
		t.Errorf("fence granted %d claims, want 2", got)
	}
}

// TestConcurrentHandshakesOnOneNodeShareItsClaim covers re-entrancy. Every handshake for
// an uncached domain reaches the gate, so a node must not read its own in-flight claim as
// another node's and refuse to finish the order it already started.
func TestConcurrentHandshakesOnOneNodeShareItsClaim(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	node := splitBrainNode(fence)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = node.refuseIssuance(domain)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent handshake %d on the claim holder was refused: %v", i, err)
		}
	}
	if got := fence.grantCount(); got != 1 {
		t.Errorf("one node took %d claims for one domain, want 1", got)
	}
}

// TestFailedOrderDoesNotHoldTheClaimPastItsExpiry: the claim is given back when the
// certificate is stored, and an order that fails stores none. autocert retries a failed
// renewal 30-60 minutes later, after the fence has let the claim go on its own
// (issuanceClaimTTL) and another node may have taken it. The retry must ask the fence
// again instead of reading its lapsed claim as still its own.
func TestFailedOrderDoesNotHoldTheClaimPastItsExpiry(t *testing.T) {
	const domain = "mail.example.com"

	setup := func(t *testing.T) (*fakeFence, *Manager) {
		fence := newFakeFence()
		node := splitBrainNode(fence)
		if err := node.refuseIssuance(domain); err != nil {
			t.Fatalf("first order refused: %v", err)
		}
		// The order fails, so nothing releases the claim; issuanceClaimTTL passes.
		node.claimMu.Lock()
		claim := node.issuanceClaims[domain]
		claim.expires = time.Now().Add(-time.Second)
		node.issuanceClaims[domain] = claim
		node.claimMu.Unlock()
		return fence, node
	}

	t.Run("taken by another node", func(t *testing.T) {
		// To the fence, the claim this node let lapse and another node then took
		// looks the same as the one it still records: held.
		_, node := setup(t)
		if err := node.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
			t.Errorf("retry after the claim lapsed and another node took it = %v, want errIssuanceDeferred", err)
		}
	})

	t.Run("free", func(t *testing.T) {
		fence, node := setup(t)
		fence.mu.Lock()
		delete(fence.held, domain) // lapsed, and nobody took it
		fence.mu.Unlock()
		if err := node.refuseIssuance(domain); err != nil {
			t.Fatalf("retry after the claim lapsed refused: %v", err)
		}
		if got := fence.grantCount(); got != 2 {
			t.Errorf("fence granted %d claims, want 2: the retry must take the claim anew", got)
		}
	})
}

// TestFenceFailureFallsBackToIssuing pins the availability choice: if the fence cannot be
// reached, ordering proceeds. An expired certificate takes the node's TLS down entirely,
// while the worst case of ordering unfenced is a duplicate order costing rate-limit budget.
func TestFenceFailureFallsBackToIssuing(t *testing.T) {
	fence := newFakeFence()
	fence.err = errors.New("database unreachable")

	node := splitBrainNode(fence)
	if err := node.refuseIssuance("mail.example.com"); err != nil {
		t.Errorf("an unreachable fence blocked issuance: %v; an expired certificate is worse "+
			"than a duplicate order", err)
	}
}

// TestNoFenceKeepsGossipOnlyBehaviour covers the proxy-only node, which has no database.
func TestNoFenceKeepsGossipOnlyBehaviour(t *testing.T) {
	node := splitBrainNode(nil)
	if err := node.refuseIssuance("mail.example.com"); err != nil {
		t.Errorf("a node with no fence configured must fall back to gossip leadership: %v", err)
	}

	follower := splitBrainNode(nil)
	follower.clusterManager.(*fakeCoordinator).leader.Store(false)
	if err := follower.refuseIssuance("mail.example.com"); !errors.Is(err, errIssuanceDeferred) {
		t.Errorf("a non-leader with no fence was allowed to issue: %v", err)
	}
}

var _ autocert.Cache = emptyCache{}
