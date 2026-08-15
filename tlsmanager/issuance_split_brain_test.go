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
// still reach.
type fakeFence struct {
	mu     sync.Mutex
	held   map[string]bool
	err    error
	grants int
}

func newFakeFence() *fakeFence { return &fakeFence{held: map[string]bool{}} }

func (f *fakeFence) TryHoldIssuance(_ context.Context, domain string, _ time.Duration) (func(context.Context), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.held[domain] {
		return nil, nil
	}
	f.held[domain] = true
	f.grants++
	return func(context.Context) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.held, domain)
	}, nil
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
