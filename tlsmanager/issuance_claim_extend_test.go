package tlsmanager

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// expireClaimIn makes the claim node holds on domain expire in left, at node and at the
// fence alike, as if it had been taken issuanceClaimTTL-left ago.
func expireClaimIn(t *testing.T, node *Manager, fence *fakeFence, domain string, left time.Duration) {
	t.Helper()
	node.claimMu.Lock()
	claim, held := node.issuanceClaims[domain]
	claim.expires = time.Now().Add(left)
	node.issuanceClaims[domain] = claim
	node.claimMu.Unlock()

	fence.mu.Lock()
	fenced, granted := fence.held[domain]
	fenced.expires = fence.now().Add(left)
	fence.held[domain] = fenced
	fence.mu.Unlock()

	if !held || !granted {
		t.Fatalf("node holds no claim on %s", domain)
	}
}

// An order that re-enters this node's claim near the claim's expiry - a renewal timer,
// a retry or a handshake miss, after an earlier order failed and kept the claim - runs
// for its whole exchange. The fence lets the claim go at its expiry whatever still runs
// under it, so unless the claim is extended over that exchange, the other partition's
// leader takes it and orders the same certificate while this node's order still runs.
func TestReentrantWorkExtendsClaimOverItsExchange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timeout   time.Duration // the deadline autocert gives the exchange
		cacheMiss bool          // the work is a handshake's cache miss, not a renewal's order
	}{
		{name: "renewal", timeout: 10 * time.Minute},
		{name: "handshake cache miss", timeout: 5 * time.Minute, cacheMiss: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const domain = "mail.example.com"
			const rsaKey = domain + "+rsa"
			fence := newFakeFence()
			nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
			gate := newIssuanceGate(emptyCache{}, nodeA)
			rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

			// An earlier order failed and stored nothing, so its claim stays held until
			// it expires: one second after the RSA work starts under it.
			if err := nodeA.refuseIssuance(domain); err != nil {
				t.Fatal(err)
			}
			expireClaimIn(t, nodeA, fence, domain, time.Second)

			work := exchange(t, tc.timeout)
			if tc.cacheMiss {
				if _, err := gate.Get(work, rsaKey); !errors.Is(err, autocert.ErrCacheMiss) {
					t.Fatalf("RSA Get = %v, want ErrCacheMiss", err)
				}
			} else if _, err := rt.RoundTrip(newACMENewOrderRequest(t, work, domain)); err != nil {
				t.Fatalf("RSA newOrder: %v", err)
			}

			deadline, _ := work.Deadline()
			for _, at := range []struct {
				name string
				t    time.Time
			}{
				{"just past the claim's original expiry", time.Now().Add(2 * time.Second)},
				{"just before the exchange's deadline", deadline.Add(-time.Second)},
			} {
				fence.at(at.t)
				if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
					t.Fatalf("%s, nodeB = %v: the claim lapsed under nodeA's running exchange "+
						"and nodeB was let order %s too", at.name, err, domain)
				}
			}

			if err := gate.Put(work, rsaKey, []byte("rsa-cert")); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.refuseIssuance(domain); err != nil {
				t.Fatalf("claim was not released once the work stored its certificate: %v", err)
			}
		})
	}
}

// A claim the fence has already given to another node cannot cover new work, however
// long this node's own record of it says it still runs: that record is kept on this
// node's clock, the expiry on the fence's. Work that would outlive the claim has to find
// out from the fence, and stand down.
func TestReentrantWorkDoesNotExtendClaimTakenElsewhere(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	if err := nodeA.refuseIssuance(domain); err != nil {
		t.Fatal(err)
	}
	// nodeA's clock runs behind the fence's: to the fence the claim has lapsed while
	// nodeA still counts a second on it, and nodeB took it in between.
	expireClaimIn(t, nodeA, fence, domain, time.Second)
	fence.at(time.Now().Add(2 * time.Second))
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("nodeB could not take the lapsed claim: %v", err)
	}

	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, exchange(t, 10*time.Minute), domain)); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("nodeA's renewal order under the claim nodeB now holds = %v, want errIssuanceDeferred", err)
	}
}

// Extending a claim asks the fence, and an unreachable fence must not stop an order any
// more than it stops one that takes a claim: an expired certificate takes the node's TLS
// down, while the worst case of ordering unfenced is a duplicate order.
func TestReentrantWorkProceedsWhenTheFenceCannotExtend(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	node := splitBrainNode(fence)
	rt := &issuanceFence{manager: node, base: okRoundTripper{}}

	if err := node.refuseIssuance(domain); err != nil {
		t.Fatal(err)
	}
	expireClaimIn(t, node, fence, domain, time.Second)
	fence.mu.Lock()
	fence.err = errors.New("database unreachable")
	fence.mu.Unlock()

	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, exchange(t, 10*time.Minute), domain)); err != nil {
		t.Errorf("an unreachable fence blocked a renewal under this node's own claim: %v", err)
	}
}

// Every handshake for a certificate the cache lacks reads it, so every one of them
// reaches the claim with an exchange of its own that ends a little later than the last.
// Extending the claim only as far as each one's exchange would write to the fence on
// every handshake; one extension has to cover the handshakes that follow it.
func TestHandshakeMissesDoNotExtendClaimEachTime(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	node := splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, node)

	if err := node.refuseIssuance(domain); err != nil {
		t.Fatal(err)
	}
	expireClaimIn(t, node, fence, domain, time.Second)
	asked := fence.askCount()

	for range 5 {
		if _, err := gate.Get(exchange(t, 5*time.Minute), domain); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("handshake Get = %v, want ErrCacheMiss", err)
		}
	}
	if got := fence.askCount() - asked; got > 1 {
		t.Errorf("five handshake misses asked the fence %d times, want at most once", got)
	}
}
