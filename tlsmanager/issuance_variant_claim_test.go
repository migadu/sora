package tlsmanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func newACMENewOrderRequest(t *testing.T, domain string) *http.Request {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	jws, err := json.Marshal(map[string]string{
		"payload": base64.RawURLEncoding.EncodeToString(payload),
	})
	if err != nil {
		t.Fatalf("marshal jws: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://acme.example/order", bytes.NewReader(jws))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

type okRoundTripper struct{}

type orderRoundTripFunc func(*http.Request) (*http.Response, error)

func (f orderRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestCacheMissOrderRetryReleasesClaimAfterPut(t *testing.T) {
	const domain = "retry.example.com"
	ctx := context.Background()
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	if _, err := gate.Get(ctx, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get: %v", err)
	}
	for _, transportFailure := range []bool{false, true} {
		rt := &issuanceFence{manager: nodeA, base: orderRoundTripFunc(func(*http.Request) (*http.Response, error) {
			if transportFailure {
				return nil, io.ErrUnexpectedEOF
			}
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		})}
		resp, _ := rt.RoundTrip(newACMENewOrderRequest(t, domain))
		if resp != nil {
			resp.Body.Close()
		}
	}
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("retry newOrder: %v", err)
	}
	if err := gate.Put(ctx, domain, []byte("cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("completed retry retained claim: %v", err)
	}
}

func TestFailedRenewalDoesNotLeaveCacheMissOrderReference(t *testing.T) {
	const domain = "mixed.example.com"
	ctx := context.Background()
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	if _, err := gate.Get(ctx, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get: %v", err)
	}
	// The newOrder payload identifies the domain, not RSA/ECDSA. A sibling RSA
	// renewal can arrive before this ECDSA cache miss's order, and fail later.
	failedRenewal, err := nodeA.refuseOrderIssuance(domain)
	if err != nil {
		t.Fatal(err)
	}
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatal(err)
	}
	nodeA.dropFailedOrderRef(failedRenewal)
	if err := gate.Put(ctx, domain, []byte("ecdsa-cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("failed sibling renewal retained completed order's claim: %v", err)
	}
}

func TestLateNewOrderFailureDoesNotDropNewClaimReference(t *testing.T) {
	const domain = "late.example.com"
	ctx := context.Background()
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	oldRef, err := nodeA.refuseOrderIssuance(domain)
	if err != nil {
		t.Fatal(err)
	}
	// Let the old lease expire while its HTTP request is still outstanding.
	nodeA.claimMu.Lock()
	old := nodeA.issuanceClaims[domain]
	old.expires = time.Now().Add(-time.Second)
	nodeA.issuanceClaims[domain] = old
	nodeA.claimMu.Unlock()
	old.release(ctx)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	for range 2 {
		if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
			t.Fatal(err)
		}
	}
	nodeA.dropFailedOrderRef(oldRef)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	if err := gate.Put(ctx, domain, []byte("ecdsa")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("late failure released new sibling's claim: %v", err)
	}
	if err := gate.Put(ctx, domain+"+rsa", []byte("rsa")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("completed claim: %v", err)
	}
}

func (okRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

// autocert stores ECDSA certificates under "<domain>" and RSA certificates under
// "<domain>+rsa". When both variants are ordered concurrently on one node, finishing
// the faster variant must not release the cluster-wide claim while the slower variant
// is still ordering.
func TestConcurrentCacheMissVariantsKeepClaimUntilLastPut(t *testing.T) {
	const domain = "mail.example.com"
	const rsaKey = domain + "+rsa"
	ctx := context.Background()

	fence := newFakeFence()
	nodeA := splitBrainNode(fence)
	nodeB := splitBrainNode(fence)
	gateA := newIssuanceGate(emptyCache{}, nodeA)
	rtA := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// Both ECDSA and RSA handshakes miss the cache on nodeA.
	if _, err := gateA.Get(ctx, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("ECDSA Get = %v, want ErrCacheMiss", err)
	}
	if _, err := gateA.Get(ctx, rsaKey); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("RSA Get = %v, want ErrCacheMiss", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants after both variant misses = %d, want 1", got)
	}

	// ECDSA sends newOrder and stores its certificate before RSA sends newOrder.
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("ECDSA newOrder: %v", err)
	}
	if err := gateA.Put(ctx, domain, []byte("ecdsa-cert")); err != nil {
		t.Fatalf("ECDSA Put: %v", err)
	}

	// RSA is still in flight on nodeA: partitioned leader nodeB must NOT be able to
	// grab the fence, and nodeA's RSA newOrder check must still succeed.
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("nodeB was allowed to claim %s while nodeA's RSA order is still in flight: %v", domain, err)
	}
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("nodeA's own in-flight RSA newOrder was refused after ECDSA Put: %v", err)
	}

	// Once RSA stores its certificate as well, the claim must be released.
	if err := gateA.Put(ctx, rsaKey, []byte("rsa-cert")); err != nil {
		t.Fatalf("RSA Put: %v", err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("claim was not released after both variants completed: %v", err)
	}
	if got := fence.grantCount(); got != 2 {
		t.Errorf("fence grants = %d, want 2", got)
	}
}

// Background renewals do not pass through issuanceGate.Get (both certificates are still
// cached); they enter through issuanceFence.RoundTrip(newOrder) and complete in Put.
func TestConcurrentRenewalVariantsKeepClaimUntilLastPut(t *testing.T) {
	const domain = "mail.example.com"
	const rsaKey = domain + "+rsa"
	ctx := context.Background()

	fence := newFakeFence()
	nodeA := splitBrainNode(fence)
	nodeB := splitBrainNode(fence)
	gateA := newIssuanceGate(emptyCache{}, nodeA)
	rtA := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// Both ECDSA and RSA renewal goroutines post newOrder on nodeA.
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("ECDSA renewal newOrder: %v", err)
	}
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("RSA renewal newOrder: %v", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants after both renewal newOrders = %d, want 1", got)
	}

	// ECDSA renewal finishes first.
	if err := gateA.Put(ctx, domain, []byte("ecdsa-renewed")); err != nil {
		t.Fatalf("ECDSA renewal Put: %v", err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("nodeB was allowed to claim %s while nodeA's RSA renewal is still in flight: %v", domain, err)
	}

	// RSA renewal finishes second; now the claim is released.
	if err := gateA.Put(ctx, rsaKey, []byte("rsa-renewed")); err != nil {
		t.Fatalf("RSA renewal Put: %v", err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("claim was not released after both renewals completed: %v", err)
	}
}

// lapseClaim models issuanceClaimTTL passing on the claim node holds for domain: the
// fence lets it go by itself, so node has to ask the fence again.
func lapseClaim(t *testing.T, node *Manager, domain string) {
	t.Helper()
	node.claimMu.Lock()
	claim, held := node.issuanceClaims[domain]
	claim.expires = time.Now().Add(-time.Second)
	node.issuanceClaims[domain] = claim
	node.claimMu.Unlock()
	if !held || claim.release == nil {
		t.Fatalf("node holds no claim on %s", domain)
	}
	claim.release(context.Background())
}

// A claim lapses issuanceClaimTTL after it was taken, also while an order started late
// under it - a re-entrant order does not extend it - is still running. When the sibling
// variant's order then takes a fresh claim, the older order's Put must not give that
// claim away: the sibling is still ordering under it, and another node could start a
// duplicate order.
func TestStaleVariantPutKeepsNewerClaim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cacheMiss bool // the RSA order started from a handshake's cache miss, not a renewal
	}{
		{name: "renewal"},
		{name: "cache miss", cacheMiss: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const domain = "mail.example.com"
			const rsaKey = domain + "+rsa"
			ctx := context.Background()
			fence := newFakeFence()
			nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
			gate := newIssuanceGate(emptyCache{}, nodeA)
			rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

			// An earlier failed attempt left the claim held; the RSA order starts under it.
			if err := nodeA.refuseIssuance(domain); err != nil {
				t.Fatal(err)
			}
			if tc.cacheMiss {
				if _, err := gate.Get(ctx, rsaKey); !errors.Is(err, autocert.ErrCacheMiss) {
					t.Fatalf("RSA Get = %v, want ErrCacheMiss", err)
				}
			}
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
				t.Fatalf("RSA newOrder: %v", err)
			}

			lapseClaim(t, nodeA, domain)

			// The ECDSA renewal reads a cached certificate, so no cache miss holds the
			// fresh claim it takes: only its order does.
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
				t.Fatalf("ECDSA newOrder: %v", err)
			}
			if got := fence.grantCount(); got != 2 {
				t.Fatalf("fence grants = %d, want 2: the ECDSA order must take a fresh claim", got)
			}

			if err := gate.Put(ctx, rsaKey, []byte("rsa-cert")); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
				t.Fatalf("the RSA order from the lapsed claim gave away the claim the ECDSA order still runs under: nodeB = %v", err)
			}

			if err := gate.Put(ctx, domain, []byte("ecdsa-cert")); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.refuseIssuance(domain); err != nil {
				t.Fatalf("claim was not released after both orders stored their certificates: %v", err)
			}
		})
	}
}

// An order that started while the fence was unreachable ran under no claim at all. Its
// Put must not give away the claim the sibling variant took once the fence was back.
func TestUnfencedVariantPutKeepsLaterClaim(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	fence.mu.Lock()
	fence.err = errors.New("database unreachable")
	fence.mu.Unlock()
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("RSA newOrder with the fence unreachable: %v", err)
	}
	fence.mu.Lock()
	fence.err = nil
	fence.mu.Unlock()
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("ECDSA newOrder: %v", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants = %d, want 1", got)
	}

	if err := gate.Put(ctx, domain+"+rsa", []byte("rsa-cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("the unfenced RSA order gave away the claim the ECDSA order still runs under: nodeB = %v", err)
	}

	if err := gate.Put(ctx, domain, []byte("ecdsa-cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("claim was not released after both orders stored their certificates: %v", err)
	}
}

// Keeping an order's reference past the claim it started under must not keep a later
// claim held for an exchange that is over: autocert stores a certificate within the
// context its exchange runs under, so an order whose context ended long ago and stored
// nothing has failed.
func TestFinishedExchangeDoesNotHoldLaterClaim(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// A handshake's miss is ordered and the order accepted, then the exchange fails, so
	// no Put follows.
	ended, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Hour))
	defer cancel()
	if _, err := gate.Get(ended, domain+"+rsa"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("failed exchange's Get = %v, want ErrCacheMiss", err)
	}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain).WithContext(ended)); err != nil {
		t.Fatalf("failed exchange's newOrder: %v", err)
	}

	lapseClaim(t, nodeA, domain)

	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, domain)); err != nil {
		t.Fatalf("next newOrder: %v", err)
	}
	if err := gate.Put(ctx, domain, []byte("cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("an exchange that ended an hour ago kept the later claim held: %v", err)
	}
}
