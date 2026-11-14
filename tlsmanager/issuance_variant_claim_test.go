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
