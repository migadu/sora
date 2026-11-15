package tlsmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// exchange is the context autocert runs one ACME exchange under - its cache read, its
// newOrder requests and its Put - with the deadline autocert gives it: five minutes
// for a handshake, ten for a renewal.
func exchange(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// newACMENewOrderRequest is a newOrder for domain sent by the exchange ctx belongs to.
func newACMENewOrderRequest(t *testing.T, ctx context.Context, domain string) *http.Request {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://acme.example/order", bytes.NewReader(jws))
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
	ctx := exchange(t, 5*time.Minute)
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
		resp, _ := rt.RoundTrip(newACMENewOrderRequest(t, ctx, domain))
		if resp != nil {
			resp.Body.Close()
		}
	}
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, ctx, domain)); err != nil {
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
	handshake, renewal := exchange(t, 5*time.Minute), exchange(t, 10*time.Minute)
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	if _, err := gate.Get(handshake, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get: %v", err)
	}
	// The newOrder payload identifies the domain, not RSA/ECDSA. A sibling RSA
	// renewal can arrive before this ECDSA cache miss's order, and fail later.
	failedRenewal, err := nodeA.refuseOrderIssuance(renewal, domain)
	if err != nil {
		t.Fatal(err)
	}
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, handshake, domain)); err != nil {
		t.Fatal(err)
	}
	nodeA.dropFailedOrderRef(failedRenewal)
	if err := gate.Put(handshake, domain, []byte("ecdsa-cert")); err != nil {
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
	oldRef, err := nodeA.refuseOrderIssuance(exchange(t, 10*time.Minute), domain)
	if err != nil {
		t.Fatal(err)
	}
	// Let the old lease expire while its HTTP request is still outstanding.
	nodeA.claimMu.Lock()
	old := nodeA.issuanceClaims[domain]
	old.expires = time.Now().Add(-time.Second)
	nodeA.issuanceClaims[domain] = old
	nodeA.claimMu.Unlock()
	old.hold.Release(ctx)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}
	ecdsa, rsa := exchange(t, 10*time.Minute), exchange(t, 10*time.Minute)
	for _, renewal := range []context.Context{ecdsa, rsa} {
		if _, err := rt.RoundTrip(newACMENewOrderRequest(t, renewal, domain)); err != nil {
			t.Fatal(err)
		}
	}
	nodeA.dropFailedOrderRef(oldRef)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	if err := gate.Put(ecdsa, domain, []byte("ecdsa")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("late failure released new sibling's claim: %v", err)
	}
	if err := gate.Put(rsa, domain+"+rsa", []byte("rsa")); err != nil {
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
	ecdsa, rsa := exchange(t, 5*time.Minute), exchange(t, 5*time.Minute)

	fence := newFakeFence()
	nodeA := splitBrainNode(fence)
	nodeB := splitBrainNode(fence)
	gateA := newIssuanceGate(emptyCache{}, nodeA)
	rtA := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// Both ECDSA and RSA handshakes miss the cache on nodeA.
	if _, err := gateA.Get(ecdsa, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("ECDSA Get = %v, want ErrCacheMiss", err)
	}
	if _, err := gateA.Get(rsa, rsaKey); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("RSA Get = %v, want ErrCacheMiss", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants after both variant misses = %d, want 1", got)
	}

	// ECDSA sends newOrder and stores its certificate before RSA sends newOrder.
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, ecdsa, domain)); err != nil {
		t.Fatalf("ECDSA newOrder: %v", err)
	}
	if err := gateA.Put(ecdsa, domain, []byte("ecdsa-cert")); err != nil {
		t.Fatalf("ECDSA Put: %v", err)
	}

	// RSA is still in flight on nodeA: partitioned leader nodeB must NOT be able to
	// grab the fence, and nodeA's RSA newOrder check must still succeed.
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("nodeB was allowed to claim %s while nodeA's RSA order is still in flight: %v", domain, err)
	}
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, rsa, domain)); err != nil {
		t.Fatalf("nodeA's own in-flight RSA newOrder was refused after ECDSA Put: %v", err)
	}

	// Once RSA stores its certificate as well, the claim must be released.
	if err := gateA.Put(rsa, rsaKey, []byte("rsa-cert")); err != nil {
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
	ecdsa, rsa := exchange(t, 10*time.Minute), exchange(t, 10*time.Minute)

	fence := newFakeFence()
	nodeA := splitBrainNode(fence)
	nodeB := splitBrainNode(fence)
	gateA := newIssuanceGate(emptyCache{}, nodeA)
	rtA := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// Both ECDSA and RSA renewal goroutines post newOrder on nodeA.
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, ecdsa, domain)); err != nil {
		t.Fatalf("ECDSA renewal newOrder: %v", err)
	}
	if _, err := rtA.RoundTrip(newACMENewOrderRequest(t, rsa, domain)); err != nil {
		t.Fatalf("RSA renewal newOrder: %v", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants after both renewal newOrders = %d, want 1", got)
	}

	// ECDSA renewal finishes first.
	if err := gateA.Put(ecdsa, domain, []byte("ecdsa-renewed")); err != nil {
		t.Fatalf("ECDSA renewal Put: %v", err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("nodeB was allowed to claim %s while nodeA's RSA renewal is still in flight: %v", domain, err)
	}

	// RSA renewal finishes second; now the claim is released.
	if err := gateA.Put(rsa, rsaKey, []byte("rsa-renewed")); err != nil {
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
	if !held || claim.hold == nil {
		t.Fatalf("node holds no claim on %s", domain)
	}
	claim.hold.Release(context.Background())
}

// A claim can lapse while an order started late under it is still running: when the
// fence could not be reached to extend the claim over the order. When the sibling
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
			rsa := exchange(t, 10*time.Minute)
			if tc.cacheMiss {
				rsa = exchange(t, 5*time.Minute)
			}
			ecdsa := exchange(t, 10*time.Minute)
			fence := newFakeFence()
			nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
			gate := newIssuanceGate(emptyCache{}, nodeA)
			rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

			// An earlier failed attempt left the claim held; the RSA order starts under it.
			if err := nodeA.refuseIssuance(domain); err != nil {
				t.Fatal(err)
			}
			if tc.cacheMiss {
				if _, err := gate.Get(rsa, rsaKey); !errors.Is(err, autocert.ErrCacheMiss) {
					t.Fatalf("RSA Get = %v, want ErrCacheMiss", err)
				}
			}
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, rsa, domain)); err != nil {
				t.Fatalf("RSA newOrder: %v", err)
			}

			lapseClaim(t, nodeA, domain)

			// The ECDSA renewal reads a cached certificate, so no cache miss holds the
			// fresh claim it takes: only its order does.
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, ecdsa, domain)); err != nil {
				t.Fatalf("ECDSA newOrder: %v", err)
			}
			if got := fence.grantCount(); got != 2 {
				t.Fatalf("fence grants = %d, want 2: the ECDSA order must take a fresh claim", got)
			}

			if err := gate.Put(rsa, rsaKey, []byte("rsa-cert")); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
				t.Fatalf("the RSA order from the lapsed claim gave away the claim the ECDSA order still runs under: nodeB = %v", err)
			}

			if err := gate.Put(ecdsa, domain, []byte("ecdsa-cert")); err != nil {
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
	rsa, ecdsa := exchange(t, 10*time.Minute), exchange(t, 10*time.Minute)
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	fence.mu.Lock()
	fence.err = errors.New("database unreachable")
	fence.mu.Unlock()
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, rsa, domain)); err != nil {
		t.Fatalf("RSA newOrder with the fence unreachable: %v", err)
	}
	fence.mu.Lock()
	fence.err = nil
	fence.mu.Unlock()
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, ecdsa, domain)); err != nil {
		t.Fatalf("ECDSA newOrder: %v", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants = %d, want 1", got)
	}

	if err := gate.Put(rsa, domain+"+rsa", []byte("rsa-cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
		t.Fatalf("the unfenced RSA order gave away the claim the ECDSA order still runs under: nodeB = %v", err)
	}

	if err := gate.Put(ecdsa, domain, []byte("ecdsa-cert")); err != nil {
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
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	// A handshake's miss is ordered and the order accepted, then the exchange fails, so
	// no Put follows.
	ended, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	if _, err := gate.Get(ended, domain+"+rsa"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("failed exchange's Get = %v, want ErrCacheMiss", err)
	}
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, ended, domain)); err != nil {
		t.Fatalf("failed exchange's newOrder: %v", err)
	}

	lapseClaim(t, nodeA, domain)

	next := exchange(t, 10*time.Minute)
	if _, err := rt.RoundTrip(newACMENewOrderRequest(t, next, domain)); err != nil {
		t.Fatalf("next newOrder: %v", err)
	}
	if err := gate.Put(next, domain, []byte("cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("an exchange that ended an hour ago kept the later claim held: %v", err)
	}
}

// autocert's GetCertificate stores the certificate for every handshake that missed the
// cache, also for one that only waited for another handshake's order: createCert hands
// the waiter the certificate, and GetCertificate then calls cachePut for it (x/crypto
// v0.55.0 acme/autocert). The owner releases the waiter before it stores the
// certificate itself, so the waiter's Put can come first. That Put completes no order,
// and must not stand in for the sibling variant's renewal, which is still ordering.
func TestWaitingHandshakePutKeepsSiblingOrderClaim(t *testing.T) {
	for _, tc := range []struct {
		name        string
		waiterFirst bool
	}{
		{name: "waiter stores first", waiterFirst: true},
		{name: "owner stores first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const domain = "mail.example.com"
			fence := newFakeFence()
			nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
			gate := newIssuanceGate(emptyCache{}, nodeA)
			rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

			// The RSA certificate is still cached, so its renewal misses nothing: only
			// its order holds the claim.
			rsaRenewal := exchange(t, 10*time.Minute)
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, rsaRenewal, domain)); err != nil {
				t.Fatalf("RSA renewal newOrder: %v", err)
			}

			// Two handshakes miss the ECDSA certificate; the owner orders it, the waiter
			// waits for that order.
			owner, waiter := exchange(t, 5*time.Minute), exchange(t, 5*time.Minute)
			for _, handshake := range []context.Context{owner, waiter} {
				if _, err := gate.Get(handshake, domain); !errors.Is(err, autocert.ErrCacheMiss) {
					t.Fatalf("ECDSA Get = %v, want ErrCacheMiss", err)
				}
			}
			if _, err := rt.RoundTrip(newACMENewOrderRequest(t, owner, domain)); err != nil {
				t.Fatalf("ECDSA newOrder: %v", err)
			}

			puts := []context.Context{owner, waiter}
			if tc.waiterFirst {
				puts = []context.Context{waiter, owner}
			}
			for _, handshake := range puts {
				if err := gate.Put(handshake, domain, []byte("ecdsa-cert")); err != nil {
					t.Fatal(err)
				}
			}
			if err := nodeB.refuseIssuance(domain); !errors.Is(err, errIssuanceDeferred) {
				t.Fatalf("the ECDSA handshakes gave away the claim the RSA renewal still runs under: nodeB = %v", err)
			}

			if err := gate.Put(rsaRenewal, domain+"+rsa", []byte("rsa-cert")); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.refuseIssuance(domain); err != nil {
				t.Fatalf("claim was not released after every order stored its certificate: %v", err)
			}
		})
	}
}

// autocert tries one challenge type per order and starts a new order for the next type
// when one fails (verifyRFC), so one exchange can send several accepted newOrders. Its
// Put ends the exchange, and with it every one of them.
func TestPutCompletesEveryOrderOfItsExchange(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	gate := newIssuanceGate(emptyCache{}, nodeA)
	rt := &issuanceFence{manager: nodeA, base: okRoundTripper{}}

	renewal := exchange(t, 10*time.Minute)
	for _, challenge := range []string{"tls-alpn-01", "http-01"} {
		if _, err := rt.RoundTrip(newACMENewOrderRequest(t, renewal, domain)); err != nil {
			t.Fatalf("newOrder for %s: %v", challenge, err)
		}
	}
	if err := gate.Put(renewal, domain, []byte("cert")); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("the exchange stored its certificate but its first order still holds the claim: %v", err)
	}
}

// newIssuingACME starts an ACME server that issues every order at once - the order is
// ready without authorizations, and finalize signs the CSR's key with a test CA - and
// returns its directory URL.
func newIssuingACME(t *testing.T) string {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	var nonce atomic.Int64
	var mu sync.Mutex
	var issued []byte
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	withNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))
	}
	order := func(w http.ResponseWriter, status int, body map[string]any) {
		withNonce(w)
		w.Header().Set("Location", srv.URL+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		withNonce(w)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			srv.URL+"/nonce", srv.URL+"/account", srv.URL+"/order")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		withNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		withNonce(w)
		w.Header().Set("Location", srv.URL+"/account/1")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"valid"}`)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		order(w, http.StatusCreated, map[string]any{"status": "ready", "finalize": srv.URL + "/finalize"})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		var jws struct{ Payload string }
		var finalize struct{ CSR string }
		body, _ := io.ReadAll(r.Body)
		payload, _ := base64.RawURLEncoding.DecodeString(func() string { json.Unmarshal(body, &jws); return jws.Payload }())
		json.Unmarshal(payload, &finalize)
		der, _ := base64.RawURLEncoding.DecodeString(finalize.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(12 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, ca, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		issued = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
		mu.Unlock()
		order(w, http.StatusOK, map[string]any{"status": "valid", "certificate": srv.URL + "/cert"})
	})
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		withNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		mu.Lock()
		defer mu.Unlock()
		w.Write(issued)
	})
	return srv.URL + "/directory"
}

// End to end through autocert: a Put completes only the orders of its own exchange,
// which works only because autocert sends the newOrder and stores the certificate
// under one context. If it ever stopped doing so, the order would hold the claim until
// its exchange's deadline, and this test would catch that.
func TestIssuedCertificateCompletesItsOrder(t *testing.T) {
	const domain = "mail.example.com"
	fence := newFakeFence()
	nodeA, nodeB := splitBrainNode(fence), splitBrainNode(fence)
	am := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      newIssuanceGate(autocert.DirCache(t.TempDir()), nodeA),
		Client: &acme.Client{
			DirectoryURL: newIssuingACME(t),
			HTTPClient:   &http.Client{Transport: &issuanceFence{manager: nodeA, base: http.DefaultTransport}},
		},
	}

	if _, err := am.GetCertificate(ecdsaClientHello(domain)); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	if got := fence.grantCount(); got != 1 {
		t.Fatalf("fence grants = %d, want 1: the issuance must have taken the claim", got)
	}
	if err := nodeB.refuseIssuance(domain); err != nil {
		t.Fatalf("the certificate is stored but its order still holds the claim: %v", err)
	}
}
