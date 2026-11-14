package tlsmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// orderCountingACME is an ACME server that registers accounts and refuses every
// order. It counts both, so a test can tell an ACME exchange that stopped before
// ordering from one that ordered.
type orderCountingACME struct {
	accounts atomic.Int64
	orders   atomic.Int64
}

// newOrderCountingACME starts the server and returns its directory URL.
func newOrderCountingACME(t *testing.T) (*orderCountingACME, string) {
	t.Helper()

	acme := &orderCountingACME{}
	var nonce atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	withNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))
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
		acme.accounts.Add(1)
		withNonce(w)
		w.Header().Set("Location", srv.URL+"/account/1")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"valid"}`)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		acme.orders.Add(1)
		withNonce(w)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"test server refuses every order"}`)
	})
	return acme, srv.URL + "/directory"
}

// certCacheEntry builds a cache entry in autocert's format for a certificate valid
// from notBefore to notAfter.
func certCacheEntry(t *testing.T, domain string, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	var buf bytes.Buffer
	buf.Write(encodeECDSAKeyPEM(t, key))
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return buf.Bytes()
}

// dueForRenewal is a cache entry for a 90-day certificate with 10 days left, inside
// the 30-day renewal window.
func dueForRenewal(t *testing.T, domain string) []byte {
	return certCacheEntry(t, domain, 7, time.Now().Add(-80*24*time.Hour), time.Now().Add(10*24*time.Hour))
}

// waitFor polls cond for up to timeout.
func waitFor(timeout time.Duration, cond func() bool) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// TestCachedCertificateIsRenewedWithoutAHandshake: autocert starts a certificate's
// renewal timer only when it loads the certificate, and on its own it loads one only
// inside a handshake for that domain. The node that may renew - the leader - must not
// depend on client traffic reaching it: what the node finds in the cache at startup
// has to be armed for renewal.
func TestCachedCertificateIsRenewedWithoutAHandshake(t *testing.T) {
	const domain = "mail.example.com"
	_, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	acme, directory := newOrderCountingACME(t)
	m.autocertMgr.Client.DirectoryURL = directory
	seedACMEAccountKey(t, m)

	if err := m.autocertMgr.Cache.Put(context.Background(), domain, dueForRenewal(t, domain)); err != nil {
		t.Fatalf("storing certificate: %v", err)
	}

	m.prewarmCertificates()

	if !waitFor(5*time.Second, func() bool { return acme.orders.Load() > 0 }) {
		t.Fatal("a certificate inside its renewal window was not renewed: no order reached the ACME server without a handshake")
	}
}

// TestRenewalTakesTheIssuanceClaim: a first issuance takes the cluster-wide claim
// before it orders, so that two nodes that both believe they lead (a gossip split)
// cannot both order. A renewal orders as well and must take the same claim.
func TestRenewalTakesTheIssuanceClaim(t *testing.T) {
	const domain = "mail.example.com"

	setup := func(t *testing.T, fence *fakeFence) (*Manager, *orderCountingACME) {
		_, endpoint := newStubS3(t)
		coordinator := &fakeCoordinator{}
		coordinator.leader.Store(true)
		m, _ := newTestClusterManager(t, endpoint, coordinator, func(le *config.TLSLetsEncryptConfig) {
			le.FallbackDir = t.TempDir()
		})
		acme, directory := newOrderCountingACME(t)
		m.autocertMgr.Client.DirectoryURL = directory
		seedACMEAccountKey(t, m)
		m.SetCertificateFence(fence)

		if err := m.autocertMgr.Cache.Put(context.Background(), domain, dueForRenewal(t, domain)); err != nil {
			t.Fatalf("storing certificate: %v", err)
		}
		// A handshake loads the certificate and starts its renewal timer, which fires
		// at once: the certificate is inside its renewal window.
		if _, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello(domain)); err != nil {
			t.Fatalf("handshake for the cached certificate: %v", err)
		}
		if !waitFor(5*time.Second, func() bool { return acme.accounts.Load() > 0 }) {
			t.Fatal("the renewal never reached the ACME server")
		}
		return m, acme
	}

	t.Run("claim held by another node", func(t *testing.T) {
		fence := newFakeFence()
		fence.held[domain] = true // the other partition's leader is ordering

		_, acme := setup(t, fence)
		time.Sleep(500 * time.Millisecond)
		if orders := acme.orders.Load(); orders != 0 {
			t.Errorf("renewal orders while another node holds the issuance claim = %d, want 0", orders)
		}
	})

	t.Run("claim free", func(t *testing.T) {
		fence := newFakeFence()

		_, acme := setup(t, fence)
		if !waitFor(5*time.Second, func() bool { return acme.orders.Load() > 0 }) {
			t.Fatal("renewal never ordered although the claim was free")
		}
		if grants := fence.grantCount(); grants != 1 {
			t.Errorf("issuance claims taken by the renewal = %d, want 1", grants)
		}
	})
}
