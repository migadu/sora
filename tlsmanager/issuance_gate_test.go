package tlsmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// fakeCoordinator stands in for the cluster manager so leadership can be moved.
type fakeCoordinator struct {
	leader atomic.Bool
}

func (f *fakeCoordinator) IsLeader() bool { return f.leader.Load() }

func (f *fakeCoordinator) GetNodeID() string { return "node-2" }

func (f *fakeCoordinator) GetLeaderID() string {
	if f.leader.Load() {
		return "node-2"
	}
	return "node-1"
}

func (f *fakeCoordinator) OnLeaderChange(func(isLeader bool, newLeaderID string)) {}

// countingCache counts the reads a cache is asked for.
type countingCache struct {
	autocert.Cache
	gets atomic.Int64
}

func (c *countingCache) Get(ctx context.Context, name string) ([]byte, error) {
	c.gets.Add(1)
	return c.Cache.Get(ctx, name)
}

// autocertCacheEntry builds a cache entry in autocert's own format - the private key
// followed by the certificate it belongs to - so that autocert accepts it for domain.
func autocertCacheEntry(t *testing.T, domain string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
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

func encodeECDSAKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// seedACMEAccountKey stores the shared ACME account key the leader would have written on
// its first issuance. Without it a non-leader stops at the blocked account-key write
// instead of reaching Let's Encrypt, and the tests below would pass for the wrong reason.
func seedACMEAccountKey(t *testing.T, m *Manager) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := m.autocertMgr.Cache.Put(context.Background(), "acme_account+key", encodeECDSAKeyPEM(t, key)); err != nil {
		t.Fatalf("seeding ACME account key: %v", err)
	}
}

// ecdsaClientHello is a hello autocert maps to the plain "<domain>" cache key. A hello
// offering no ECDSA cipher suite is mapped to "<domain>+rsa" instead.
func ecdsaClientHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:   domain,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

// newNonLeaderManager builds a manager for a cluster node that is not the leader, with
// the shared S3 stub already holding what the leader would have published.
func newNonLeaderManager(t *testing.T) (m *Manager, acmeHits *atomic.Int64, endpoint string, coordinator *fakeCoordinator) {
	t.Helper()

	_, endpoint = newStubS3(t)
	coordinator = &fakeCoordinator{}
	coordinator.leader.Store(true) // seed the shared cache as the leader would have

	m, acmeHits = newTestClusterManager(t, endpoint, coordinator, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	seedACMEAccountKey(t, m)
	coordinator.leader.Store(false)

	// Same wait, on a scale that suits a test.
	m.issuanceWait = time.Second
	m.issuancePoll = 50 * time.Millisecond

	return m, acmeHits, endpoint, coordinator
}

// TestNonLeaderHandshakeDoesNotOrderCertificate is the core of leader-only issuance: a
// handshake for an uncached domain arriving at a node that is not the leader must not
// run a Let's Encrypt transaction. Such an order is counted against the account's rate
// limits and its HTTP-01 token only exists in this node's memory, so validations
// reaching any other node 404 and burn the failed-validation limit that the leader
// needs for its own issuance.
func TestNonLeaderHandshakeDoesNotOrderCertificate(t *testing.T) {
	m, acmeHits, _, _ := newNonLeaderManager(t)

	_, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello("mail.example.com"))
	if err == nil {
		t.Fatal("handshake on a non-leader for an uncached domain: err = nil, want failure")
	}
	if !errors.Is(err, ErrCertificateUnavailable) {
		t.Errorf("err = %v, want %v", err, ErrCertificateUnavailable)
	}
	if hits := acmeHits.Load(); hits != 0 {
		t.Errorf("ACME requests from a non-leader = %d, want 0", hits)
	}
}

// TestNonLeaderServesCertificateIssuedByLeader covers the other half: having declined to
// issue, the node must pick up the leader's certificate from the shared cache rather
// than fail the handshake outright.
func TestNonLeaderServesCertificateIssuedByLeader(t *testing.T) {
	m, acmeHits, endpoint, _ := newNonLeaderManager(t)
	domain := "mail.example.com"

	shared := newStubS3Cache(t, endpoint)
	published := make(chan struct{})
	go func() {
		defer close(published)
		time.Sleep(100 * time.Millisecond)
		if err := shared.Put(context.Background(), domain, autocertCacheEntry(t, domain)); err != nil {
			t.Errorf("leader publishing certificate: %v", err)
		}
	}()
	defer func() { <-published }()

	cert, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello(domain))
	if err != nil {
		t.Fatalf("handshake while the leader issues: err = %v, want the leader's certificate", err)
	}
	if cert == nil {
		t.Fatal("handshake while the leader issues: cert = nil")
	}
	if hits := acmeHits.Load(); hits != 0 {
		t.Errorf("ACME requests from a non-leader = %d, want 0", hits)
	}
}

// TestLeaderHandshakeOrdersCertificate guards the gate against over-reach: the leader
// still issues on a cache miss.
func TestLeaderHandshakeOrdersCertificate(t *testing.T) {
	m, acmeHits, _, coordinator := newNonLeaderManager(t)
	coordinator.leader.Store(true)

	if _, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello("mail.example.com")); err == nil {
		t.Fatal("handshake against the ACME stub: err = nil, want failure")
	}
	if hits := acmeHits.Load(); hits == 0 {
		t.Error("ACME requests from the cluster leader = 0, want the leader to order the certificate")
	}
}

// TestRateLimitedDomainDoesNotOrderCertificate keeps the rate-limit gate in front of the
// ACME flow: once Let's Encrypt has answered 429 for a domain, further orders for it are
// rejected before they are made.
func TestRateLimitedDomainDoesNotOrderCertificate(t *testing.T) {
	_, endpoint := newStubS3(t)
	m, acmeHits := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	seedACMEAccountKey(t, m)
	m.markRateLimited("mail.example.com", time.Now().Add(time.Hour))

	_, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello("mail.example.com"))
	if err == nil {
		t.Fatal("handshake for a rate-limited domain: err = nil, want failure")
	}
	if !errors.Is(err, ErrCertificateUnavailable) {
		t.Errorf("err = %v, want %v", err, ErrCertificateUnavailable)
	}
	if hits := acmeHits.Load(); hits != 0 {
		t.Errorf("ACME requests for a rate-limited domain = %d, want 0", hits)
	}

	// Clearing the mark lets the same handshake order, so it was the gate that stopped it.
	m.clearRateLimit("mail.example.com")
	if _, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello("mail.example.com")); err == nil {
		t.Fatal("handshake against the ACME stub: err = nil, want failure")
	}
	if hits := acmeHits.Load(); hits == 0 {
		t.Error("ACME requests once the rate limit has passed = 0, want the order to go through")
	}
}

func TestCertificateDomain(t *testing.T) {
	tests := []struct {
		name          string
		domain        string
		isCertificate bool
	}{
		{"mail.example.com", "mail.example.com", true},
		{"mail.example.com+rsa", "mail.example.com", true},
		{"mail.example.com+token", "", false},
		// autocert builds this key as httpTokenCacheKey = path.Base(tokenPath)+"+http-01",
		// a suffix. The earlier "http-01+<token>" case here matched no key autocert ever
		// writes, so it agreed with the code without testing the contract.
		{"sometoken+http-01", "", false},
		{"acme_account+key", "", false},
		{"acme_account.key", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, isCertificate := certificateDomain(tt.name)
			if domain != tt.domain || isCertificate != tt.isCertificate {
				t.Errorf("certificateDomain(%q) = (%q, %v), want (%q, %v)", tt.name, domain, isCertificate, tt.domain, tt.isCertificate)
			}
		})
	}
}

// TestRateLimitedDomainStillServesCachedCertificate pins the other side of that gate:
// rate limiting stops new orders, never the serving of a certificate already held.
func TestRateLimitedDomainStillServesCachedCertificate(t *testing.T) {
	_, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	domain := "mail.example.com"
	if err := m.autocertMgr.Cache.Put(context.Background(), domain, autocertCacheEntry(t, domain)); err != nil {
		t.Fatalf("storing certificate: %v", err)
	}
	m.markRateLimited(domain, time.Now().Add(time.Hour))

	if _, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello(domain)); err != nil {
		t.Fatalf("handshake for a cached but rate-limited domain: err = %v, want the cached certificate", err)
	}
}

// TestRepeatHandshakesDoNotRepeatCacheReads: autocert answers from its in-memory state
// once a certificate is loaded. A wrapper that reads the cache on every handshake to
// decide something about that certificate defeats it - with an S3-backed cache that is
// an S3 GET per handshake, and a stalled endpoint then parks every handshake goroutine.
func TestRepeatHandshakesDoNotRepeatCacheReads(t *testing.T) {
	_, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	domain := "mail.example.com"
	if err := m.autocertMgr.Cache.Put(context.Background(), domain, autocertCacheEntry(t, domain)); err != nil {
		t.Fatalf("storing certificate: %v", err)
	}

	counter := &countingCache{Cache: m.autocertMgr.Cache}
	m.autocertMgr.Cache = counter

	const handshakes = 20
	for i := 0; i < handshakes; i++ {
		if _, err := m.GetTLSConfig().GetCertificate(ecdsaClientHello(domain)); err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
	}

	if gets := counter.gets.Load(); gets > 2 {
		t.Errorf("cache reads for %d handshakes of one cached certificate = %d, want at most 2", handshakes, gets)
	}
}

// TestNonLeaderACMETransportIsFenced covers the issuance paths that never consult the
// certificate cache - autocert's background renewal among them - where the cache gate
// cannot see the node about to talk to Let's Encrypt.
func TestNonLeaderACMETransportIsFenced(t *testing.T) {
	m, acmeHits, _, coordinator := newNonLeaderManager(t)

	httpClient := m.autocertMgr.Client.HTTPClient
	if httpClient == nil {
		t.Fatal("ACME client uses the default HTTP transport: nothing stops a node that must not issue from reaching Let's Encrypt")
	}

	if _, err := httpClient.Get(m.autocertMgr.Client.DirectoryURL); err == nil {
		t.Error("ACME request from a non-leader: err = nil, want it refused")
	}
	if hits := acmeHits.Load(); hits != 0 {
		t.Errorf("ACME requests from a non-leader = %d, want 0", hits)
	}

	coordinator.leader.Store(true)
	if _, err := httpClient.Get(m.autocertMgr.Client.DirectoryURL); err != nil {
		t.Errorf("ACME request from the leader: err = %v, want it forwarded", err)
	}
	if hits := acmeHits.Load(); hits != 1 {
		t.Errorf("ACME requests after taking leadership = %d, want 1", hits)
	}
}

// TestServedTLSConfigAdvertisesACMEALPN: autocert tries tls-alpn-01 first on a fresh
// order and only falls back to http-01 with a second order, so a config that cannot
// negotiate acme-tls/1 spends an extra order and a failed validation on every issuance.
func TestServedTLSConfigAdvertisesACMEALPN(t *testing.T) {
	_, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})

	protos := m.GetTLSConfig().NextProtos
	if !slices.Contains(protos, acme.ALPNProto) {
		t.Errorf("NextProtos = %v, want it to include %q", protos, acme.ALPNProto)
	}
}
