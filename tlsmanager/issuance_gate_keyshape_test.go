package tlsmanager

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// certificateDomain decides whether a cache miss should be treated as "this node wants
// to order a certificate". It must recognise autocert's non-certificate keys exactly, so
// the shapes are pinned here against the upstream source
// (golang.org/x/crypto/acme/autocert/autocert.go):
//
//	certificate     "<domain>", and "<domain>+rsa"   (certKey, :221)
//	tls-alpn-01     "<domain>+token"                 (certKey, :218)
//	http-01 token   "<token>+http-01"                (httpTokenCacheKey, :896)
//	account key     "acme_account+key" / "acme_account.key"
//
// Getting http-01 wrong is not cosmetic: on a non-leader the gate answers a miss with
// errIssuanceDeferred, and autocert's HTTPHandler writes that error's text into the body
// of a 404 served on the public port 80 (autocert.go:411). The text names the cluster
// leader and this node, so an unauthenticated request to /.well-known/acme-challenge/
// would enumerate cluster node ids.

func TestCertificateDomainRecognisesAutocertKeyShapes(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		wantDomain    string
		wantIsCertKey bool
	}{
		{"plain certificate", "mail.example.com", "mail.example.com", true},
		{"rsa certificate", "mail.example.com+rsa", "mail.example.com", true},
		{"tls-alpn-01 challenge cert", "mail.example.com+token", "", false},
		{"http-01 token", "6fXAG9VyGm1XGmH4Ec3xdA+http-01", "", false},
		{"acme account key", "acme_account+key", "", false},
		{"legacy acme account key", "acme_account.key", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, isCertKey := certificateDomain(tt.key)
			if isCertKey != tt.wantIsCertKey {
				t.Errorf("certificateDomain(%q) isCertificate = %v, want %v", tt.key, isCertKey, tt.wantIsCertKey)
			}
			if domain != tt.wantDomain {
				t.Errorf("certificateDomain(%q) domain = %q, want %q", tt.key, domain, tt.wantDomain)
			}
		})
	}
}

// TestHTTPTokenMissIsAPlainCacheMissOnANonLeader is the consequence test: whatever the
// gate does for certificates, a missing http-01 token must come back as an ordinary
// cache miss, carrying no cluster topology into a response autocert serves publicly.
func TestHTTPTokenMissIsAPlainCacheMissOnANonLeader(t *testing.T) {
	coordinator := &fakeCoordinator{}
	coordinator.leader.Store(false) // this node must not issue

	gate := newIssuanceGate(emptyCache{}, &Manager{clusterManager: coordinator})

	_, err := gate.Get(context.Background(), "6fXAG9VyGm1XGmH4Ec3xdA+http-01")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Errorf("Get on a missing http-01 token returned %v, want autocert.ErrCacheMiss", err)
	}
	if err != nil {
		for _, secret := range []string{coordinator.GetNodeID(), coordinator.GetLeaderID(), "leader"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error for a missing http-01 token names %q; autocert writes this text into "+
					"a 404 body on the public ACME endpoint: %v", secret, err)
			}
		}
	}
}

// emptyCache reports every key as absent.
type emptyCache struct{}

func (emptyCache) Get(context.Context, string) ([]byte, error) { return nil, autocert.ErrCacheMiss }
func (emptyCache) Put(context.Context, string, []byte) error   { return nil }
func (emptyCache) Delete(context.Context, string) error        { return nil }
