package tlsmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme/autocert"
)

func newStubS3Cache(t *testing.T, endpoint string) *S3Cache {
	t.Helper()

	cache, err := NewS3Cache(config.TLSLetsEncryptS3Config{
		Bucket:     "certs",
		Endpoint:   endpoint,
		DisableTLS: true,
		AccessKey:  "test",
		SecretKey:  "test",
	})
	if err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	return cache
}

// TestS3CacheGetNotFoundIsCacheMiss guards the genuine miss: a certificate that is
// really absent must still invite issuance.
func TestS3CacheGetNotFoundIsCacheMiss(t *testing.T) {
	_, endpoint := newStubS3(t)
	cache := newStubS3Cache(t, endpoint)

	_, err := cache.Get(context.Background(), "mail.example.com")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get on absent object: err = %v, want autocert.ErrCacheMiss", err)
	}
}

// TestS3CacheGetBackendFailureIsNotCacheMiss verifies that a failing S3 backend is
// reported as an error. Reported as a cache miss it tells autocert the certificate
// does not exist, which orders a new one from Let's Encrypt for a domain that already
// has a certificate in S3.
func TestS3CacheGetBackendFailureIsNotCacheMiss(t *testing.T) {
	s3, endpoint := newStubS3(t)
	cache := newStubS3Cache(t, endpoint)
	s3.failGets(http.StatusInternalServerError)

	_, err := cache.Get(context.Background(), "mail.example.com")
	if err == nil {
		t.Fatal("Get with failing S3 backend: err = nil, want an error")
	}
	if errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get with failing S3 backend: err = %v, want a backend error, not autocert.ErrCacheMiss", err)
	}
}

// TestFallbackCacheGetBackendFailureIsNotCacheMiss covers the same distinction one
// layer up, for a node whose local certificate directory is still empty.
func TestFallbackCacheGetBackendFailureIsNotCacheMiss(t *testing.T) {
	s3Cache := newTrackingCache()
	s3Cache.setError(errors.New("connection reset by peer"))

	cache, err := NewFallbackCache(s3Cache, t.TempDir())
	if err != nil {
		t.Fatalf("NewFallbackCache: %v", err)
	}

	_, err = cache.Get(context.Background(), "mail.example.com")
	if err == nil {
		t.Fatal("Get with failing S3 backend: err = nil, want an error")
	}
	if errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get with failing S3 backend: err = %v, want a backend error, not autocert.ErrCacheMiss", err)
	}
}

// TestS3OutageDoesNotOrderCertificate is the end of that chain: a handshake during an
// S3 outage must fail rather than place a Let's Encrypt order that is doomed
// cluster-wide and burns issuance rate limits.
func TestS3OutageDoesNotOrderCertificate(t *testing.T) {
	s3, endpoint := newStubS3(t)
	m, acmeHits := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})

	s3.failGets(http.StatusServiceUnavailable)

	_, err := m.GetTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "mail.example.com"})
	if err == nil {
		t.Fatal("handshake during S3 outage: err = nil, want failure")
	}
	if !errors.Is(err, ErrCertificateUnavailable) {
		t.Errorf("handshake during S3 outage: err = %v, want %v", err, ErrCertificateUnavailable)
	}
	if hits := acmeHits.Load(); hits != 0 {
		t.Errorf("ACME requests during S3 outage = %d, want 0 (certificate may already exist in S3)", hits)
	}
}
