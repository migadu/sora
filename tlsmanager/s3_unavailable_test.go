//go:build integration
// +build integration

package tlsmanager

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// TestS3UnavailableBut CertExistsInS3 tests the critical scenario:
// 1. S3 gets marked unavailable due to a timeout on a different operation
// 2. Pre-warming or TLS handshake needs a cert that IS in S3
// 3. System should still try S3 and find the cert
//
// This test reproduces the production bug where one node couldn't find
// certificates in S3 because S3 was marked unavailable, leading to
// unnecessary ACME requests and rate limiting.
func TestS3UnavailableButCertExistsInS3(t *testing.T) {
	// Create mock S3 cache
	s3Cache := newTrackingCache()
	ctx := context.Background()

	// Create fallback cache
	tempDir := t.TempDir()
	cache, err := NewFallbackCache(s3Cache, tempDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	// Cast to FallbackCache to access internal methods
	fc, ok := cache.(*FallbackCache)
	if !ok {
		t.Fatal("Cache is not a FallbackCache")
	}

	t.Log("Step 1: Store certificate in S3 (simulating it was issued previously)")

	// Generate and store certificate in S3
	certData, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		12345,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	domain := "imap.migadu.com"
	if err := s3Cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate in S3: %v", err)
	}

	t.Log("Step 2: Simulate S3 being marked unavailable due to error on different cert")

	// Trigger an error to mark S3 unavailable
	// This simulates what happens when S3 times out on a different operation
	s3Cache.setError(context.DeadlineExceeded)
	_, err = fc.primary.Get(ctx, "some-other-cert.com")
	if err == nil {
		t.Fatal("Expected error from S3")
	}

	// Mark S3 as unavailable (simulating what Get() does)
	fc.markS3Unavailable()
	s3Cache.setError(nil) // S3 actually works, but cache thinks it's unavailable

	t.Logf("Step 3: S3 marked unavailable - will retry anyway for missing cert")

	// Reset counters to track this specific operation
	s3Cache.resetCounters()

	// Now try to get the certificate we know exists in S3
	// OLD BUG: Would return ErrCacheMiss without trying S3
	// NEW FIX: Should try S3 anyway and find the cert
	data, err := cache.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Expected to find certificate in S3, got error: %v", err)
	}

	if data == nil || len(data) == 0 {
		t.Fatal("Expected certificate data, got empty")
	}

	// Verify S3 was actually accessed (despite being marked unavailable)
	if s3Cache.getCallCount() != 1 {
		t.Errorf("Expected 1 S3 Get call (retry despite unavailable), got %d", s3Cache.getCallCount())
	}

	t.Logf("Step 4: SUCCESS - Certificate found in S3 despite being marked unavailable")
	t.Log("This prevents unnecessary ACME requests and rate limiting")

	// Wait for async goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestS3RecoveryAfterTransientError tests that S3 recovers after transient errors
func TestS3RecoveryAfterTransientError(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	tempDir := t.TempDir()
	cache, err := NewFallbackCache(s3Cache, tempDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	fc, ok := cache.(*FallbackCache)
	if !ok {
		t.Fatal("Cache is not a FallbackCache")
	}

	t.Log("Step 1: Store multiple certificates in S3")

	certs := map[string][]byte{}
	for i, domain := range []string{"cert1.example.com", "cert2.example.com", "cert3.example.com"} {
		certData, err := generateTestCertificate(
			time.Now(),
			time.Now().Add(90*24*time.Hour),
			int64(100+i),
		)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}
		certs[domain] = certData
		if err := s3Cache.Put(ctx, domain, certData); err != nil {
			t.Fatalf("Failed to store certificate: %v", err)
		}
	}

	t.Log("Step 2: First cert retrieval succeeds")
	_, err = cache.Get(ctx, "cert1.example.com")
	if err != nil {
		t.Fatalf("Expected cert1 to be found: %v", err)
	}

	t.Log("Step 3: S3 has transient error on cert2")
	s3Cache.setError(context.DeadlineExceeded)
	_, err = cache.Get(ctx, "cert2.example.com")
	if err != autocert.ErrCacheMiss {
		t.Fatalf("Expected cache miss due to S3 error, got: %v", err)
	}

	// This marks S3 as unavailable
	if fc.isS3Available() {
		t.Error("Expected S3 to be marked unavailable after error")
	}

	t.Log("Step 4: S3 recovers - cert3 should still be retrievable")
	s3Cache.setError(nil)

	// Even though S3 is marked unavailable, we should still try for cert3
	data, err := cache.Get(ctx, "cert3.example.com")
	if err != nil {
		t.Fatalf("Expected cert3 to be found (S3 recovered), got error: %v", err)
	}

	if data == nil {
		t.Fatal("Expected certificate data")
	}

	// S3 should be marked available again after successful operation
	if !fc.isS3Available() {
		t.Error("Expected S3 to be marked available after successful Get")
	}

	t.Log("Step 5: SUCCESS - S3 recovered and subsequent operations work")

	// Wait for async goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestPrewarmingAfterS3Marked Unavailable tests pre-warming behavior when S3 marked unavailable
func TestPrewarmingAfterS3MarkedUnavailable(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	tempDir := t.TempDir()
	cache, err := NewFallbackCache(s3Cache, tempDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	fc, ok := cache.(*FallbackCache)
	if !ok {
		t.Fatal("Cache is not a FallbackCache")
	}

	t.Log("Step 1: Store certificates for all domains")
	domains := []string{"pop.migadu.com", "imap.migadu.com", "lmtp.migadu.com"}
	for i, domain := range domains {
		certData, err := generateTestCertificate(
			time.Now(),
			time.Now().Add(90*24*time.Hour),
			int64(1000+i),
		)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}
		if err := s3Cache.Put(ctx, domain, certData); err != nil {
			t.Fatalf("Failed to store certificate: %v", err)
		}
	}

	t.Log("Step 2: Mark S3 as unavailable (simulating startup after S3 issues)")
	fc.markS3Unavailable()

	t.Log("Step 3: Pre-warming checks all domains")
	// Simulate what pre-warming does: check if certs exist
	found := 0
	missing := 0

	s3Cache.resetCounters()

	for _, domain := range domains {
		data, err := cache.Get(ctx, domain)
		if err != nil {
			t.Logf("Pre-warm: Domain %s not found: %v", domain, err)
			missing++
		} else if len(data) > 0 {
			t.Logf("Pre-warm: Domain %s found (size=%d)", domain, len(data))
			found++
		}
	}

	// All certs should be found despite S3 being marked unavailable
	if found != 3 {
		t.Errorf("Expected to find all 3 certificates, found %d", found)
	}

	if missing != 0 {
		t.Errorf("Expected 0 missing certificates, got %d", missing)
	}

	// S3 should have been tried for each domain
	if s3Cache.getCallCount() != 3 {
		t.Errorf("Expected 3 S3 Get calls (one per domain), got %d", s3Cache.getCallCount())
	}

	// S3 should be marked available again after successful operations
	if !fc.isS3Available() {
		t.Error("Expected S3 to be marked available after successful pre-warming")
	}

	t.Log("Step 4: SUCCESS - All certificates found despite initial S3 unavailable status")

	// Wait for async goroutines to complete
	time.Sleep(100 * time.Millisecond)
}
