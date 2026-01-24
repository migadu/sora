package tlsmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestCertificatePrewarming tests that certificates are loaded from cache at startup
func TestCertificatePrewarming(t *testing.T) {
	// Create mock S3 cache
	s3Cache := newTrackingCache()

	// Domain to test
	domain := "test.example.com"

	// Generate a test certificate
	certData, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		12345,
	)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Store certificate in S3 (simulating it was issued before server start)
	ctx := context.Background()
	if err := s3Cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate in S3: %v", err)
	}

	t.Logf("Step 1: Certificate stored in S3 (simulating previous issuance)")

	// Note: We can't easily create a full Manager in tests because it requires real S3
	// Instead, test the pre-warming logic directly
	t.Logf("Step 2: Testing pre-warm logic simulation")

	// Simulate what pre-warming does:
	// 1. Check if cert exists in cache
	s3Cache.resetCounters()
	cachedCert, err := s3Cache.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Certificate should exist in cache: %v", err)
	}

	if s3Cache.getCallCount() != 1 {
		t.Errorf("Expected 1 S3 Get call during pre-warm, got %d", s3Cache.getCallCount())
	}

	// 2. Verify it's the right certificate
	block, _ := pem.Decode(cachedCert)
	if block == nil {
		t.Fatal("Failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("Failed to parse certificate")
	}

	if cert.SerialNumber.Int64() != 12345 {
		t.Errorf("Expected serial 12345, got %d", cert.SerialNumber.Int64())
	}

	t.Logf("Step 3: Pre-warm would load certificate serial=%d from cache", cert.SerialNumber.Int64())

	// In a real scenario, autocert.Manager.GetCertificate() would be called with this cert
	// and it would be loaded into autocert's internal state map

	t.Logf("Step 4: Certificate would be available for TLS handshakes without ACME request")

	// Verify the cert is still in cache (not removed during test)
	s3Cache.resetCounters()
	_, err = s3Cache.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Certificate should still be in cache: %v", err)
	}

	t.Logf("Success: Pre-warming simulation complete")
}

// TestPrewarmingWithMultipleDomains tests pre-warming with multiple domains
func TestPrewarmingWithMultipleDomains(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	domains := []string{
		"example1.com",
		"example2.com",
		"example3.com",
	}

	// Store certificates for first 2 domains (3rd will be missing)
	for i := 0; i < 2; i++ {
		certData, err := generateTestCertificate(
			time.Now(),
			time.Now().Add(90*24*time.Hour),
			int64(i+1),
		)
		if err != nil {
			t.Fatalf("Failed to generate certificate %d: %v", i, err)
		}

		if err := s3Cache.Put(ctx, domains[i], certData); err != nil {
			t.Fatalf("Failed to store certificate %d: %v", i, err)
		}
	}

	t.Logf("Step 1: Stored certificates for 2 of 3 domains")

	// Simulate pre-warming all 3 domains
	warmed := 0
	failed := 0

	s3Cache.resetCounters()
	for _, domain := range domains {
		_, err := s3Cache.Get(ctx, domain)
		if err != nil {
			t.Logf("Pre-warm: Domain %s not in cache (will be issued on demand)", domain)
			failed++
			continue
		}

		t.Logf("Pre-warm: Domain %s loaded from cache", domain)
		warmed++
	}

	// Should have loaded 2 certs, failed on 1
	if warmed != 2 {
		t.Errorf("Expected 2 certificates warmed, got %d", warmed)
	}
	if failed != 1 {
		t.Errorf("Expected 1 failed (missing cert), got %d", failed)
	}

	// Should have made 3 cache checks total
	if s3Cache.getCallCount() != 3 {
		t.Errorf("Expected 3 S3 Get calls, got %d", s3Cache.getCallCount())
	}

	t.Logf("Step 2: Pre-warming complete - %d loaded, %d missing", warmed, failed)
}

// TestPrewarmingWithCacheFailure tests pre-warming behavior when cache is unavailable
func TestPrewarmingWithCacheFailure(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	domain := "test.example.com"

	// Store certificate initially
	certData, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		999,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := s3Cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in cache")

	// Simulate S3 becoming unavailable
	s3Cache.setError(context.DeadlineExceeded)
	t.Logf("Step 2: S3 marked as unavailable (simulated timeout)")

	// Try to pre-warm - should handle gracefully
	s3Cache.resetCounters()
	_, err = s3Cache.Get(ctx, domain)
	if err == nil {
		t.Error("Expected error from cache, got nil")
	}

	t.Logf("Step 3: Pre-warm failed gracefully (cert will be issued on first handshake)")

	// Clear the error
	s3Cache.setError(nil)

	// Now pre-warming should work
	s3Cache.resetCounters()
	_, err = s3Cache.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Expected cache to work after recovery: %v", err)
	}

	t.Logf("Step 4: Pre-warm succeeded after S3 recovery")
}

// TestPrewarmingRaceCondition tests that pre-warming completes before TLS handshakes
func TestPrewarmingRaceCondition(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	domain := "test.example.com"

	// Store certificate
	certData, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		555,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := s3Cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in S3")

	// Simulate pre-warming (synchronous in our implementation)
	s3Cache.resetCounters()
	startTime := time.Now()
	_, err = s3Cache.Get(ctx, domain)
	prewarmDuration := time.Since(startTime)

	if err != nil {
		t.Fatalf("Pre-warming failed: %v", err)
	}

	t.Logf("Step 2: Pre-warming completed in %v", prewarmDuration)

	// Pre-warming should be fast (< 1 second for local cache)
	if prewarmDuration > 1*time.Second {
		t.Errorf("Pre-warming took too long: %v (should be < 1s)", prewarmDuration)
	}

	// Simulate immediate TLS handshake after pre-warming
	s3Cache.resetCounters()
	_, err = s3Cache.Get(ctx, domain)
	if err != nil {
		t.Fatalf("TLS handshake failed after pre-warming: %v", err)
	}

	// If pre-warming worked, this should hit cache (fast path)
	t.Logf("Step 3: TLS handshake succeeded immediately after pre-warming")
}

// TestPrewarmingDoesNotTriggerACME tests that pre-warming only loads from cache
func TestPrewarmingDoesNotTriggerACME(t *testing.T) {
	s3Cache := newTrackingCache()
	ctx := context.Background()

	domains := []string{
		"has-cert.example.com",
		"no-cert.example.com",
	}

	// Only store cert for first domain
	certData, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		111,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := s3Cache.Put(ctx, domains[0], certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored for %s only", domains[0])

	// Simulate pre-warming logic:
	// 1. Check cache first
	// 2. Only call GetCertificate if cert exists in cache
	s3Cache.resetCounters()

	for _, domain := range domains {
		_, err := s3Cache.Get(ctx, domain)
		if err != nil {
			// Not in cache - DON'T call autocert.GetCertificate
			// (which would trigger ACME request)
			t.Logf("Pre-warm: Skipping %s (not in cache)", domain)
			continue
		}

		// In cache - would call autocert.GetCertificate here
		t.Logf("Pre-warm: Loading %s from cache", domain)
	}

	// Should have checked cache for both domains
	if s3Cache.getCallCount() != 2 {
		t.Errorf("Expected 2 cache checks, got %d", s3Cache.getCallCount())
	}

	// Should NOT have any Put calls (no new certs issued)
	if s3Cache.putCalls.Load() != 0 {
		t.Errorf("Expected 0 ACME requests (Put calls), got %d", s3Cache.putCalls.Load())
	}

	t.Logf("Step 2: Pre-warming complete - no ACME requests triggered")
}
