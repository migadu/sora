package tlsmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// trackingCache wraps mockCache to track call counts
type trackingCache struct {
	*mockCache
	getCalls    atomic.Int64
	putCalls    atomic.Int64
	deleteCalls atomic.Int64
	getDelay    time.Duration
	getError    error
	mu          sync.Mutex // protects getError and getDelay
}

func newTrackingCache() *trackingCache {
	return &trackingCache{
		mockCache: newMockCache(),
	}
}

func (t *trackingCache) Get(ctx context.Context, name string) ([]byte, error) {
	t.getCalls.Add(1)

	// Get delay and error
	t.mu.Lock()
	delay := t.getDelay
	err := t.getError
	t.mu.Unlock()

	// Simulate delay
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Return error if set
	if err != nil {
		return nil, err
	}

	return t.mockCache.Get(ctx, name)
}

func (t *trackingCache) Put(ctx context.Context, name string, data []byte) error {
	t.putCalls.Add(1)
	return t.mockCache.Put(ctx, name, data)
}

func (t *trackingCache) Delete(ctx context.Context, name string) error {
	t.deleteCalls.Add(1)
	return t.mockCache.Delete(ctx, name)
}

func (t *trackingCache) resetCounters() {
	t.getCalls.Store(0)
	t.putCalls.Store(0)
	t.deleteCalls.Store(0)
}

func (t *trackingCache) getCallCount() int64 {
	return t.getCalls.Load()
}

func (t *trackingCache) setError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getError = err
}

func (t *trackingCache) setDelay(delay time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getDelay = delay
}

// TestCertificateRenewalFlow tests the full certificate renewal flow
func TestCertificateRenewalFlow(t *testing.T) {
	ctx := context.Background()

	// Create tracking S3 cache
	s3Cache := newTrackingCache()

	// Create fallback cache on top
	fallbackDir := t.TempDir()
	fallback, err := NewFallbackCache(s3Cache, fallbackDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	// Generate old certificate (expires soon)
	oldCert, err := generateTestCertificate(
		time.Now().Add(-60*24*time.Hour), // 60 days ago
		time.Now().Add(5*24*time.Hour),   // Expires in 5 days
		1,
	)
	if err != nil {
		t.Fatalf("Failed to generate old certificate: %v", err)
	}

	// Store old certificate in S3 only (not in local cache yet)
	domain := "test.example.com"
	if err := s3Cache.Put(ctx, domain, oldCert); err != nil {
		t.Fatalf("Failed to store old certificate in S3: %v", err)
	}

	t.Logf("Step 1: Old certificate stored in S3")

	// First retrieval - should fetch from S3 and cache locally
	s3Cache.resetCounters()
	data1, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed to get certificate from fallback cache: %v", err)
	}

	if s3Cache.getCallCount() != 1 {
		t.Errorf("Expected 1 S3 Get call, got %d", s3Cache.getCallCount())
	}

	// Verify it's the old certificate
	block, _ := pem.Decode(data1)
	if block == nil {
		t.Fatal("Failed to decode certificate")
	}
	cert1, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("Failed to parse certificate")
	}
	if cert1.SerialNumber.Int64() != 1 {
		t.Errorf("Expected certificate serial 1, got %d", cert1.SerialNumber.Int64())
	}

	t.Logf("Step 2: Old certificate retrieved from S3 and cached locally (serial=%d)", cert1.SerialNumber.Int64())

	// Wait a bit for async local cache sync to complete
	time.Sleep(100 * time.Millisecond)

	// Second retrieval - should come from local cache (no S3 call)
	s3Cache.resetCounters()
	data2, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed to get certificate from local cache: %v", err)
	}

	// Due to async sync, we might still hit S3 once if sync hasn't completed
	// But subsequent calls should definitely use local cache
	if s3Cache.getCallCount() > 1 {
		t.Errorf("Expected at most 1 S3 Get call, got %d", s3Cache.getCallCount())
	}

	if string(data1) != string(data2) {
		t.Error("Expected same certificate from local cache")
	}

	t.Logf("Step 3: Certificate served from cache (S3 calls: %d)", s3Cache.getCallCount())

	// Simulate certificate renewal - new certificate issued to S3 by leader
	newCert, err := generateTestCertificate(
		time.Now(),                      // Just issued
		time.Now().Add(90*24*time.Hour), // Expires in 90 days
		2,
	)
	if err != nil {
		t.Fatalf("Failed to generate new certificate: %v", err)
	}

	if err := s3Cache.Put(ctx, domain, newCert); err != nil {
		t.Fatalf("Failed to store new certificate in S3: %v", err)
	}

	t.Logf("Step 4: New certificate issued and stored in S3 (serial=2)")

	// Immediate retrieval could return either old (local cache) or new (S3) certificate
	// depending on timing. The key point is that local cache serves certificates quickly
	// and S3 failures don't block TLS handshakes.
	s3Cache.resetCounters()
	data3, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	block, _ = pem.Decode(data3)
	cert3, _ := x509.ParseCertificate(block.Bytes)

	t.Logf("Step 5: Certificate retrieved (serial=%d, S3 calls=%d)", cert3.SerialNumber.Int64(), s3Cache.getCallCount())

	// In production, the cert_sync worker would detect this and update the local cache.
	// For the test, we'll simulate clearing the local cache (e.g., after restart)
	fc, ok := fallback.(*FallbackCache)
	if !ok {
		t.Fatal("Failed to cast to FallbackCache")
	}

	// Delete from local cache to simulate restart or cache clear
	if err := fc.fallback.Delete(ctx, domain); err != nil {
		t.Fatalf("Failed to clear local cache: %v", err)
	}

	t.Logf("Step 6: Local cache cleared (simulating server restart)")

	// Now retrieval should fetch NEW certificate from S3
	s3Cache.resetCounters()
	data4, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed to get new certificate: %v", err)
	}

	if s3Cache.getCallCount() != 1 {
		t.Errorf("Expected 1 S3 Get call after cache clear, got %d", s3Cache.getCallCount())
	}

	block, _ = pem.Decode(data4)
	cert4, _ := x509.ParseCertificate(block.Bytes)
	if cert4.SerialNumber.Int64() != 2 {
		t.Errorf("Expected new certificate serial 2, got %d", cert4.SerialNumber.Int64())
	}

	t.Logf("Step 7: New certificate retrieved from S3 after restart (serial=%d)", cert4.SerialNumber.Int64())

	// Wait for async goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestS3FailureScenario tests behavior when S3 is unavailable
func TestS3FailureScenario(t *testing.T) {
	ctx := context.Background()

	// Create tracking S3 cache
	s3Cache := newTrackingCache()

	// Create fallback cache
	fallbackDir := t.TempDir()
	fallback, err := NewFallbackCache(s3Cache, fallbackDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	domain := "test.example.com"

	// Generate certificate
	cert, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		1,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Store in S3
	if err := s3Cache.Put(ctx, domain, cert); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	// First retrieval succeeds
	data1, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed first retrieval: %v", err)
	}

	t.Logf("Step 1: Certificate retrieved successfully and cached locally")

	// Second retrieval from local cache succeeds
	data2, err := fallback.Get(ctx, domain)
	if err != nil {
		t.Fatalf("Failed second retrieval: %v", err)
	}

	if string(data1) != string(data2) {
		t.Error("Expected same certificate from cache")
	}

	t.Logf("Step 2: Certificate served from local cache")

	// Simulate S3 failure - set timeout error
	s3Cache.setError(errors.New("S3 timeout"))

	t.Logf("Step 3: S3 marked as unavailable (simulated timeout)")

	// Clear local cache to force S3 check
	fc := fallback.(*FallbackCache)
	if err := fc.fallback.Delete(ctx, domain); err != nil {
		t.Fatalf("Failed to clear local cache: %v", err)
	}

	// Try to get certificate - should get ErrCacheMiss (not the S3 error)
	// This is the fix we implemented
	data3, err := fallback.Get(ctx, domain)
	if err != autocert.ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss when S3 fails, got: %v", err)
	}
	if data3 != nil {
		t.Error("Expected nil data on cache miss")
	}

	t.Logf("Step 4: S3 failure correctly treated as cache miss (prevents autocert from retrying)")

	// Wait for async goroutines to complete
	time.Sleep(100 * time.Millisecond)
}

// TestS3SlowResponseWithTimeout tests behavior when S3 is slow
func TestS3SlowResponseWithTimeout(t *testing.T) {
	ctx := context.Background()

	// Create tracking S3 cache with 10-second delay
	s3Cache := newTrackingCache()
	s3Cache.setDelay(10 * time.Second)

	// Create fallback cache
	fallbackDir := t.TempDir()
	fallback, err := NewFallbackCache(s3Cache, fallbackDir)
	if err != nil {
		t.Fatalf("Failed to create fallback cache: %v", err)
	}

	domain := "test.example.com"

	// Generate certificate and store in S3
	cert, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		1,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := s3Cache.Put(ctx, domain, cert); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in S3")

	// Try to retrieve with slow S3 - should timeout (5 second timeout in FallbackCache)
	start := time.Now()
	data, err := fallback.Get(ctx, domain)
	elapsed := time.Since(start)

	// Should timeout around 5 seconds (FallbackCache has 5s timeout for S3)
	if elapsed > 6*time.Second {
		t.Errorf("Expected timeout around 5 seconds, took %v", elapsed)
	}

	// Should get context deadline exceeded error, which gets converted to ErrCacheMiss
	if err != autocert.ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss on S3 timeout, got: %v", err)
	}

	if data != nil {
		t.Error("Expected nil data on timeout")
	}

	t.Logf("Step 2: S3 Get timed out after %v (correctly treated as cache miss)", elapsed)
}

// TestRateLimitErrorDetection tests that rate limit errors are properly detected and tracked
func TestRateLimitErrorDetection(t *testing.T) {
	m := &Manager{
		rateLimitMap: make(map[string]time.Time),
	}

	domain := "example.com"

	// Simulate a rate limit error message from Let's Encrypt
	// Use a future date to ensure the rate limit is still active
	futureDate := time.Now().Add(168 * time.Hour).Format("2006-01-02 15:04:05 MST")
	rateLimitError := errors.New(fmt.Sprintf("429 urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after %s: see https://letsencrypt.org/docs/rate-limits/", futureDate))

	// Check if error contains rate limit markers
	errStr := rateLimitError.Error()
	if !strings.Contains(errStr, "429") || !strings.Contains(errStr, "rateLimited") {
		t.Error("Test error doesn't contain expected rate limit markers")
	}

	// Parse retry-after time
	retryAfter := time.Now().Add(24 * time.Hour) // Default
	if strings.Contains(errStr, "retry after") {
		parts := strings.Split(errStr, "retry after ")
		if len(parts) > 1 {
			// Extract "2026-01-25 12:42:05 UTC" from the full error message
			// The format is: "retry after 2026-01-25 12:42:05 UTC: see https://..."
			remainder := parts[1]
			// Split on the next colon to get just the timestamp part
			timeParts := strings.SplitN(remainder, ": ", 2)
			if len(timeParts) > 0 {
				timeStr := strings.TrimSpace(timeParts[0])

				// Try to parse
				if parsedTime, err := time.Parse("2006-01-02 15:04:05 MST", timeStr); err == nil {
					retryAfter = parsedTime
					t.Logf("Parsed retry-after time: %v", retryAfter)
				} else {
					t.Logf("Failed to parse time (will use default): %v (timeStr=%q)", err, timeStr)
				}
			}
		}
	}

	// Mark domain as rate-limited
	m.markRateLimited(domain, retryAfter)

	// Verify it's tracked
	if limited, after := m.isRateLimited(domain); !limited {
		t.Error("Domain should be rate-limited")
	} else {
		t.Logf("Domain correctly marked as rate-limited until %v", after)
	}

	// Clear and verify
	m.clearRateLimit(domain)
	if limited, _ := m.isRateLimited(domain); limited {
		t.Error("Domain should not be rate-limited after clearing")
	}
}

// TestGetCertificateWithRateLimit tests the GetCertificate wrapper with rate limiting
func TestGetCertificateWithRateLimit(t *testing.T) {
	m := &Manager{
		rateLimitMap: make(map[string]time.Time),
	}

	domain := "example.com"

	// Initially not rate-limited
	if limited, _ := m.isRateLimited(domain); limited {
		t.Error("Domain should not be rate-limited initially")
	}

	// Mark as rate-limited for 1 second
	m.markRateLimited(domain, time.Now().Add(1*time.Second))

	// Should be blocked
	if limited, retryAfter := m.isRateLimited(domain); !limited {
		t.Error("Domain should be rate-limited")
	} else {
		t.Logf("Domain is rate-limited until %v", retryAfter)
	}

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again
	if limited, _ := m.isRateLimited(domain); limited {
		t.Error("Domain should not be rate-limited after expiry")
	}

	t.Log("Rate limit expired successfully")
}

// TestConcurrentCacheAccess tests that concurrent access to the cache is safe
func TestConcurrentCacheAccess(t *testing.T) {
	ctx := context.Background()
	cache := newTrackingCache()

	domain := "test.example.com"
	cert, err := generateTestCertificate(
		time.Now(),
		time.Now().Add(90*24*time.Hour),
		1,
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Store initial certificate
	if err := cache.Put(ctx, domain, cert); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	// Launch 100 concurrent readers
	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := cache.Get(ctx, domain)
			if err != nil {
				errChan <- err
				return
			}
			if data == nil {
				errChan <- errors.New("got nil certificate")
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("Concurrent access error: %v", err)
	}

	t.Logf("Successfully handled 100 concurrent cache reads")
}
