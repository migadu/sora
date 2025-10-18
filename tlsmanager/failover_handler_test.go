package tlsmanager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// mockCache is a simple in-memory cache for testing
type mockCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string][]byte),
	}
}

func (m *mockCache) Get(ctx context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, exists := m.data[name]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}
	return data, nil
}

func (m *mockCache) Put(ctx context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[name] = data
	return nil
}

func (m *mockCache) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, name)
	return nil
}

// TestFailoverCache_ExistingCertificate verifies no retry for existing certificates
func TestFailoverCache_ExistingCertificate(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	ctx := context.Background()
	testData := []byte("existing certificate")

	// Put a certificate in the underlying cache
	if err := underlying.Put(ctx, "existing-cert", testData); err != nil {
		t.Fatalf("Failed to put cert: %v", err)
	}

	// Get should return immediately without retry
	start := time.Now()
	data, err := cache.Get(ctx, "existing-cert")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Got wrong data: expected %q, got %q", testData, data)
	}

	// Should be instant (< 100ms)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Get took too long (%v), should be instant for existing cert", elapsed)
	}
}

// TestFailoverCache_MissingCertificate_NoRetry verifies no retry when cert doesn't exist and isn't being issued
func TestFailoverCache_MissingCertificate_NoRetry(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	ctx := context.Background()

	// Get a non-existent certificate
	start := time.Now()
	_, err := cache.Get(ctx, "missing-cert")
	elapsed := time.Since(start)

	if err != autocert.ErrCacheMiss {
		t.Fatalf("Expected ErrCacheMiss, got: %v", err)
	}

	// Should return immediately without retry (< 100ms)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Get took too long (%v), should return immediately for missing cert", elapsed)
	}
}

// TestFailoverCache_CertificateBeingIssued_Retry verifies retry logic when cert is being issued
func TestFailoverCache_CertificateBeingIssued_Retry(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	ctx := context.Background()
	certName := "new-cert"
	testData := []byte("newly issued certificate")

	// Simulate another goroutine issuing a certificate
	// by marking it as being issued
	cache.issuingCerts.Store(certName, true)

	// Start a goroutine that will add the certificate after 2 seconds
	go func() {
		time.Sleep(2 * time.Second)
		underlying.Put(context.Background(), certName, testData)
		cache.issuingCerts.Delete(certName)
	}()

	// Get should retry and eventually succeed
	start := time.Now()
	data, err := cache.Get(ctx, certName)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get should have succeeded after retry, got error: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Got wrong data: expected %q, got %q", testData, data)
	}

	// Should have taken ~2 seconds (cert appeared after 2s)
	if elapsed < 1*time.Second || elapsed > 4*time.Second {
		t.Errorf("Get took %v, expected around 2 seconds", elapsed)
	}
}

// TestFailoverCache_CertificateBeingIssued_Timeout verifies timeout when cert isn't ready
func TestFailoverCache_CertificateBeingIssued_Timeout(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	ctx := context.Background()
	certName := "delayed-cert"

	// Mark certificate as being issued but never actually issue it
	cache.issuingCerts.Store(certName, true)
	defer cache.issuingCerts.Delete(certName)

	// Get should retry maxRetries times and then give up
	start := time.Now()
	_, err := cache.Get(ctx, certName)
	elapsed := time.Since(start)

	if err != autocert.ErrCacheMiss {
		t.Fatalf("Expected ErrCacheMiss after timeout, got: %v", err)
	}

	// Should have taken ~5 seconds (5 retries × 1 second)
	if elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Errorf("Get took %v, expected around 5 seconds (maxRetries * retryDelay)", elapsed)
	}
}

// TestFailoverCache_Put_CleansUpTracking verifies that Put cleans up tracking after completion
func TestFailoverCache_Put_CleansUpTracking(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	ctx := context.Background()
	certName := "tracked-cert"
	testData := []byte("certificate data")

	// Before Put, cert should not be tracked
	if _, isBeingIssued := cache.issuingCerts.Load(certName); isBeingIssued {
		t.Error("Certificate should not be marked as being issued before Put")
	}

	// Do a Put
	err := cache.Put(ctx, certName, testData)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// After Put completes, cert should not be tracked anymore
	if _, isBeingIssued := cache.issuingCerts.Load(certName); isBeingIssued {
		t.Error("Certificate should not be marked as being issued after Put completes")
	}

	// Verify certificate was actually stored
	data, err := underlying.Get(ctx, certName)
	if err != nil {
		t.Fatalf("Certificate not stored: %v", err)
	}
	if string(data) != string(testData) {
		t.Errorf("Wrong data stored: expected %q, got %q", testData, data)
	}
}

// TestFailoverCache_ContextCancellation verifies that context cancellation stops retry
func TestFailoverCache_ContextCancellation(t *testing.T) {
	underlying := newMockCache()
	cache := NewFailoverAwareCache(underlying)

	certName := "context-test-cert"

	// Mark certificate as being issued
	cache.issuingCerts.Store(certName, true)
	defer cache.issuingCerts.Delete(certName)

	// Create a context that we'll cancel after 1 second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Get in a goroutine
	errChan := make(chan error)
	go func() {
		_, err := cache.Get(ctx, certName)
		errChan <- err
	}()

	// Cancel the context after 1 second
	time.Sleep(1 * time.Second)
	cancel()

	// Get should return with context.Canceled error
	err := <-errChan
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}
}

// slowCache is a mock cache that adds delay to Get operations
type slowCache struct {
	*mockCache
	getDelay time.Duration
}

func (s *slowCache) Get(ctx context.Context, name string) ([]byte, error) {
	time.Sleep(s.getDelay)
	return s.mockCache.Get(ctx, name)
}

// TestFailoverCache_NoDelayForExistingCerts verifies that existing certs don't trigger S3 delays
func TestFailoverCache_NoDelayForExistingCerts(t *testing.T) {
	// Create a slow underlying cache (simulating S3 latency)
	underlying := &slowCache{
		mockCache: newMockCache(),
		getDelay:  500 * time.Millisecond, // Simulate 500ms S3 latency
	}

	// But even with a slow underlying cache, if cert exists, first Get succeeds
	testData := []byte("existing cert")
	underlying.Put(context.Background(), "slow-cert", testData)

	cache := NewFailoverAwareCache(underlying)
	ctx := context.Background()

	// First Get - will be slow due to underlying cache delay
	start := time.Now()
	data, err := cache.Get(ctx, "slow-cert")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Got wrong data: expected %q, got %q", testData, data)
	}

	// Should take around 500ms (one Get call to slow cache)
	if elapsed < 400*time.Millisecond || elapsed > 700*time.Millisecond {
		t.Errorf("Get took %v, expected around 500ms", elapsed)
	}
}

// errorCache is a mock cache that returns errors
type errorCache struct {
	*mockCache
	getError error
}

func (e *errorCache) Get(ctx context.Context, name string) ([]byte, error) {
	if e.getError != nil {
		return nil, e.getError
	}
	return e.mockCache.Get(ctx, name)
}

// TestFailoverCache_NonCacheMissError verifies that non-ErrCacheMiss errors propagate immediately
func TestFailoverCache_NonCacheMissError(t *testing.T) {
	testError := fmt.Errorf("S3 connection failed")
	underlying := &errorCache{
		mockCache: newMockCache(),
		getError:  testError,
	}

	cache := NewFailoverAwareCache(underlying)
	ctx := context.Background()

	// Get should return the error immediately without retry
	start := time.Now()
	_, err := cache.Get(ctx, "error-cert")
	elapsed := time.Since(start)

	if err != testError {
		t.Fatalf("Expected specific error, got: %v", err)
	}

	// Should be immediate (< 100ms)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Get took too long (%v), should return error immediately", elapsed)
	}
}
