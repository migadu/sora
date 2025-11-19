package lookupcache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestThunderingHerdPrevention verifies that singleflight prevents multiple concurrent
// fetches for the same key when cache is cold
func TestThunderingHerdPrevention(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 1000, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	var fetchCount atomic.Int32
	serverName := "test-server"
	username := "user@example.com"

	// Simulate an expensive fetch operation
	fetchFn := func() (*CacheEntry, error) {
		fetchCount.Add(1)
		time.Sleep(100 * time.Millisecond) // Simulate slow database query
		return &CacheEntry{
			AccountID:      123,
			HashedPassword: "hash123",
			PasswordHash:   HashPassword("password123"),
			Result:         AuthSuccess,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(5 * time.Minute),
			IsNegative:     false,
		}, nil
	}

	// Launch 100 concurrent requests
	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-startSignal // Wait for start signal to ensure maximum concurrency

			entry, fromCache, err := cache.GetOrFetch(serverName, username, fetchFn)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if entry == nil {
				t.Error("Expected entry, got nil")
				return
			}
			if entry.AccountID != 123 {
				t.Errorf("Expected AccountID 123, got %d", entry.AccountID)
			}
			// First request won't be from cache, others may or may not be depending on timing
			_ = fromCache
		}()
	}

	// Start all goroutines at once
	close(startSignal)
	wg.Wait()

	// The key assertion: fetchFn should only be called ONCE despite 100 concurrent requests
	// This proves singleflight prevented the thundering herd
	actualFetchCount := fetchCount.Load()
	if actualFetchCount != 1 {
		t.Errorf("Expected fetchFn to be called exactly 1 time (singleflight), but was called %d times", actualFetchCount)
	} else {
		t.Logf("✅ Thundering herd prevented: fetchFn called only %d time(s) for %d concurrent requests", actualFetchCount, concurrency)
	}

	// Verify the entry is now cached
	entry, fromCache := cache.Get(serverName, username)
	if !fromCache {
		t.Error("Expected entry to be cached after fetch")
	}
	if entry == nil {
		t.Error("Expected cached entry, got nil")
	}
}

// TestThunderingHerdPreventionMultipleKeys verifies that singleflight works correctly
// with multiple different keys (should not block each other)
func TestThunderingHerdPreventionMultipleKeys(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 1000, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	var fetchCounts sync.Map // map[string]int32

	serverName := "test-server"
	numKeys := 10
	concurrencyPerKey := 10

	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	for keyIdx := 0; keyIdx < numKeys; keyIdx++ {
		username := fmt.Sprintf("user%d@example.com", keyIdx)
		fetchCounts.Store(username, new(atomic.Int32))

		for i := 0; i < concurrencyPerKey; i++ {
			wg.Add(1)
			go func(user string) {
				defer wg.Done()
				<-startSignal

				fetchFn := func() (*CacheEntry, error) {
					counter, _ := fetchCounts.Load(user)
					counter.(*atomic.Int32).Add(1)
					time.Sleep(50 * time.Millisecond)
					return &CacheEntry{
						AccountID:      int64(100 + keyIdx),
						HashedPassword: "hash" + user,
						PasswordHash:   HashPassword("password"),
						Result:         AuthSuccess,
						CreatedAt:      time.Now(),
						ExpiresAt:      time.Now().Add(5 * time.Minute),
						IsNegative:     false,
					}, nil
				}

				_, _, err := cache.GetOrFetch(serverName, user, fetchFn)
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", user, err)
				}
			}(username)
		}
	}

	close(startSignal)
	wg.Wait()

	// Each key should have been fetched exactly once
	fetchCounts.Range(func(key, value interface{}) bool {
		username := key.(string)
		count := value.(*atomic.Int32).Load()
		if count != 1 {
			t.Errorf("Key %s: expected 1 fetch, got %d", username, count)
		}
		return true
	})

	t.Logf("✅ Singleflight works correctly for %d different keys with %d concurrent requests each", numKeys, concurrencyPerKey)
}

// TestThunderingHerdPreventionWithErrors verifies that errors are also deduplicated
func TestThunderingHerdPreventionWithErrors(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 1000, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	var fetchCount atomic.Int32
	serverName := "test-server"
	username := "error-user@example.com"

	// Simulate a fetch that always errors
	fetchFn := func() (*CacheEntry, error) {
		fetchCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		return nil, fmt.Errorf("simulated database error")
	}

	concurrency := 50
	var wg sync.WaitGroup
	wg.Add(concurrency)
	startSignal := make(chan struct{})

	errorCount := atomic.Int32{}

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-startSignal

			_, _, err := cache.GetOrFetch(serverName, username, fetchFn)
			if err != nil {
				errorCount.Add(1)
			}
		}()
	}

	close(startSignal)
	wg.Wait()

	// Should only call fetchFn once (singleflight deduplication)
	actualFetchCount := fetchCount.Load()
	if actualFetchCount != 1 {
		t.Errorf("Expected fetchFn to be called 1 time, got %d", actualFetchCount)
	}

	// All requests should receive the error
	actualErrorCount := errorCount.Load()
	if actualErrorCount != int32(concurrency) {
		t.Errorf("Expected %d errors, got %d", concurrency, actualErrorCount)
	}

	t.Logf("✅ Error deduplication works: %d concurrent requests, only %d fetch attempt(s)", concurrency, actualFetchCount)
}

// TestCacheHitDoesNotUseSingleflight verifies that cache hits bypass singleflight
func TestCacheHitDoesNotUseSingleflight(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 1000, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	var fetchCount atomic.Int32
	serverName := "test-server"
	username := "cached-user@example.com"

	fetchFn := func() (*CacheEntry, error) {
		fetchCount.Add(1)
		return &CacheEntry{
			AccountID:      456,
			HashedPassword: "hash456",
			PasswordHash:   HashPassword("password456"),
			Result:         AuthSuccess,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(5 * time.Minute),
			IsNegative:     false,
		}, nil
	}

	// First call - should fetch
	_, fromCache, err := cache.GetOrFetch(serverName, username, fetchFn)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if fromCache {
		t.Error("First call should not be from cache")
	}
	if fetchCount.Load() != 1 {
		t.Errorf("Expected 1 fetch, got %d", fetchCount.Load())
	}

	// Subsequent calls - should hit cache without calling fetchFn
	for i := 0; i < 100; i++ {
		_, fromCache, err = cache.GetOrFetch(serverName, username, fetchFn)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !fromCache {
			t.Error("Subsequent calls should be from cache")
		}
	}

	// fetchFn should still only have been called once
	if fetchCount.Load() != 1 {
		t.Errorf("Expected fetchFn to remain at 1 call, got %d", fetchCount.Load())
	}

	t.Logf("✅ Cache hits bypass singleflight: 100 requests served from cache, only 1 fetch")
}
