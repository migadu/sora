package proxy

import (
	"testing"
	"time"
)

// TestCacheMemoryGrowthBetweenCleanups tests that expired entries accumulate between cleanup cycles
func TestCacheMemoryGrowthBetweenCleanups(t *testing.T) {
	// Create cache with long cleanup interval to simulate the gap
	cache := newPrelookupCache(
		"test",
		100*time.Millisecond, // Short TTL for testing
		50*time.Millisecond,  // Short negative TTL
		10000,                // Large max size
		10*time.Second,       // Long cleanup interval - simulates the gap
	)
	defer cache.Stop(testContext(t))

	// Add entries that will expire quickly
	for i := 0; i < 100; i++ {
		key := testEmail(i)
		cache.Set(key, &UserRoutingInfo{ServerAddress: "backend:143"}, AuthSuccess)
	}

	// Verify all entries are in cache
	initialSize := len(cache.entries)
	if initialSize != 100 {
		t.Fatalf("Expected 100 entries initially, got %d", initialSize)
	}

	// Wait for entries to expire (but cleanup hasn't run yet)
	time.Sleep(200 * time.Millisecond)

	// Try to access expired entries - they should be "not found" but still in memory
	for i := 0; i < 100; i++ {
		key := testEmail(i)
		_, _, found := cache.Get(key)
		if found {
			t.Errorf("Expected expired entry to not be found")
		}
	}

	// Check memory - expired entries should still be in the map
	cache.mu.RLock()
	sizeAfterExpiry := len(cache.entries)
	cache.mu.RUnlock()

	if sizeAfterExpiry != 100 {
		t.Errorf("MEMORY GROWTH: Expected 100 expired entries still in memory, got %d", sizeAfterExpiry)
		t.Errorf("Expired entries are not removed until cleanup runs")
	} else {
		t.Logf("⚠️  Memory Growth Confirmed: %d expired entries still in memory", sizeAfterExpiry)
		t.Logf("These entries consume memory until cleanup runs (every %v)", cache.cleanupInterval)
	}

	// Trigger manual cleanup
	cache.cleanup()

	// Now expired entries should be removed
	cache.mu.RLock()
	sizeAfterCleanup := len(cache.entries)
	cache.mu.RUnlock()

	if sizeAfterCleanup != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", sizeAfterCleanup)
	} else {
		t.Logf("✓ Cleanup removed all %d expired entries", initialSize)
	}
}

// TestCacheMemoryGrowthWithHighChurn tests memory growth under high insertion rate
func TestCacheMemoryGrowthWithHighChurn(t *testing.T) {
	// Simulate real-world scenario:
	// - 5 minute cleanup interval (default)
	// - 1 minute TTL (common for negative cache)
	// - High insertion rate
	cache := newPrelookupCache(
		"test",
		1*time.Minute,  // Positive TTL
		30*time.Second, // Negative TTL
		10000,          // Max size
		5*time.Minute,  // Cleanup interval (default)
	)
	defer cache.Stop(testContext(t))

	// Simulate high churn: 100 entries/second for 2 seconds
	// In production, this could be 100 failed login attempts/second
	startTime := time.Now()
	insertCount := 0

	for i := 0; i < 200; i++ {
		key := testEmail(i)
		// Simulate negative cache entries (failed logins)
		cache.Set(key, nil, AuthFailed)
		insertCount++

		// Small delay to simulate real traffic
		time.Sleep(10 * time.Millisecond)
	}

	elapsed := time.Since(startTime)
	t.Logf("Inserted %d entries in %v (%.0f entries/sec)", insertCount, elapsed, float64(insertCount)/elapsed.Seconds())

	// Check current cache size
	cache.mu.RLock()
	currentSize := len(cache.entries)
	cache.mu.RUnlock()

	t.Logf("Current cache size: %d entries", currentSize)

	// Wait for some entries to expire (but not all)
	time.Sleep(1 * time.Second)

	// Count expired entries still in memory
	cache.mu.RLock()
	now := time.Now()
	expiredCount := 0
	activeCount := 0
	for _, entry := range cache.entries {
		if now.After(entry.expiresAt) {
			expiredCount++
		} else {
			activeCount++
		}
	}
	totalSize := len(cache.entries)
	cache.mu.RUnlock()

	t.Logf("Cache state after expiry:")
	t.Logf("  Total entries: %d", totalSize)
	t.Logf("  Expired (dead weight): %d (%.1f%%)", expiredCount, float64(expiredCount)/float64(totalSize)*100)
	t.Logf("  Active: %d (%.1f%%)", activeCount, float64(activeCount)/float64(totalSize)*100)

	if expiredCount > 0 {
		// Calculate memory waste
		// Each entry is roughly: 8 (pointer) + 8 (string) + 200 (UserRoutingInfo) + 24 (time.Time) = ~240 bytes
		estimatedWaste := expiredCount * 240
		t.Logf("⚠️  Estimated memory waste: ~%d KB from expired entries", estimatedWaste/1024)
		t.Logf("   This memory won't be reclaimed until cleanup runs (in ~5 minutes)")
	}

	// Manually trigger cleanup
	cache.cleanup()

	cache.mu.RLock()
	sizeAfterCleanup := len(cache.entries)
	cache.mu.RUnlock()

	removedByCleanup := totalSize - sizeAfterCleanup
	t.Logf("✓ Cleanup removed %d expired entries", removedByCleanup)
	t.Logf("  Remaining entries: %d", sizeAfterCleanup)
}

// TestCacheEvictionVsCleanup tests the difference between eviction and cleanup
func TestCacheEvictionVsCleanup(t *testing.T) {
	// Small cache to trigger eviction
	cache := newPrelookupCache(
		"test",
		1*time.Second, // Short TTL
		500*time.Millisecond,
		100,            // Small max size to trigger eviction
		10*time.Second, // Long cleanup to observe behavior
	)
	defer cache.Stop(testContext(t))

	// Fill cache to max
	for i := 0; i < 100; i++ {
		cache.Set(testEmail(i), &UserRoutingInfo{ServerAddress: "backend:143"}, AuthSuccess)
	}

	initialSize := len(cache.entries)
	if initialSize != 100 {
		t.Fatalf("Expected 100 entries, got %d", initialSize)
	}

	// Wait for entries to expire
	time.Sleep(1500 * time.Millisecond)

	// Cache is now full of expired entries
	// Add one more entry - should trigger eviction
	cache.Set("new@example.com", &UserRoutingInfo{ServerAddress: "backend:143"}, AuthSuccess)

	// Size should still be 100 (evicted oldest expired entry)
	cache.mu.RLock()
	sizeAfterEviction := len(cache.entries)
	cache.mu.RUnlock()

	if sizeAfterEviction != 100 {
		t.Errorf("Expected 100 entries after eviction, got %d", sizeAfterEviction)
	}

	// But most entries are expired!
	cache.mu.RLock()
	now := time.Now()
	expiredCount := 0
	for _, entry := range cache.entries {
		if now.After(entry.expiresAt) {
			expiredCount++
		}
	}
	cache.mu.RUnlock()

	t.Logf("After eviction: %d total entries, %d expired (%.1f%%)",
		sizeAfterEviction, expiredCount, float64(expiredCount)/float64(sizeAfterEviction)*100)

	if expiredCount > 90 {
		t.Logf("⚠️  ISSUE: Eviction only removes 1 entry, but %d entries are expired", expiredCount)
		t.Logf("   Cache is wasting memory on expired entries")
	}

	// Cleanup should remove all expired entries
	cache.cleanup()

	cache.mu.RLock()
	sizeAfterCleanup := len(cache.entries)
	cache.mu.RUnlock()

	removedByCleanup := sizeAfterEviction - sizeAfterCleanup
	t.Logf("✓ Cleanup removed %d expired entries (eviction only removed 1)", removedByCleanup)
}

// TestLazyExpirationDoesNotDeleteEntries verifies that Get() doesn't delete expired entries
func TestLazyExpirationDoesNotDeleteEntries(t *testing.T) {
	cache := newPrelookupCache(
		"test",
		100*time.Millisecond,
		50*time.Millisecond,
		1000,
		10*time.Second,
	)
	defer cache.Stop(testContext(t))

	// Add entry
	key := "test@example.com"
	cache.Set(key, &UserRoutingInfo{ServerAddress: "backend:143"}, AuthSuccess)

	// Verify it's in cache
	_, _, found := cache.Get(key)
	if !found {
		t.Fatal("Expected entry to be found")
	}

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Access expired entry - should return not found
	_, _, found = cache.Get(key)
	if found {
		t.Error("Expected expired entry to not be found")
	}

	// BUT - entry should still be in the map!
	cache.mu.RLock()
	_, existsInMap := cache.entries[key]
	cache.mu.RUnlock()

	if !existsInMap {
		t.Error("Expected expired entry to still be in map (lazy expiration)")
	} else {
		t.Logf("✓ Confirmed: Get() returns 'not found' for expired entries")
		t.Logf("   BUT the entry remains in memory until cleanup runs")
		t.Logf("   This is lazy expiration - trades memory for performance")
	}
}

// Helper functions

func testContext(t *testing.T) testingContext {
	return testingContext{t: t}
}

type testingContext struct {
	t *testing.T
}

func (tc testingContext) Done() <-chan struct{} {
	return make(chan struct{}) // Never done
}

func (tc testingContext) Err() error {
	return nil
}

func (tc testingContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (tc testingContext) Value(key interface{}) interface{} {
	return nil
}

func testEmail(i int) string {
	return "user" + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+(i/100)%10)) + "@example.com"
}
