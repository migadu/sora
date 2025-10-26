package authcache

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestAuthCache_MemoryCleanup verifies that expired entries are cleaned up and memory doesn't grow indefinitely
func TestAuthCache_MemoryCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	// Create cache with very short TTLs and frequent cleanup
	cache := New(50*time.Millisecond, 50*time.Millisecond, 10000, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add many entries rapidly
	numEntries := 1000
	for i := 0; i < numEntries; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Verify all entries are cached
	_, _, size, _ := cache.GetStats()
	if size != numEntries {
		t.Errorf("Expected %d entries, got %d", numEntries, size)
	}

	// Wait for entries to expire and cleanup to run (TTL=50ms, cleanup=100ms)
	time.Sleep(200 * time.Millisecond)

	// All entries should be cleaned up
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after expiration, got %d", size)
	}
}

// TestAuthCache_MaxSizeEnforcement verifies that cache never exceeds max size
func TestAuthCache_MaxSizeEnforcement(t *testing.T) {
	maxSize := 100
	cache := New(1*time.Second, 1*time.Second, maxSize, 1*time.Second)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add way more entries than max size
	for i := 0; i < maxSize*3; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))

		// Verify size never exceeds max
		_, _, size, _ := cache.GetStats()
		if size > maxSize {
			t.Fatalf("Cache size %d exceeded max size %d at iteration %d", size, maxSize, i)
		}
	}

	// Final size should be exactly max size
	_, _, size, _ := cache.GetStats()
	if size != maxSize {
		t.Errorf("Expected final size %d, got %d", maxSize, size)
	}
}

// TestAuthCache_NoLeakAfterStop verifies cache properly stops and doesn't leak goroutines
func TestAuthCache_NoLeakAfterStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping goroutine leak test in short mode")
	}

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create and stop many caches
	numCaches := 10
	for i := 0; i < numCaches; i++ {
		cache := New(1*time.Second, 1*time.Second, 100, 100*time.Millisecond)

		// Add some entries
		password := "testpassword"
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		for j := 0; j < 10; j++ {
			address := fmt.Sprintf("user%d@example.com", j)
			cache.SetSuccess(address, int64(j), string(hash))
		}

		// Stop the cache
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := cache.Stop(ctx); err != nil {
			t.Errorf("Failed to stop cache %d: %v", i, err)
		}
		cancel()
	}

	// Force garbage collection
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Check goroutine count hasn't grown significantly
	finalGoroutines := runtime.NumGoroutine()
	leakedGoroutines := finalGoroutines - initialGoroutines

	// Allow some variance (background goroutines, GC, etc.)
	maxAllowedLeak := 2
	if leakedGoroutines > maxAllowedLeak {
		t.Errorf("Potential goroutine leak: initial=%d, final=%d, leaked=%d (max allowed: %d)",
			initialGoroutines, finalGoroutines, leakedGoroutines, maxAllowedLeak)
	}
}

// TestAuthCache_ExpiredNotRemovedOnRead verifies that expired entries remain in map until cleanup
// This is a performance optimization - we don't delete on every read, only during periodic cleanup
func TestAuthCache_ExpiredNotRemovedOnRead(t *testing.T) {
	cache := New(50*time.Millisecond, 50*time.Millisecond, 100, 10*time.Second) // Long cleanup interval
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add an entry
	cache.SetSuccess("test@example.com", 123, string(hash))

	// Verify it's cached
	_, _, size, _ := cache.GetStats()
	if size != 1 {
		t.Fatalf("Expected 1 entry, got %d", size)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Try to authenticate - should fail (expired)
	if _, found := cache.Authenticate("test@example.com", password); found {
		t.Error("Expected cache miss for expired entry")
	}

	// Entry should STILL be in the map (not deleted on read)
	_, _, size, _ = cache.GetStats()
	if size != 1 {
		t.Errorf("Expected entry to remain in map until cleanup, got size=%d", size)
	}

	// Manually trigger cleanup
	cache.cleanup()

	// Now it should be removed
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", size)
	}
}
