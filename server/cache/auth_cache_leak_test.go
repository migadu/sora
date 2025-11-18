package cache

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestAuthCache_NoGoroutineLeak tests that the cache properly cleans up its goroutine
func TestAuthCache_NoGoroutineLeak(t *testing.T) {
	// Get initial goroutine count
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create and stop multiple caches
	for i := 0; i < 10; i++ {
		cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)

		// Add some entries
		cache.Set("imap", "user@example.com", &CacheEntry{
			AccountID:  123,
			AuthResult: AuthSuccess,
		})

		// Stop the cache
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := cache.Stop(ctx)
		cancel()

		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
	}

	// Force GC and wait for goroutines to finish
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	leakedGoroutines := finalGoroutines - initialGoroutines

	// Allow some variance (background GC, etc.) but should not leak 10 goroutines
	if leakedGoroutines > 2 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, leakedGoroutines)
	}
}

// TestAuthCache_StopIdempotent tests that Stop can be called multiple times safely
func TestAuthCache_StopIdempotent(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)

	ctx := context.Background()

	// First stop - should work
	err := cache.Stop(ctx)
	if err != nil {
		t.Fatalf("First Stop failed: %v", err)
	}

	// Second stop - should not panic
	err = cache.Stop(ctx)
	if err != nil {
		t.Fatalf("Second Stop failed: %v", err)
	}

	// Third stop - should still not panic
	err = cache.Stop(ctx)
	if err != nil {
		t.Fatalf("Third Stop failed: %v", err)
	}
}

// TestAuthCache_ConcurrentAccess tests that concurrent access doesn't cause issues
func TestAuthCache_ConcurrentAccess(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Set("imap", "user@example.com", &CacheEntry{
					AccountID:  int64(id*1000 + j),
					AuthResult: AuthSuccess,
				})
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Get("imap", "user@example.com")
			}
		}()
	}

	// Concurrent invalidations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Invalidate("imap", "user@example.com")
			}
		}()
	}

	wg.Wait()

	// Should not crash or deadlock
}

// TestAuthCache_NoMemoryLeakOnExpiry tests that expired entries are actually removed
func TestAuthCache_NoMemoryLeakOnExpiry(t *testing.T) {
	cache := New(50*time.Millisecond, 50*time.Millisecond, 10000, 25*time.Millisecond)
	defer cache.Stop(context.Background())

	// Add many entries
	for i := 0; i < 1000; i++ {
		cache.Set("imap", "user"+string(rune(i))+"@example.com", &CacheEntry{
			AccountID:  int64(i),
			AuthResult: AuthSuccess,
		})
	}

	// Verify they're all cached
	_, _, size, _ := cache.GetStats()
	if size != 1000 {
		t.Errorf("Expected 1000 entries, got %d", size)
	}

	// Wait for entries to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// All entries should be expired and cleaned up
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after expiry, got %d (memory leak)", size)
	}
}

// TestAuthCache_MaxSizeDoesNotGrowUnbounded tests that cache respects max size
func TestAuthCache_MaxSizeDoesNotGrowUnbounded(t *testing.T) {
	maxSize := 100
	cache := New(5*time.Second, 2*time.Second, maxSize, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Try to add way more than max size
	for i := 0; i < maxSize*10; i++ {
		cache.Set("imap", "user"+string(rune(i))+"@example.com", &CacheEntry{
			AccountID:  int64(i),
			AuthResult: AuthSuccess,
		})
	}

	// Size should not exceed max
	_, _, size, _ := cache.GetStats()
	if size > maxSize {
		t.Errorf("Cache grew beyond max size: %d > %d (memory leak)", size, maxSize)
	}
}
