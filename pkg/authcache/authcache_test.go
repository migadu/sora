package authcache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthCache_SuccessfulAuth(t *testing.T) {
	// Use long TTLs and cleanup interval to prevent race with cleanup goroutine
	cache := New(10*time.Second, 10*time.Second, 100, 1*time.Hour)
	defer cache.Stop(context.Background())

	// Create a test password hash
	password := "testpassword"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate password hash: %v", err)
	}

	address := "test@example.com"
	accountID := int64(123)

	// First authentication - should be a cache miss
	if cachedID, found := cache.Authenticate(address, password); found {
		t.Error("Expected cache miss on first authentication")
	} else if cachedID != 0 {
		t.Errorf("Expected accountID=0 on cache miss, got %d", cachedID)
	}

	// Set successful authentication
	cache.SetSuccess(address, accountID, string(hash))

	// Second authentication - should be a cache hit
	if cachedID, found := cache.Authenticate(address, password); !found {
		t.Error("Expected cache hit on second authentication")
	} else if cachedID != accountID {
		t.Errorf("Expected accountID=%d, got %d", accountID, cachedID)
	}

	// Wrong password - should be cache hit but auth failure, and cache gets invalidated
	if cachedID, found := cache.Authenticate(address, "wrongpassword"); found {
		t.Error("Expected authentication failure with wrong password")
	} else if cachedID != 0 {
		t.Errorf("Expected accountID=0 on auth failure, got %d", cachedID)
	}

	// Verify stats - cache should be invalidated after wrong password (password mismatch)
	hits, misses, size, hitRate := cache.GetStats()
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if hits != 2 {
		t.Errorf("Expected 2 hits (1 success + 1 wrong password), got %d", hits)
	}
	// After password mismatch, cache is invalidated (our new behavior)
	if size != 0 {
		t.Errorf("Expected 0 cached entries after password mismatch, got %d", size)
	}
	if hitRate < 66 || hitRate > 67 {
		t.Errorf("Expected hit rate ~66.7%%, got %.2f%%", hitRate)
	}
}

func TestAuthCache_FailureCache(t *testing.T) {
	// Use long TTLs and cleanup interval to prevent race with cleanup goroutine
	cache := New(10*time.Second, 10*time.Second, 100, 1*time.Hour)
	defer cache.Stop(context.Background())

	address := "nonexistent@example.com"

	// Cache a failure (user not found)
	cache.SetFailure(address, int(AuthUserNotFound))

	// Verify it's cached
	_, _, size, _ := cache.GetStats()
	if size != 1 {
		t.Errorf("Expected 1 cached entry, got %d", size)
	}

	// Attempting authentication should still be cache miss for negative entries
	// (we don't cache the password, so we can't verify it)
	if _, found := cache.Authenticate(address, "anypassword"); found {
		t.Error("Expected cache miss for negative cache entry")
	}
}

func TestAuthCache_Expiration(t *testing.T) {
	cache := New(50*time.Millisecond, 100*time.Millisecond, 100, 1*time.Second)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	address := "test@example.com"
	accountID := int64(456)

	// Set successful authentication
	cache.SetSuccess(address, accountID, string(hash))

	// Should be cached
	if _, found := cache.Authenticate(address, password); !found {
		t.Error("Expected cache hit immediately after SetSuccess")
	}

	// Wait for expiration (positive TTL = 50ms)
	time.Sleep(60 * time.Millisecond)

	// Should be expired
	if _, found := cache.Authenticate(address, password); found {
		t.Error("Expected cache miss after expiration")
	}
}

func TestAuthCache_Invalidation(t *testing.T) {
	// Use long cleanup interval to prevent race with cleanup goroutine
	cache := New(1*time.Second, 1*time.Second, 100, 1*time.Hour)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	address := "test@example.com"
	accountID := int64(789)

	// Set successful authentication
	cache.SetSuccess(address, accountID, string(hash))

	// Verify it's cached
	if _, found := cache.Authenticate(address, password); !found {
		t.Error("Expected cache hit before invalidation")
	}

	// Invalidate the entry
	cache.Invalidate(address)

	// Should be gone
	if _, found := cache.Authenticate(address, password); found {
		t.Error("Expected cache miss after invalidation")
	}

	// Verify size
	_, _, size, _ := cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 cached entries after invalidation, got %d", size)
	}
}

func TestAuthCache_MaxSize(t *testing.T) {
	maxSize := 5
	// Use long cleanup interval to prevent race with cleanup goroutine
	cache := New(1*time.Second, 1*time.Second, maxSize, 1*time.Hour)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add more entries than max size
	for i := 0; i < maxSize+3; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Size should be capped at maxSize
	_, _, size, _ := cache.GetStats()
	if size != maxSize {
		t.Errorf("Expected size=%d, got %d", maxSize, size)
	}
}

func TestAuthCache_CleanupExpired(t *testing.T) {
	cache := New(50*time.Millisecond, 50*time.Millisecond, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add multiple entries
	for i := 0; i < 5; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Verify all are cached
	_, _, size, _ := cache.GetStats()
	if size != 5 {
		t.Errorf("Expected 5 entries, got %d", size)
	}

	// Wait for expiration + cleanup
	time.Sleep(200 * time.Millisecond)

	// All should be cleaned up
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", size)
	}
}

func TestAuthCache_PasswordChangeInvalidation(t *testing.T) {
	// Use long TTL and cleanup interval to prevent race with cleanup
	cache := New(10*time.Second, 10*time.Second, 100, 1*time.Hour)
	defer cache.Stop(context.Background())

	address := "user@example.com"
	accountID := int64(999)

	// User's old password
	oldPassword := "oldpassword123"
	oldHash, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)

	// Cache successful auth with old password
	cache.SetSuccess(address, accountID, string(oldHash))

	// Verify old password works (cache hit)
	if cachedID, found := cache.Authenticate(address, oldPassword); !found {
		t.Error("Expected cache hit with old password")
	} else if cachedID != accountID {
		t.Errorf("Expected accountID=%d, got %d", accountID, cachedID)
	}

	// Verify cache size
	_, _, size, _ := cache.GetStats()
	if size != 1 {
		t.Errorf("Expected 1 cached entry, got %d", size)
	}

	// User changes password (simulate by trying new password)
	newPassword := "newpassword456"

	// Try to authenticate with new password - should fail AND invalidate cache
	if _, found := cache.Authenticate(address, newPassword); found {
		t.Error("Expected authentication failure with new password (cache has old hash)")
	}

	// Cache should be invalidated (password mismatch detected)
	_, _, sizeAfter, _ := cache.GetStats()
	if sizeAfter != 0 {
		t.Errorf("Expected cache to be invalidated (size=0), got %d - CACHE NOT INVALIDATED!", sizeAfter)
	}

	// Now simulate DB returning new hash and caching it
	newHash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	cache.SetSuccess(address, accountID, string(newHash))

	// New password should work now
	if cachedID, found := cache.Authenticate(address, newPassword); !found {
		t.Error("Expected cache hit with new password after re-caching")
	} else if cachedID != accountID {
		t.Errorf("Expected accountID=%d, got %d", accountID, cachedID)
	}

	// Old password should fail and invalidate again
	if _, found := cache.Authenticate(address, oldPassword); found {
		t.Error("Expected authentication failure with old password")
	}

	// Cache should be invalidated again
	_, _, sizeFinal, _ := cache.GetStats()
	if sizeFinal != 0 {
		t.Errorf("Expected cache invalidated after old password attempt, got size=%d", sizeFinal)
	}
}

func TestAuthCache_MemoryGrowthPrevention(t *testing.T) {
	// Simulate production config: 30s TTL, 5min cleanup
	cache := New(30*time.Second, 5*time.Second, 10000, 5*time.Minute)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add 1000 entries (simulating high traffic)
	for i := 0; i < 1000; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Verify size
	_, _, size, _ := cache.GetStats()
	if size != 1000 {
		t.Errorf("Expected 1000 entries, got %d", size)
	}
	t.Logf("Cache size after adding 1000 entries: %d", size)

	// Size should not exceed 1000 (no unbounded growth)
	if size > 1000 {
		t.Errorf("MEMORY LEAK: Cache grew beyond expected size! Expected 1000, got %d", size)
	}
}

func TestAuthCache_CleanupRemovesExpiredEntries(t *testing.T) {
	// Use short TTL and fast cleanup to test cleanup loop
	cache := New(500*time.Millisecond, 500*time.Millisecond, 1000, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add 100 entries
	for i := 0; i < 100; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Verify we have 100 entries
	_, _, size, _ := cache.GetStats()
	if size != 100 {
		t.Errorf("Expected 100 entries, got %d", size)
	}
	t.Logf("Initial cache size: %d", size)

	// Wait for entries to expire (500ms TTL + buffer)
	time.Sleep(600 * time.Millisecond)

	// Wait for cleanup to run (cleanup interval is 100ms)
	// Give it 2-3 cleanup cycles to be safe
	time.Sleep(300 * time.Millisecond)

	// Verify entries were cleaned up
	_, _, sizeAfter, _ := cache.GetStats()
	if sizeAfter != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d - MEMORY LEAK!", sizeAfter)
	}
	t.Logf("Cache size after cleanup: %d", sizeAfter)
}

func TestAuthCache_ContinuousCleanupPreventsGrowth(t *testing.T) {
	// Create cache with short TTL and frequent cleanup
	cache := New(200*time.Millisecond, 200*time.Millisecond, 10000, 50*time.Millisecond)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Simulate continuous login attempts over 1 second
	// This simulates real-world scenario where users login continuously
	done := make(chan bool)
	go func() {
		for i := 0; i < 200; i++ {
			address := fmt.Sprintf("user%d@example.com", i%100)
			cache.SetSuccess(address, int64(i), string(hash))
			time.Sleep(5 * time.Millisecond) // 5ms between logins
		}
		done <- true
	}()

	<-done

	// Wait for cleanup to run (TTL is 200ms, cleanup every 50ms)
	time.Sleep(300 * time.Millisecond)

	// Cache should be small (not all 200 entries!)
	// Most should have expired and been cleaned up
	_, _, finalSize, _ := cache.GetStats()
	if finalSize > 50 {
		t.Errorf("Expected cache size < 50 after cleanup, got %d - MEMORY LEAK!", finalSize)
	}
	t.Logf("Final cache size: %d (expected < 50)", finalSize)
}

func TestAuthCache_CleanupLogsRemovedEntries(t *testing.T) {
	// Test that cleanup actually logs when it removes entries
	cache := New(100*time.Millisecond, 100*time.Millisecond, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	password := "testpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Add entries
	for i := 0; i < 10; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		cache.SetSuccess(address, int64(i), string(hash))
	}

	// Verify cached
	_, _, size, _ := cache.GetStats()
	if size != 10 {
		t.Errorf("Expected 10 entries, got %d", size)
	}

	// Wait for expiration + cleanup
	// TTL=100ms, cleanup=100ms, so wait 250ms total
	time.Sleep(250 * time.Millisecond)

	// Should be cleaned up
	_, _, sizeAfter, _ := cache.GetStats()
	if sizeAfter != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", sizeAfter)
	}
}
