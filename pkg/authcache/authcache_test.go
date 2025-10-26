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

	// Wrong password - should be cache hit but auth failure
	if cachedID, found := cache.Authenticate(address, "wrongpassword"); found {
		t.Error("Expected authentication failure with wrong password")
	} else if cachedID != 0 {
		t.Errorf("Expected accountID=0 on auth failure, got %d", cachedID)
	}

	// Verify stats
	hits, misses, size, hitRate := cache.GetStats()
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if hits != 2 {
		t.Errorf("Expected 2 hits (1 success + 1 wrong password), got %d", hits)
	}
	if size != 1 {
		t.Errorf("Expected 1 cached entry, got %d", size)
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
