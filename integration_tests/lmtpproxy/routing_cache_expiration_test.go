//go:build integration

package lmtpproxy_test

import (
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

// TestRoutingCacheExpiration tests that routing cache entries expire after TTL
//
// This test reproduces the production bug where a domain moved from one backend
// to another, but the routing cache kept the old backend address for 5 minutes
// (or whatever the configured positive TTL is).
//
// Expected behavior:
//   - Cache entry created with backend A
//   - After TTL expires, cache should miss and force fresh remotelookup
//   - New remotelookup returns backend B
//
// Bug scenario:
//   - Cache entry created with backend A at 00:24:15
//   - Domain moved to backend B (remotelookup now returns B)
//   - At 00:25:16 (1 minute later), cache still returns backend A
//   - Backend A rejects with "NO [AUTHORIZATIONFAILED] Authorization failed"
//   - This continues until cache expires (5 minutes by default)
func TestRoutingCacheExpiration(t *testing.T) {
	// Create a lookup cache with SHORT TTL for testing (2 seconds)
	// In production, this is typically 5 minutes
	shortTTL := 2 * time.Second
	cache := lookupcache.New(
		shortTTL,       // positiveTTL (successful lookups)
		1*time.Minute,  // negativeTTL (failures)
		10000,          // maxSize
		30*time.Second, // cleanupInterval
		30*time.Second, // positiveRevalidationWindow
	)

	serverName := "lmtp-proxy"
	username := "team@workdepot.com.au"

	// Simulate remotelookup returning backend A
	t.Logf("Time 0s: RemoteLookup returns backend A (57.128.127.128:24)")
	entryBackendA := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "57.128.127.128:24", // Old backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(shortTTL),
	}
	cache.Set(serverName, username, entryBackendA)

	// Verify cache hit returns backend A
	cached, found := cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit after Set")
	}
	if cached.ServerAddress != "57.128.127.128:24" {
		t.Errorf("Expected backend A, got %s", cached.ServerAddress)
	}
	t.Logf("✓ Cache returns backend A (expected)")

	// Simulate time passing - 1 second later (still within TTL)
	time.Sleep(1 * time.Second)
	t.Logf("Time 1s: Domain moved to backend B (141.94.162.186:993)")
	t.Logf("Time 1s: But cache still returns backend A (TTL not expired)")

	// Cache should still return backend A (TTL not expired)
	cached, found = cache.Get(serverName, username)
	if !found {
		t.Error("BUG: Cache miss before TTL expired - expected cache hit")
	}
	if cached.ServerAddress != "57.128.127.128:24" {
		t.Errorf("Expected backend A (old cached value), got %s", cached.ServerAddress)
	}
	t.Logf("✓ Cache still returns backend A (TTL not expired)")

	// THIS IS THE BUG:
	// At this point, remotelookup would return backend B (141.94.162.186:993)
	// but the cache returns backend A (57.128.127.128:24)
	// So the proxy routes to backend A, which rejects with:
	// "Backend authentication failed proxy=imap-main-ip4 user=team@workdepot.com.au backend=141.94.162.186:993 error=failed to authenticate to backend server: p9417 NO [AUTHORIZATIONFAILED] Authorization failed"
	t.Logf("")
	t.Logf("BUG SCENARIO:")
	t.Logf("  - Cache returns backend A: %s", cached.ServerAddress)
	t.Logf("  - RemoteLookup would return backend B: 141.94.162.186:993")
	t.Logf("  - Proxy routes to backend A (from cache)")
	t.Logf("  - Backend A rejects: 'NO [AUTHORIZATIONFAILED] Authorization failed'")
	t.Logf("  - This continues for %v until cache expires", shortTTL)
	t.Logf("")

	// Wait for TTL to expire
	t.Logf("Time 2s: Waiting for cache TTL to expire...")
	time.Sleep(1200 * time.Millisecond) // Wait for TTL to expire (total 2.2s > 2s TTL)

	// After TTL expires, cache should miss
	cached, found = cache.Get(serverName, username)
	if found {
		t.Errorf("BUG: Cache HIT after TTL expired - expected cache MISS")
		t.Errorf("  Cached entry still returns: %s", cached.ServerAddress)
		t.Error("  This means expired entries are NOT being filtered out on Get()")
		t.Fail()
	} else {
		t.Logf("✓ Cache MISS after TTL expired (expected)")
	}

	// Now simulate fresh remotelookup returning backend B
	t.Logf("Time 2.2s: Fresh remotelookup returns backend B (141.94.162.186:993)")
	entryBackendB := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "141.94.162.186:993", // New backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(shortTTL),
	}
	cache.Set(serverName, username, entryBackendB)

	// Verify cache now returns backend B
	cached, found = cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit after Set")
	}
	if cached.ServerAddress != "141.94.162.186:993" {
		t.Errorf("Expected backend B, got %s", cached.ServerAddress)
	}
	t.Logf("✓ Cache now returns backend B (new correct backend)")

	t.Logf("")
	t.Logf("=== Test Summary ===")
	t.Logf("This test confirms that:")
	t.Logf("1. Cache entries DO expire after TTL (Get() returns not found)")
	t.Logf("2. During TTL window, stale routing persists")
	t.Logf("3. In production with 5min TTL, stale routing lasts 5 minutes")
	t.Logf("")
	t.Logf("Root cause:")
	t.Logf("  - Cache TTL is the ONLY mechanism to expire old routing")
	t.Logf("  - No invalidation when remotelookup returns different backend")
	t.Logf("  - No health check to detect backend rejections")
	t.Logf("")
	t.Logf("Potential fixes:")
	t.Logf("  1. Invalidate cache on backend auth failure (AUTHORIZATIONFAILED)")
	t.Logf("  2. Reduce TTL for remotelookup entries (e.g., 30s instead of 5m)")
	t.Logf("  3. Add version/ETag to remotelookup API responses")
	t.Logf("  4. Add manual cache invalidation API endpoint")
}

// TestRoutingCacheNoExpirationWithinTTL verifies cache behavior within TTL window
func TestRoutingCacheNoExpirationWithinTTL(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute,  // positiveTTL - production default
		1*time.Minute,  // negativeTTL
		10000,          // maxSize
		30*time.Second, // cleanupInterval
		30*time.Second, // positiveRevalidationWindow
	)

	serverName := "lmtp-proxy"
	username := "test@example.com"

	// Store entry with backend A
	now := time.Now()
	entry := &lookupcache.CacheEntry{
		AccountID:        12345,
		ActualEmail:      username,
		ServerAddress:    "backend-a.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
	}
	cache.Set(serverName, username, entry)

	// Verify cache returns backend A immediately
	cached, found := cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit")
	}
	if cached.ServerAddress != "backend-a.example.com:24" {
		t.Errorf("Expected backend A, got %s", cached.ServerAddress)
	}

	// Wait 1 second and verify cache still returns backend A
	time.Sleep(1 * time.Second)
	cached, found = cache.Get(serverName, username)
	if !found {
		t.Error("Expected cache hit after 1 second (TTL is 5 minutes)")
	}
	if cached.ServerAddress != "backend-a.example.com:24" {
		t.Errorf("Expected backend A, got %s", cached.ServerAddress)
	}

	t.Logf("✓ Cache correctly retains entry within TTL window")
	t.Logf("  Entry age: %v", time.Since(now))
	t.Logf("  TTL: 5m")
	t.Logf("  Server: %s", cached.ServerAddress)
}

// TestManualCacheInvalidationWorkaround tests manual cache invalidation as workaround
func TestManualCacheInvalidationWorkaround(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute,  // positiveTTL
		1*time.Minute,  // negativeTTL
		10000,          // maxSize
		30*time.Second, // cleanupInterval
		30*time.Second, // positiveRevalidationWindow
	)

	serverName := "lmtp-proxy"
	username := "test@example.com"

	// Store entry with backend A
	entry := &lookupcache.CacheEntry{
		AccountID:        12345,
		ActualEmail:      username,
		ServerAddress:    "backend-a.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, entry)

	// Verify cached
	if _, found := cache.Get(serverName, username); !found {
		t.Fatal("Expected cache hit")
	}

	// Simulate backend rejection - manually invalidate cache
	t.Logf("Backend A rejects - invalidating cache")
	cacheKey := serverName + ":" + username
	cache.Invalidate(cacheKey)

	// Verify cache miss after invalidation
	if _, found := cache.Get(serverName, username); found {
		t.Error("Expected cache miss after manual invalidation")
	}

	// Fresh remotelookup returns backend B
	entryB := &lookupcache.CacheEntry{
		AccountID:        12345,
		ActualEmail:      username,
		ServerAddress:    "backend-b.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, entryB)

	// Verify cache now returns backend B
	cached, found := cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit after re-caching")
	}
	if cached.ServerAddress != "backend-b.example.com:24" {
		t.Errorf("Expected backend B, got %s", cached.ServerAddress)
	}

	t.Logf("✓ Manual cache invalidation works as expected")
	t.Logf("  This could be the fix: invalidate cache on AUTHORIZATIONFAILED")
}

// TestCacheExpirationWithActiveUser simulates the production scenario where
// a domain moved backends and verifies cache expires properly.
//
// This is a REGRESSION TEST for the bug where active users kept stale routing
// indefinitely. Now cache expires naturally after positive_ttl.
func TestCacheExpirationWithActiveUser(t *testing.T) {
	// Use SHORT TTL for testing (2 seconds)
	shortTTL := 2 * time.Second
	cache := lookupcache.New(
		shortTTL,       // positiveTTL
		1*time.Minute,  // negativeTTL
		10000,          // maxSize
		30*time.Second, // cleanupInterval
		30*time.Second, // positiveRevalidationWindow
	)

	serverName := "lmtp-proxy"
	username := "team@workdepot.com.au"

	// Initial cache entry with backend A
	entry := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "57.128.127.128:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(shortTTL),
	}
	cache.Set(serverName, username, entry)

	t.Logf("Simulating active user making requests every 1s (TTL=%v)", shortTTL)

	// Simulate active user making requests every second
	iterations := 5
	cacheExpiredAt := -1
	for i := 0; i < iterations; i++ {
		time.Sleep(1 * time.Second)

		cached, found := cache.Get(serverName, username)
		if !found {
			t.Logf("  %ds: Cache expired", i+1)
			cacheExpiredAt = i + 1
			break
		}

		t.Logf("  %ds: Cache hit, backend=%s", i+1, cached.ServerAddress)
	}

	// Verify cache expired
	_, found := cache.Get(serverName, username)
	if found {
		t.Errorf("❌ REGRESSION: Cache still valid after %ds (%.1fx TTL)",
			iterations,
			float64(iterations)/shortTTL.Seconds())
		t.Fail()
	} else {
		t.Logf("✓ Cache expired after positive_ttl")
		if cacheExpiredAt > 0 {
			t.Logf("  Expired at %ds (expected ~%v)", cacheExpiredAt, shortTTL)
		}
	}
}
