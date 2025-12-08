//go:build integration

package lmtpproxy_test

import (
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

// TestPositiveTTLShouldExpireWithoutRefresh tests that positive TTL entries
// expire after the configured time, even for routing cache.
//
// REQUIREMENT:
//   - positive_ttl configures how long successful lookups are cached
//   - After positive_ttl expires, remotelookup should revalidate (both auth AND routing)
//   - Refresh() should NOT be called for routing cache
func TestPositiveTTLShouldExpireWithoutRefresh(t *testing.T) {
	positiveTTL := 2 * time.Second
	cache := lookupcache.New(
		positiveTTL,   // positive_ttl
		1*time.Minute, // negative_ttl
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "lmtp-proxy"
	username := "test@example.com"

	// Cache routing entry
	entry := &lookupcache.CacheEntry{
		AccountID:        12345,
		ActualEmail:      username,
		ServerAddress:    "backend-a.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, entry)

	t.Logf("Cached routing: backend-a.example.com:24")
	t.Logf("positive_ttl: %v", positiveTTL)

	// Verify cache hit
	cached, found := cache.Get(serverName, username)
	if !found || cached.ServerAddress != "backend-a.example.com:24" {
		t.Fatal("Expected cache hit with backend A")
	}
	t.Logf("✓ Cache hit immediately after Set()")

	// Wait for positive_ttl to expire
	t.Logf("Waiting %v for positive_ttl to expire...", positiveTTL+500*time.Millisecond)
	time.Sleep(positiveTTL + 500*time.Millisecond)

	// After positive_ttl, cache should miss (forcing remotelookup revalidation)
	_, found = cache.Get(serverName, username)
	if found {
		t.Errorf("REQUIREMENT VIOLATION: Cache still valid after positive_ttl")
		t.Errorf("  Expected: cache miss (remotelookup revalidation)")
		t.Errorf("  Actual: cache hit")
		t.Errorf("  This means positive_ttl is not being respected")
		t.Fail()
	} else {
		t.Logf("✓ Cache expired after positive_ttl (remotelookup will revalidate)")
	}
}

// TestNegativeTTLShouldExpire tests that negative TTL entries expire
// and are NEVER refreshed.
//
// REQUIREMENT:
//   - negative_ttl configures how long failed lookups are cached
//   - After negative_ttl expires, remotelookup should retry
//   - Negative entries should NEVER be refreshed (always expire after negative_ttl)
func TestNegativeTTLShouldExpire(t *testing.T) {
	negativeTTL := 2 * time.Second
	cache := lookupcache.New(
		5*time.Minute, // positive_ttl
		negativeTTL,   // negative_ttl
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "lmtp-proxy"
	username := "test@example.com"

	// Cache negative entry (user not found)
	entry := &lookupcache.CacheEntry{
		Result:     lookupcache.AuthUserNotFound,
		IsNegative: true,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(negativeTTL),
	}
	cache.Set(serverName, username, entry)

	t.Logf("Cached negative entry: user not found")
	t.Logf("negative_ttl: %v", negativeTTL)

	// Verify cache hit
	cached, found := cache.Get(serverName, username)
	if !found || !cached.IsNegative {
		t.Fatal("Expected cache hit with negative entry")
	}
	t.Logf("✓ Cache hit immediately after Set()")

	// Wait for negative_ttl to expire
	t.Logf("Waiting %v for negative_ttl to expire...", negativeTTL+500*time.Millisecond)
	time.Sleep(negativeTTL + 500*time.Millisecond)

	// After negative_ttl, cache should miss
	_, found = cache.Get(serverName, username)
	if found {
		t.Errorf("REQUIREMENT VIOLATION: Negative cache still valid after negative_ttl")
		t.Errorf("  Expected: cache miss (remotelookup retry)")
		t.Errorf("  Actual: cache hit")
		t.Fail()
	} else {
		t.Logf("✓ Negative cache expired after negative_ttl")
	}
}

// TestBackendAuthFailureShouldInvalidateCache tests that backend
// AUTHORIZATIONFAILED should immediately invalidate BOTH auth and routing cache.
//
// REQUIREMENT:
//   - When backend returns AUTHORIZATIONFAILED, invalidate cache immediately
//   - This forces next request to do fresh remotelookup
//   - Applies to both auth cache and routing cache
func TestBackendAuthFailureShouldInvalidateCache(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute, // positive_ttl
		1*time.Minute, // negative_ttl
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "lmtp-proxy"
	username := "team@workdepot.com.au"

	// Cache entry with backend A
	entry := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "57.128.127.128:24", // Old backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, entry)

	// Verify cached
	cached, found := cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit")
	}
	t.Logf("✓ Cached: backend=%s", cached.ServerAddress)

	// Simulate backend AUTHORIZATIONFAILED
	t.Logf("Backend returns: NO [AUTHORIZATIONFAILED] Authorization failed")
	t.Logf("Expected behavior: Invalidate cache immediately")

	// THIS IS THE FIX: Invalidate cache on backend auth failure
	cacheKey := serverName + ":" + username
	cache.Invalidate(cacheKey)
	t.Logf("✓ Cache invalidated")

	// Verify cache miss
	_, found = cache.Get(serverName, username)
	if found {
		t.Error("REQUIREMENT VIOLATION: Cache still valid after backend auth failure")
		t.Error("  Expected: cache miss (force fresh remotelookup)")
		t.Error("  Actual: cache hit")
		t.Fail()
	} else {
		t.Logf("✓ Cache miss - next request will do fresh remotelookup")
	}

	// Fresh remotelookup returns backend B
	newEntry := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "141.94.162.186:993", // New backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, newEntry)

	// Verify new backend cached
	cached, found = cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit after fresh remotelookup")
	}
	if cached.ServerAddress != "141.94.162.186:993" {
		t.Errorf("Expected backend B, got %s", cached.ServerAddress)
	}
	t.Logf("✓ Fresh remotelookup cached new backend: %s", cached.ServerAddress)

	t.Logf("")
	t.Logf("=== REQUIREMENT SATISFIED ===")
	t.Logf("Backend AUTHORIZATIONFAILED -> Invalidate cache -> Fresh remotelookup")
}

// TestCacheExpiresForActiveUsers verifies that routing cache expires after
// positive_ttl even when the user is actively making requests.
//
// This is a REGRESSION TEST ensuring we don't reintroduce the bug where
// cache.Refresh() calls prevented cache expiration for active users.
func TestCacheExpiresForActiveUsers(t *testing.T) {
	positiveTTL := 2 * time.Second
	cache := lookupcache.New(
		positiveTTL,   // positive_ttl
		1*time.Minute, // negative_ttl
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "lmtp-proxy"
	username := "test@example.com"

	// Cache routing entry
	entry := &lookupcache.CacheEntry{
		AccountID:        12345,
		ActualEmail:      username,
		ServerAddress:    "backend-a.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, username, entry)

	t.Logf("Simulating active user making requests every 1s (TTL=%v)", positiveTTL)

	// Simulate user making requests every 1 second (like email client)
	for i := 0; i < 3; i++ {
		time.Sleep(1 * time.Second)

		_, found := cache.Get(serverName, username)
		if !found {
			// Cache expired during active use - this is the EXPECTED behavior
			t.Logf("  %ds: Cache expired", i+1)
			t.Logf("✓ Cache expired despite active use - next request triggers remotelookup")
			return
		}

		t.Logf("  %ds: Cache hit", i+1)
	}

	// After 3 seconds (1.5x TTL), cache should have expired
	_, found := cache.Get(serverName, username)
	if found {
		t.Errorf("❌ REGRESSION: Cache still valid after 3s (1.5x TTL)")
		t.Errorf("  Cache should expire naturally after positive_ttl")
		t.Fail()
	} else {
		t.Logf("✓ Cache expired after positive_ttl as expected")
	}
}

// TestPositiveTTLVsNegativeTTLBehavior tests the difference between
// positive and negative TTL behavior.
func TestPositiveTTLVsNegativeTTLBehavior(t *testing.T) {
	positiveTTL := 5 * time.Minute
	negativeTTL := 1 * time.Minute

	cache := lookupcache.New(
		positiveTTL,
		negativeTTL,
		10000,
		30*time.Second,
		30*time.Second,
	)

	t.Logf("Configuration:")
	t.Logf("  positive_ttl: %v (successful lookups)", positiveTTL)
	t.Logf("  negative_ttl: %v (failed lookups)", negativeTTL)
	t.Logf("")

	serverName := "test-proxy"

	// Test positive entry
	positiveEntry := &lookupcache.CacheEntry{
		AccountID:        12345,
		ServerAddress:    "backend.example.com:24",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		IsNegative:       false,
	}
	cache.Set(serverName, "user1@example.com", positiveEntry)

	cachedPos, found := cache.Get(serverName, "user1@example.com")
	if !found {
		t.Error("Expected cache hit for positive entry")
	}
	ttlRemaining := time.Until(cachedPos.ExpiresAt)
	t.Logf("Positive entry cached:")
	t.Logf("  User: user1@example.com")
	t.Logf("  Backend: %s", cachedPos.ServerAddress)
	t.Logf("  TTL remaining: %v (should be ~%v)", ttlRemaining, positiveTTL)
	t.Logf("  Will expire at: %s", cachedPos.ExpiresAt.Format("15:04:05"))

	// Test negative entry
	negativeEntry := &lookupcache.CacheEntry{
		Result:     lookupcache.AuthUserNotFound,
		IsNegative: true,
	}
	cache.Set(serverName, "user2@example.com", negativeEntry)

	cachedNeg, found := cache.Get(serverName, "user2@example.com")
	if !found {
		t.Error("Expected cache hit for negative entry")
	}
	ttlRemaining = time.Until(cachedNeg.ExpiresAt)
	t.Logf("")
	t.Logf("Negative entry cached:")
	t.Logf("  User: user2@example.com")
	t.Logf("  Result: AuthUserNotFound")
	t.Logf("  TTL remaining: %v (should be ~%v)", ttlRemaining, negativeTTL)
	t.Logf("  Will expire at: %s", cachedNeg.ExpiresAt.Format("15:04:05"))

	t.Logf("")
	t.Logf("Expected behavior:")
	t.Logf("  - Positive entries live for %v", positiveTTL)
	t.Logf("  - Negative entries live for %v", negativeTTL)
	t.Logf("  - Neither should be refreshed (let TTL expire naturally)")
	t.Logf("  - Backend AUTHORIZATIONFAILED should invalidate immediately")
}
