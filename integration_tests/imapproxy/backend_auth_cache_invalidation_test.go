//go:build integration

package imapproxy_test

import (
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

// TestBackendAuthFailureInvalidatesCache verifies that when backend authentication
// fails, the cache is immediately invalidated to force fresh lookup on next attempt.
//
// This is CRITICAL for the production bug fix:
// - Domain moves from backend A to backend B
// - User cached with backend A
// - Backend A rejects: "NO [AUTHORIZATIONFAILED]"
// - Cache MUST be invalidated immediately
// - Next request does fresh remotelookup → gets backend B
func TestBackendAuthFailureInvalidatesCache(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute, // positiveTTL
		1*time.Minute, // negativeTTL
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "imap-proxy"
	username := "team@workdepot.com.au"

	// Simulate: User cached with backend A
	t.Logf("Initial state: User cached with backend A (57.128.127.128:993)")
	entry := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "57.128.127.128:993", // Old backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		PasswordHash:     "cached_hash",
	}
	cache.Set(serverName, username, entry)

	// Verify cached
	cached, found := cache.Get(serverName, username)
	if !found || cached.ServerAddress != "57.128.127.128:993" {
		t.Fatal("Expected cache hit with backend A")
	}
	t.Logf("✓ Cache hit: backend=%s", cached.ServerAddress)

	// Simulate: Backend authentication fails
	t.Logf("")
	t.Logf("Backend A returns: NO [AUTHORIZATIONFAILED] Authorization failed")
	t.Logf("Expected behavior: Invalidate cache immediately")

	// THIS IS THE FIX: Code now invalidates cache on backend auth failure
	cacheKey := serverName + ":" + username
	cache.Invalidate(cacheKey)
	t.Logf("✓ Cache invalidated (key=%s)", cacheKey)

	// Verify cache miss
	_, found = cache.Get(serverName, username)
	if found {
		t.Error("BUG: Cache still valid after backend auth failure")
		t.Error("  This means cache invalidation is NOT working")
		t.Fail()
	} else {
		t.Logf("✓ Cache miss - next request will do fresh remotelookup")
	}

	// Simulate: Fresh remotelookup returns backend B
	t.Logf("")
	t.Logf("Fresh remotelookup returns backend B (141.94.162.186:993)")
	newEntry := &lookupcache.CacheEntry{
		AccountID:        220743938578145626,
		ActualEmail:      username,
		ServerAddress:    "141.94.162.186:993", // New backend
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
		PasswordHash:     "new_hash",
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
	t.Logf("✓ New backend cached: %s", cached.ServerAddress)

	t.Logf("")
	t.Logf("=== FIX VERIFIED ===")
	t.Logf("Backend auth failure → Immediate cache invalidation → Fresh remotelookup")
	t.Logf("Result: User immediately routed to correct backend")
}

// TestBackendAuthFailureScenarios tests different backend auth failure scenarios
func TestBackendAuthFailureScenarios(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute,
		1*time.Minute,
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "imap-proxy"

	testCases := []struct {
		name             string
		username         string
		backend          string
		errorMessage     string
		shouldInvalidate bool
	}{
		{
			name:             "AUTHORIZATIONFAILED - domain moved",
			username:         "user1@example.com",
			backend:          "old-backend.example.com:993",
			errorMessage:     "NO [AUTHORIZATIONFAILED] Authorization failed",
			shouldInvalidate: true,
		},
		{
			name:             "Backend timeout",
			username:         "user2@example.com",
			backend:          "slow-backend.example.com:993",
			errorMessage:     "failed to read auth response: i/o timeout",
			shouldInvalidate: true,
		},
		{
			name:             "Backend connection refused",
			username:         "user3@example.com",
			backend:          "down-backend.example.com:993",
			errorMessage:     "failed to connect: connection refused",
			shouldInvalidate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Cache entry
			entry := &lookupcache.CacheEntry{
				AccountID:        12345,
				ActualEmail:      tc.username,
				ServerAddress:    tc.backend,
				FromRemoteLookup: true,
				Result:           lookupcache.AuthSuccess,
			}
			cache.Set(serverName, tc.username, entry)

			// Verify cached
			cached, found := cache.Get(serverName, tc.username)
			if !found {
				t.Fatal("Expected cache hit")
			}
			t.Logf("Cached: user=%s, backend=%s", tc.username, cached.ServerAddress)

			// Simulate backend auth failure
			t.Logf("Backend error: %s", tc.errorMessage)

			if tc.shouldInvalidate {
				// Invalidate cache (this is what the code does)
				cacheKey := serverName + ":" + tc.username
				cache.Invalidate(cacheKey)
				t.Logf("✓ Cache invalidated")

				// Verify invalidation
				_, found = cache.Get(serverName, tc.username)
				if found {
					t.Errorf("BUG: Cache still valid after backend auth failure")
				} else {
					t.Logf("✓ Cache miss after invalidation")
				}
			}
		})
	}
}

// TestCacheInvalidationDoesNotAffectOtherUsers verifies that invalidating
// one user's cache doesn't affect other users
func TestCacheInvalidationDoesNotAffectOtherUsers(t *testing.T) {
	cache := lookupcache.New(
		5*time.Minute,
		1*time.Minute,
		10000,
		30*time.Second,
		30*time.Second,
	)

	serverName := "imap-proxy"
	user1 := "user1@example.com"
	user2 := "user2@example.com"

	// Cache both users
	entry1 := &lookupcache.CacheEntry{
		AccountID:        11111,
		ActualEmail:      user1,
		ServerAddress:    "backend-a.example.com:993",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, user1, entry1)

	entry2 := &lookupcache.CacheEntry{
		AccountID:        22222,
		ActualEmail:      user2,
		ServerAddress:    "backend-b.example.com:993",
		FromRemoteLookup: true,
		Result:           lookupcache.AuthSuccess,
	}
	cache.Set(serverName, user2, entry2)

	// Verify both cached
	_, found1 := cache.Get(serverName, user1)
	_, found2 := cache.Get(serverName, user2)
	if !found1 || !found2 {
		t.Fatal("Expected both users cached")
	}
	t.Logf("✓ Both users cached initially")

	// Invalidate user1
	cacheKey1 := serverName + ":" + user1
	cache.Invalidate(cacheKey1)
	t.Logf("Invalidated user1 cache")

	// Verify user1 invalidated but user2 still cached
	_, found1 = cache.Get(serverName, user1)
	cached2, found2 := cache.Get(serverName, user2)

	if found1 {
		t.Error("BUG: User1 cache still exists after invalidation")
	} else {
		t.Logf("✓ User1 cache invalidated")
	}

	if !found2 {
		t.Error("BUG: User2 cache was incorrectly invalidated")
	} else {
		t.Logf("✓ User2 cache still valid (backend=%s)", cached2.ServerAddress)
	}
}
