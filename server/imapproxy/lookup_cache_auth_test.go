package imapproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

// TestCacheHitDoesNotDialBackend verifies that on a positive lookup-cache hit,
// authenticateUser does NOT dial the backend itself: postAuthenticationSetup
// is the single owner of connectToBackend. Regression test for the cache-hit
// double-connect (proxy review H2, 2026-07-03): the cache path used to call
// connectToBackend() and postAuthenticationSetup then connected AGAIN, dialing
// the backend twice and leaking the first connection on every cache hit.
// Before the fix this test failed: the cache path dialed 127.0.0.1:1, got
// connection-refused, and returned an error.
func TestCacheHitDoesNotDialBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache := newTestLookupCache(t)
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                newTestConnManager(t, "127.0.0.1:1"), // nothing listens here
		lookupCache:                cache,
		authLimiter:                &fakeAuthLimiter{},
		positiveRevalidationWindow: 30 * time.Second,
	}

	// Pre-populate a positive cache entry (as a previous successful DB auth would)
	cache.Set("test", "user@example.com", &lookupcache.CacheEntry{
		AccountID:    42,
		PasswordHash: lookupcache.HashPassword("secret"),
		Result:       lookupcache.AuthSuccess,
	})

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()

	sess := newSession(srv, client)

	if err := sess.authenticateUser("user@example.com", "secret"); err != nil {
		t.Fatalf("cache-hit authentication failed: %v (before the H2 fix this dialed the backend and failed)", err)
	}
	if sess.backendConn != nil {
		t.Error("cache-hit authenticateUser dialed the backend; postAuthenticationSetup must be the single owner of connectToBackend")
	}
	if sess.accountID != 42 {
		t.Errorf("accountID = %d, want 42", sess.accountID)
	}
}

// TestInvalidateLookupCacheUsesSubmittedUsername verifies that invalidation
// uses the username exactly as submitted (the cache key), not the resolved
// address. Regression test for the invalidation-key mismatch (proxy review
// M2, 2026-07-03): stale routing for token/master/+detail logins survived
// until TTL because the key was built from the resolved s.username.
func TestInvalidateLookupCacheUsesSubmittedUsername(t *testing.T) {
	cache := newTestLookupCache(t)
	srv := &Server{name: "test", lookupCache: cache}

	submitted := "user@example.com@TOKEN"
	cache.Set("test", submitted, &lookupcache.CacheEntry{AccountID: 1, Result: lookupcache.AuthSuccess})

	sess := &Session{
		server:            srv,
		submittedUsername: submitted,
		username:          "user@example.com", // resolved — the OLD buggy key source
	}
	sess.invalidateLookupCache("test")

	if _, found := cache.Get("test", submitted); found {
		t.Error("cache entry keyed on the submitted username survived invalidation")
	}
}
