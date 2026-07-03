package managesieveproxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

func newMSTestLookupCache(t *testing.T) *lookupcache.LookupCache {
	t.Helper()
	c := lookupcache.New(5*time.Minute, 1*time.Minute, 100, 5*time.Minute, 30*time.Second)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	return c
}

// TestMSInvalidateLookupCacheUsesSubmittedUsername verifies that invalidation
// uses the username exactly as submitted (the cache key), not the resolved
// address. Regression test for the invalidation-key mismatch (proxy review
// MS3, 2026-07-03): stale routing for token/master/+detail logins survived
// until TTL because the key was built from the resolved s.username.
func TestMSInvalidateLookupCacheUsesSubmittedUsername(t *testing.T) {
	cache := newMSTestLookupCache(t)
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
