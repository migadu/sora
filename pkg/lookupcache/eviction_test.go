package lookupcache

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func newEvictionTestCache(t testing.TB, maxSize int) *LookupCache {
	t.Helper()
	cache := New(5*time.Minute, time.Minute, maxSize, time.Hour, 30*time.Second)
	t.Cleanup(func() { _ = cache.Stop(context.Background()) })
	return cache
}

func requireCached(t *testing.T, cache *LookupCache, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, found := cache.Get("", key); !found {
			t.Errorf("%s was evicted, want it cached", key)
		}
	}
}

func requireEvicted(t *testing.T, cache *LookupCache, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, found := cache.Get("", key); found {
			t.Errorf("%s is still cached, want it evicted", key)
		}
	}
}

// Replacing a key that is already cached does not grow the cache, so it must
// not evict anyone else to make room.
func TestLookupCache_ReplaceAtCapacityEvictsNothing(t *testing.T) {
	inserts := map[string]func(c *LookupCache, key string){
		"SetSuccess": func(c *LookupCache, key string) { c.SetSuccess(key, 7, "hash", "secret") },
		"SetFailure": func(c *LookupCache, key string) { c.SetFailure(key, int(AuthUserNotFound)) },
		"Set": func(c *LookupCache, key string) {
			c.Set("", key, &CacheEntry{AccountID: 7, Result: AuthSuccess})
		},
	}
	for name, insert := range inserts {
		t.Run(name, func(t *testing.T) {
			cache := newEvictionTestCache(t, 4)
			keys := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"}
			for _, key := range keys {
				insert(cache, key)
			}

			insert(cache, "d@example.com")

			if _, _, size, _ := cache.GetStats(); size != len(keys) {
				t.Errorf("size = %d after replacing a cached key, want %d", size, len(keys))
			}
			requireCached(t, cache, keys...)
		})
	}
}

// A full cache makes room by dropping the entry that expires first, so a
// spray of failed logins (short negative TTL) does not push out the positive
// entries of users who logged in successfully.
func TestLookupCache_EvictsEntryThatExpiresFirst(t *testing.T) {
	t.Run("negative before older positive", func(t *testing.T) {
		cache := newEvictionTestCache(t, 3)
		cache.SetSuccess("p1@example.com", 1, "hash", "secret")
		cache.SetFailure("n1@example.com", int(AuthUserNotFound))
		cache.SetSuccess("p2@example.com", 2, "hash", "secret")

		cache.SetFailure("n2@example.com", int(AuthUserNotFound))
		requireEvicted(t, cache, "n1@example.com")
		requireCached(t, cache, "p1@example.com", "p2@example.com", "n2@example.com")

		cache.SetSuccess("p3@example.com", 3, "hash", "secret")
		requireEvicted(t, cache, "n2@example.com")
		requireCached(t, cache, "p1@example.com", "p2@example.com", "p3@example.com")

		cache.SetSuccess("p4@example.com", 4, "hash", "secret")
		requireEvicted(t, cache, "p1@example.com")
		requireCached(t, cache, "p2@example.com", "p3@example.com", "p4@example.com")
	})

	t.Run("negative spray keeps fresh positives", func(t *testing.T) {
		cache := newEvictionTestCache(t, 100)
		var positives []string
		for i := range 10 {
			key := fmt.Sprintf("user%d@example.com", i)
			positives = append(positives, key)
			cache.SetSuccess(key, int64(i+1), "hash", "secret")
		}
		for i := range 1000 {
			cache.SetFailure(fmt.Sprintf("unknown%d@example.com", i), int(AuthUserNotFound))
		}
		requireCached(t, cache, positives...)
		if _, _, size, _ := cache.GetStats(); size != 100 {
			t.Errorf("size = %d, want 100", size)
		}
	})

	t.Run("expired entry before live ones", func(t *testing.T) {
		cache := newEvictionTestCache(t, 3)
		cache.SetFailure("n1@example.com", int(AuthUserNotFound))
		cache.SetFailure("n2@example.com", int(AuthUserNotFound))
		now := time.Now()
		cache.Set("", "stale@example.com", &CacheEntry{
			AccountID: 9, Result: AuthSuccess,
			CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-time.Second),
		})

		cache.SetFailure("n3@example.com", int(AuthUserNotFound))
		if _, _, size, _ := cache.GetStats(); size != 3 {
			t.Fatalf("size = %d, want 3", size)
		}
		requireCached(t, cache, "n1@example.com", "n2@example.com", "n3@example.com")
	})

	t.Run("replacement moves the key to its new class", func(t *testing.T) {
		cache := newEvictionTestCache(t, 3)
		cache.SetFailure("x@example.com", int(AuthInvalidPassword))
		cache.SetSuccess("x@example.com", 1, "hash", "secret")
		cache.SetFailure("n1@example.com", int(AuthUserNotFound))
		cache.SetFailure("n2@example.com", int(AuthUserNotFound))

		cache.SetFailure("n3@example.com", int(AuthUserNotFound))
		requireEvicted(t, cache, "n1@example.com")
		requireCached(t, cache, "x@example.com", "n2@example.com", "n3@example.com")
	})

	t.Run("refreshed entry outlives unrefreshed one", func(t *testing.T) {
		cache := newEvictionTestCache(t, 2)
		cache.SetSuccess("p1@example.com", 1, "hash", "secret")
		cache.SetSuccess("p2@example.com", 2, "hash", "secret")
		if !cache.Refresh("", "p1@example.com") {
			t.Fatal("Refresh found no entry")
		}

		cache.SetSuccess("p3@example.com", 3, "hash", "secret")
		requireEvicted(t, cache, "p2@example.com")
		requireCached(t, cache, "p1@example.com", "p3@example.com")
	})
}

// cleanup drops every expired entry and only those, whatever order they
// were inserted in.
func TestLookupCache_CleanupRemovesOnlyExpired(t *testing.T) {
	cache := newEvictionTestCache(t, 100)
	now := time.Now()
	cache.SetSuccess("live@example.com", 1, "hash", "secret")
	cache.SetFailure("live-negative@example.com", int(AuthUserNotFound))
	for _, key := range []string{"stale1@example.com", "stale2@example.com"} {
		cache.Set("", key, &CacheEntry{
			AccountID: 2, Result: AuthSuccess,
			CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-time.Second),
		})
		cache.Set("", "negative-"+key, &CacheEntry{
			Result: AuthUserNotFound, IsNegative: true,
			CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-time.Second),
		})
	}
	cache.SetSuccess("live2@example.com", 3, "hash", "secret")

	cache.cleanup()

	if _, _, size, _ := cache.GetStats(); size != 3 {
		t.Errorf("size = %d after cleanup, want 3", size)
	}
	requireCached(t, cache, "live@example.com", "live-negative@example.com", "live2@example.com")
}

// fillWithFailures fills cache to capacity with negative entries and returns
// a source of addresses that are not cached, so every further insert evicts.
func fillWithFailures(cache *LookupCache, maxSize int) func() string {
	for i := range maxSize {
		cache.SetFailure(fmt.Sprintf("filler%d@example.com", i), int(AuthUserNotFound))
	}
	n := 0
	return func() string {
		n++
		return fmt.Sprintf("new%d@example.com", n)
	}
}

// insertCostAtCapacity returns the best per-insert time over a few rounds of
// inserts into a full cache, the minimum smoothing out GC and scheduling noise.
func insertCostAtCapacity(t *testing.T, maxSize int) time.Duration {
	cache := newEvictionTestCache(t, maxSize)
	next := fillWithFailures(cache, maxSize)
	const rounds, perRound = 5, 200
	keys := make([]string, rounds*perRound)
	for i := range keys {
		keys[i] = next()
	}
	best := time.Duration(1<<63 - 1)
	for r := range rounds {
		start := time.Now()
		for _, key := range keys[r*perRound : (r+1)*perRound] {
			cache.SetFailure(key, int(AuthUserNotFound))
		}
		if d := time.Since(start) / perRound; d < best {
			best = d
		}
	}
	return best
}

// Inserting into a full cache holds the write lock that every login waits
// on, so its cost must not grow with max_size.
func TestLookupCache_InsertAtCapacityCostIndependentOfSize(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	small := insertCostAtCapacity(t, 1_000)
	large := insertCostAtCapacity(t, 100_000)
	t.Logf("insert at capacity: max_size 1000 = %v, max_size 100000 = %v", small, large)
	// A scan of the entries makes the large cache ~100x slower; a constant-time
	// eviction leaves only cache-miss effects of the bigger map.
	if large > 20*small {
		t.Errorf("insert at capacity costs %v with max_size 100000 vs %v with 1000: eviction scales with cache size", large, small)
	}
}

// BenchmarkLookupCache_SetFailureAtCapacity times an insert of a new address
// into a full cache, which has to evict an entry first.
func BenchmarkLookupCache_SetFailureAtCapacity(b *testing.B) {
	for _, maxSize := range []int{1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("max_size=%d", maxSize), func(b *testing.B) {
			cache := newEvictionTestCache(b, maxSize)
			fillWithFailures(cache, maxSize)
			// Cycling through twice max_size addresses keeps every insert a
			// new key: the cache holds only the last max_size of them.
			keys := make([]string, 2*maxSize)
			for i := range keys {
				keys[i] = fmt.Sprintf("bench%d@example.com", i)
			}
			i := 0
			for b.Loop() {
				cache.SetFailure(keys[i%len(keys)], int(AuthUserNotFound))
				i++
			}
		})
	}
}
