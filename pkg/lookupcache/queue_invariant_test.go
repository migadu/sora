package lookupcache

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// checkQueues verifies that every cached item is linked into exactly the
// queue of its class, that each queue is in ExpiresAt order with consistent
// links, and that nothing else is linked.
func checkQueues(t *testing.T, c *LookupCache) {
	t.Helper()
	seen := make(map[*cacheItem]bool, len(c.entries))
	for _, q := range []struct {
		name     string
		queue    *expiryQueue
		negative bool
	}{{"positive", &c.positive, false}, {"negative", &c.negative, true}} {
		var prev *cacheItem
		for it := q.queue.front; it != nil; it = it.next {
			if it.prev != prev {
				t.Fatalf("%s queue: %s.prev is not the previous item", q.name, it.key)
			}
			if prev != nil && it.entry.ExpiresAt.Before(prev.entry.ExpiresAt) {
				t.Fatalf("%s queue: %s expires before %s, which precedes it", q.name, it.key, prev.key)
			}
			if it.entry.IsNegative != q.negative {
				t.Fatalf("%s queue holds %s of the other class", q.name, it.key)
			}
			if c.entries[it.key] != it {
				t.Fatalf("%s queue holds %s, which is not the cached item for its key", q.name, it.key)
			}
			if seen[it] {
				t.Fatalf("%s is linked twice", it.key)
			}
			seen[it] = true
			prev = it
		}
		if q.queue.back != prev {
			t.Fatalf("%s queue: back is not the last item", q.name)
		}
	}
	if len(seen) != len(c.entries) {
		t.Fatalf("queues link %d items, map holds %d", len(seen), len(c.entries))
	}
}

// Random operations keep both queues exact, and a full cache always evicts an
// entry that expires no later than any other, as the scan it replaced did.
func TestLookupCache_QueuesStayOrderedUnderRandomOperations(t *testing.T) {
	const maxSize = 32
	rng := rand.New(rand.NewSource(1))
	cache := newEvictionTestCache(t, maxSize)
	key := func() string { return fmt.Sprintf("u%d@example.com", rng.Intn(3*maxSize)) }

	for i := range 20000 {
		k := key()
		before := make(map[string]time.Time, len(cache.entries))
		var minAt time.Time
		for kk, it := range cache.entries {
			before[kk] = it.entry.ExpiresAt
			if minAt.IsZero() || it.entry.ExpiresAt.Before(minAt) {
				minAt = it.entry.ExpiresAt
			}
		}
		_, exists := cache.entries[k]
		full := !exists && len(cache.entries) >= maxSize

		switch rng.Intn(9) {
		case 0:
			cache.SetSuccess(k, int64(rng.Intn(8)+1), "hash", "secret")
		case 1:
			cache.SetFailure(k, int(AuthUserNotFound))
		case 2, 3:
			// An entry that brings its own expiry, anywhere from past to future.
			now := time.Now()
			cache.Set("", k, &CacheEntry{
				AccountID:  int64(rng.Intn(8) + 1),
				IsNegative: rng.Intn(2) == 0,
				CreatedAt:  now,
				ExpiresAt:  now.Add(time.Duration(rng.Intn(20)-5) * time.Minute),
			})
		case 4:
			cache.Set("", k, &CacheEntry{AccountID: int64(rng.Intn(8) + 1), IsNegative: rng.Intn(2) == 0})
		case 5:
			cache.Invalidate(k)
			full = false
		case 6:
			cache.InvalidateAccount(int64(rng.Intn(8) + 1))
			full = false
		case 7:
			cache.Refresh("", k)
			full = false
		case 8:
			cache.cleanup()
			full = false
		}
		checkQueues(t, cache)
		if len(cache.entries) > maxSize {
			t.Fatalf("op %d: %d entries, max %d", i, len(cache.entries), maxSize)
		}
		if full {
			for kk, at := range before {
				if _, still := cache.entries[kk]; !still && at.After(minAt) {
					t.Fatalf("op %d: evicted %s expiring at %v while another entry expires at %v", i, kk, at, minAt)
				}
			}
		}
	}
}
