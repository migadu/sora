package server

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a settable clock for the limiter.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestSearchLimiter returns a limiter reading the time from a fake clock.
func newTestSearchLimiter(t *testing.T, perWindow int, window time.Duration, burst int) (*SearchRateLimiter, *fakeClock) {
	t.Helper()
	limiter := NewSearchRateLimiter("TEST", perWindow, window, burst)
	require.NotNil(t, limiter)
	t.Cleanup(limiter.Stop)
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	limiter.mu.Lock()
	limiter.now = clock.now
	limiter.mu.Unlock()
	return limiter, clock
}

func TestSearchRateLimiter_Disabled(t *testing.T) {
	// Test that nil limiter (disabled) always allows searches
	var limiter *SearchRateLimiter
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		assert.NoError(t, limiter.CanSearch(ctx, 123))
	}
}

func TestSearchRateLimiter_ZeroLimit(t *testing.T) {
	// Test that limiter with 0 limit is disabled
	limiter := NewSearchRateLimiter("TEST", 0, time.Minute, 0)
	assert.Nil(t, limiter, "Limiter should be nil when perWindow is 0")
}

// A full bucket allows burst searches back to back, which by default is one
// window's worth, and then refuses.
func TestSearchRateLimiter_BurstThenRefuse(t *testing.T) {
	limiter, _ := newTestSearchLimiter(t, 5, time.Minute, 0)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		assert.NoError(t, limiter.CanSearch(ctx, 123), "search %d", i+1)
	}

	err := limiter.CanSearch(ctx, 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search rate limit exceeded")
	assert.Contains(t, err.Error(), "5 searches per 1m0s")
	// One search comes back every minute/5 = 12s.
	assert.Contains(t, err.Error(), "please wait 12s")
}

// The bucket earns back one search per window/perWindow, not the whole window's
// worth when the oldest search leaves it.
func TestSearchRateLimiter_RefillsContinuously(t *testing.T) {
	limiter, clock := newTestSearchLimiter(t, 6, time.Minute, 0)
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		require.NoError(t, limiter.CanSearch(ctx, 123))
	}
	require.Error(t, limiter.CanSearch(ctx, 123))

	clock.advance(9 * time.Second)
	err := limiter.CanSearch(ctx, 123)
	require.Error(t, err, "a search should take 10s to come back")
	assert.Contains(t, err.Error(), "please wait 1s")

	clock.advance(time.Second)
	assert.NoError(t, limiter.CanSearch(ctx, 123), "one search should be back after 10s")
	assert.Error(t, limiter.CanSearch(ctx, 123), "only one search should be back after 10s")

	clock.advance(25 * time.Second)
	assert.NoError(t, limiter.CanSearch(ctx, 123))
	assert.NoError(t, limiter.CanSearch(ctx, 123))
	assert.Error(t, limiter.CanSearch(ctx, 123), "two searches should be back after 25s, with 5s toward a third")

	clock.advance(5 * time.Second)
	assert.NoError(t, limiter.CanSearch(ctx, 123))
}

// The burst can be larger than one window's worth; the sustained rate stays
// perWindow per window.
func TestSearchRateLimiter_BurstAboveRate(t *testing.T) {
	limiter, clock := newTestSearchLimiter(t, 6, time.Minute, 30)
	ctx := context.Background()

	for i := 0; i < 30; i++ {
		require.NoError(t, limiter.CanSearch(ctx, 123), "search %d", i+1)
	}
	require.Error(t, limiter.CanSearch(ctx, 123))

	// Asking every second for ten minutes gets one search per 10s.
	allowed := 0
	for i := 0; i < 600; i++ {
		clock.advance(time.Second)
		if limiter.CanSearch(ctx, 123) == nil {
			allowed++
		}
	}
	assert.Equal(t, 60, allowed)

	// A bucket left alone fills up to the burst and no further.
	clock.advance(time.Hour)
	for i := 0; i < 30; i++ {
		require.NoError(t, limiter.CanSearch(ctx, 123), "search %d after idling", i+1)
	}
	assert.Error(t, limiter.CanSearch(ctx, 123))
}

// With the default burst, the bucket never refuses a search the sliding window it
// replaced would have allowed: any sequence of searches keeping to perWindow per
// window is admitted whole.
func TestSearchRateLimiter_AdmitsWhatSlidingWindowAdmitted(t *testing.T) {
	ctx := context.Background()
	rng := rand.New(rand.NewSource(1))

	for _, perWindow := range []int{1, 3, 7, 10, 60} {
		limiter, clock := newTestSearchLimiter(t, perWindow, time.Minute, 0)

		// The old limiter: a search is allowed if fewer than perWindow searches
		// were allowed within the window before it.
		var window []time.Time
		slidingAllows := func(now time.Time) bool {
			kept := window[:0]
			for _, at := range window {
				if at.After(now.Add(-time.Minute)) {
					kept = append(kept, at)
				}
			}
			window = kept
			if len(window) >= perWindow {
				return false
			}
			window = append(window, now)
			return true
		}

		for i := 0; i < 5000; i++ {
			// Mostly bursts, sometimes a pause long enough to refill.
			step := time.Duration(rng.Int63n(int64(2 * time.Second)))
			if rng.Intn(20) == 0 {
				step = time.Duration(rng.Int63n(int64(2 * time.Minute)))
			}
			clock.advance(step)
			if slidingAllows(clock.now()) {
				require.NoError(t, limiter.CanSearch(ctx, 123),
					"perWindow %d: search %d at %v was allowed by the sliding window", perWindow, i, clock.now())
			}
		}
	}
}

func TestSearchRateLimiter_MultipleUsers(t *testing.T) {
	limiter, _ := newTestSearchLimiter(t, 3, time.Minute, 0)
	ctx := context.Background()

	// User 1 uses their quota
	for i := 0; i < 3; i++ {
		assert.NoError(t, limiter.CanSearch(ctx, 100))
	}
	assert.Error(t, limiter.CanSearch(ctx, 100), "User 100 should be rate limited")

	// User 2 should have their own quota
	for i := 0; i < 3; i++ {
		assert.NoError(t, limiter.CanSearch(ctx, 200))
	}
	assert.Error(t, limiter.CanSearch(ctx, 200), "User 200 should be rate limited")
}

func TestSearchRateLimiter_Defaults(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 4, 0, -1)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	assert.Equal(t, time.Minute, limiter.window, "a non-positive window should default to a minute")
	assert.Equal(t, 4, limiter.burst, "a non-positive burst should default to the per-window rate")
	assert.Equal(t, 15*time.Second, limiter.interval)
}

func TestSearchRateLimiter_Stats(t *testing.T) {
	limiter, clock := newTestSearchLimiter(t, 10, time.Minute, 20)
	ctx := context.Background()

	stats := limiter.GetStats()
	assert.True(t, stats["enabled"].(bool))
	assert.Equal(t, 10, stats["max_searches_per_min"])
	assert.Equal(t, "1m0s", stats["window"])
	assert.Equal(t, 20, stats["burst"])
	assert.Equal(t, 0, stats["tracked_users"])
	assert.Equal(t, 0, stats["active_users"])

	for i := 0; i < 3; i++ {
		limiter.CanSearch(ctx, 100)
	}
	limiter.CanSearch(ctx, 200)

	stats = limiter.GetStats()
	assert.Equal(t, 2, stats["tracked_users"])
	assert.Equal(t, 2, stats["active_users"])

	// User 200's bucket is full again after 6s, user 100's after 18s.
	clock.advance(6 * time.Second)
	stats = limiter.GetStats()
	assert.Equal(t, 2, stats["tracked_users"])
	assert.Equal(t, 1, stats["active_users"])

	var nilLimiter *SearchRateLimiter
	assert.Equal(t, false, nilLimiter.GetStats()["enabled"])
}

// cleanup drops exactly the buckets that are full again, and keeps the state of
// the rest.
func TestSearchRateLimiter_Cleanup(t *testing.T) {
	limiter, clock := newTestSearchLimiter(t, 2, time.Minute, 0)
	ctx := context.Background()

	require.NoError(t, limiter.CanSearch(ctx, 100))
	require.NoError(t, limiter.CanSearch(ctx, 100))
	require.NoError(t, limiter.CanSearch(ctx, 200))

	// User 200's bucket is full after 30s, user 100's after 60s.
	clock.advance(30 * time.Second)
	limiter.cleanup()

	limiter.mu.Lock()
	_, has100 := limiter.buckets[100]
	_, has200 := limiter.buckets[200]
	limiter.mu.Unlock()
	assert.True(t, has100, "a bucket still refilling should be kept")
	assert.False(t, has200, "a full bucket should be removed")

	assert.NoError(t, limiter.CanSearch(ctx, 100))
	assert.Error(t, limiter.CanSearch(ctx, 100), "user 100 should have earned back only one search")
}

func TestSearchRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter, _ := newTestSearchLimiter(t, 10, time.Minute, 50)
	ctx := context.Background()

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if limiter.CanSearch(ctx, 123) == nil {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(50), allowed.Load(), "exactly the burst should be allowed with the clock standing still")
}

func TestSearchRateLimiter_StopCleanup(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 10, time.Minute, 0)
	require.NotNil(t, limiter)

	// Stop should not panic
	limiter.Stop()

	// Multiple stops should not panic
	limiter.Stop()

	// Nil limiter Stop should not panic
	var nilLimiter *SearchRateLimiter
	nilLimiter.Stop()
}
