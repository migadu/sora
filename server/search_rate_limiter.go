package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/pkg/metrics"
)

// SearchRateLimiter caps how many expensive searches an account may run, to
// prevent DoS attacks via excessive search queries. Each account has a token
// bucket holding up to burst searches, refilled at perWindow searches per window.
// A sustained client is held to that rate, exactly as a sliding window would hold
// it, but a burst followed by idle time is not refused: the bucket refills
// continuously rather than all at once when the oldest search leaves the window.
//
// Which commands are searches is up to the caller, which knows their criteria;
// CanSearch takes one search from the bucket.
type SearchRateLimiter struct {
	mu        sync.Mutex
	buckets   map[int64]*searchBucket
	perWindow int
	window    time.Duration
	burst     int
	// interval is the time a bucket takes to earn back one search, and capacity
	// the time it takes to fill from empty.
	interval        time.Duration
	capacity        time.Duration
	now             func() time.Time
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	protocol        string
}

// searchBucket is one account's token bucket, kept as the time at which it will
// be full again: each search moves that time one interval later, and a search
// that would move it more than the bucket's capacity past now is refused.
type searchBucket struct {
	full          time.Time
	lastLoggedAt  time.Time // Last time we logged a rate limit event
	suppressCount int       // Count of suppressed log messages since last log
}

// NewSearchRateLimiter creates a search rate limiter allowing perWindow searches
// per window, of which up to burst may run back to back (burst <= 0 means
// perWindow). It returns nil, which allows every search, when perWindow <= 0.
func NewSearchRateLimiter(protocol string, perWindow int, window time.Duration, burst int) *SearchRateLimiter {
	if perWindow <= 0 {
		return nil // Disabled
	}
	if window <= 0 {
		window = time.Minute
	}
	if burst <= 0 {
		burst = perWindow
	}

	interval := window / time.Duration(perWindow)
	limiter := &SearchRateLimiter{
		buckets:         make(map[int64]*searchBucket),
		perWindow:       perWindow,
		window:          window,
		burst:           burst,
		interval:        interval,
		capacity:        interval * time.Duration(burst),
		now:             time.Now,
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
		protocol:        protocol,
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()

	logger.Debug("Search rate limiter: Initialized", "protocol", protocol, "max", perWindow, "window", window, "burst", burst)

	return limiter
}

// CanSearch takes one search from the account's bucket, or returns an error
// saying how long to wait if the bucket is empty.
func (s *SearchRateLimiter) CanSearch(ctx context.Context, accountID int64) error {
	if s == nil {
		return nil // Disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	bucket, exists := s.buckets[accountID]
	if !exists {
		bucket = &searchBucket{full: now}
		s.buckets[accountID] = bucket
	}

	full := bucket.full
	if full.Before(now) {
		full = now
	}
	full = full.Add(s.interval)

	retryAfter := full.Sub(now) - s.capacity
	if retryAfter <= 0 {
		bucket.full = full
		return nil
	}

	// Record rate limit event
	metrics.ProtocolErrors.WithLabelValues(s.protocol, "SEARCH", "rate_limited", "client_error").Inc()

	// Log suppression: only log once per minute per user to prevent spam
	// iOS Mail and other aggressive clients may retry dozens of times per second
	logSuppressWindow := time.Minute
	shouldLog := bucket.lastLoggedAt.IsZero() || now.Sub(bucket.lastLoggedAt) >= logSuppressWindow

	if shouldLog {
		if bucket.suppressCount > 0 {
			logger.Debug("Search rate limiter: Rate limit exceeded",
				"protocol", s.protocol,
				"account", accountID,
				"burst", s.burst,
				"window", s.window,
				"retry_after", retryAfter,
				"suppressed_logs", bucket.suppressCount)
		} else {
			logger.Debug("Search rate limiter: Rate limit exceeded",
				"protocol", s.protocol,
				"account", accountID,
				"burst", s.burst,
				"window", s.window,
				"retry_after", retryAfter)
		}
		bucket.lastLoggedAt = now
		bucket.suppressCount = 0
	} else {
		bucket.suppressCount++
	}

	// Round up, so that a client waiting as told finds a search available.
	return fmt.Errorf("search rate limit exceeded: %d searches per %v, please wait %v before trying again",
		s.perWindow, s.window, (retryAfter + time.Second - 1).Truncate(time.Second))
}

// GetStats returns statistics about the search rate limiter
func (s *SearchRateLimiter) GetStats() map[string]any {
	if s == nil {
		return map[string]any{"enabled": false}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	draining := 0
	for _, bucket := range s.buckets {
		if bucket.full.After(now) {
			draining++
		}
	}

	return map[string]any{
		"enabled":              true,
		"max_searches_per_min": s.perWindow,
		"window":               s.window.String(),
		"burst":                s.burst,
		"tracked_users":        len(s.buckets),
		"active_users":         draining,
	}
}

// cleanupRoutine periodically removes buckets that have refilled
func (s *SearchRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

// cleanup removes the buckets that are full again: a full bucket is what an
// account without one starts with.
func (s *SearchRateLimiter) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	removed := 0

	for accountID, bucket := range s.buckets {
		if !bucket.full.After(now) {
			delete(s.buckets, accountID)
			removed++
		}
	}

	if removed > 0 {
		logger.Debug("Search rate limiter: Cleaned up inactive trackers", "protocol", s.protocol, "count", removed)
	}
}

// Stop stops the cleanup routine
func (s *SearchRateLimiter) Stop() {
	if s == nil {
		return
	}
	// Use select to avoid closing already-closed channel
	select {
	case <-s.stopCleanup:
		// Already stopped
		return
	default:
		close(s.stopCleanup)
	}
}
