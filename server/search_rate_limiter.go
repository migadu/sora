package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
)

// SearchRateLimiter provides per-user rate limiting for search operations
// to prevent DoS attacks via excessive search queries
type SearchRateLimiter struct {
	mu               sync.RWMutex
	userSearches     map[int64]*UserSearchTracker
	maxPerMinute     int
	window           time.Duration
	cleanupInterval  time.Duration
	stopCleanup      chan struct{}
	protocol         string
}

// UserSearchTracker tracks search operations for a single user
type UserSearchTracker struct {
	searches     []time.Time
	lastActivity time.Time
}

// NewSearchRateLimiter creates a new search rate limiter
func NewSearchRateLimiter(protocol string, maxPerMinute int, window time.Duration) *SearchRateLimiter {
	if maxPerMinute <= 0 {
		return nil // Disabled
	}

	limiter := &SearchRateLimiter{
		userSearches:    make(map[int64]*UserSearchTracker),
		maxPerMinute:    maxPerMinute,
		window:          window,
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
		protocol:        protocol,
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()

	log.Printf("[%s-SEARCH-LIMITER] Initialized: max=%d searches per %v",
		protocol, maxPerMinute, window)

	return limiter
}

// CanSearch checks if a user can perform a search operation
func (s *SearchRateLimiter) CanSearch(ctx context.Context, accountID int64) error {
	if s == nil {
		return nil // Disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tracker, exists := s.userSearches[accountID]
	if !exists {
		tracker = &UserSearchTracker{
			searches:     make([]time.Time, 0, s.maxPerMinute),
			lastActivity: time.Now(),
		}
		s.userSearches[accountID] = tracker
	}

	now := time.Now()
	tracker.lastActivity = now
	cutoff := now.Add(-s.window)

	// Remove searches outside the time window
	validSearches := tracker.searches[:0]
	for _, t := range tracker.searches {
		if t.After(cutoff) {
			validSearches = append(validSearches, t)
		}
	}
	tracker.searches = validSearches

	// Check if limit exceeded
	if len(tracker.searches) >= s.maxPerMinute {
		// Record rate limit event
		metrics.ProtocolErrors.WithLabelValues(s.protocol, "SEARCH", "rate_limited", "client_error").Inc()

		oldestSearch := tracker.searches[0]
		retryAfter := oldestSearch.Add(s.window).Sub(now)

		log.Printf("[%s-SEARCH-LIMITER] Rate limit exceeded for account %d: %d searches in %v (retry after %v)",
			s.protocol, accountID, len(tracker.searches), s.window, retryAfter)

		return fmt.Errorf("search rate limit exceeded: %d searches in %v, please wait %v before trying again",
			len(tracker.searches), s.window, retryAfter.Round(time.Second))
	}

	// Record this search
	tracker.searches = append(tracker.searches, now)

	return nil
}

// RecordSearch records a search operation (called after successful search)
// This is optional - CanSearch already records the attempt
func (s *SearchRateLimiter) RecordSearch(accountID int64) {
	if s == nil {
		return
	}

	// Update metrics
	metrics.CommandsTotal.WithLabelValues(s.protocol, "SEARCH", "success").Inc()
}

// GetStats returns statistics about the search rate limiter
func (s *SearchRateLimiter) GetStats() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	totalUsers := len(s.userSearches)
	activeUsers := 0
	totalSearches := 0

	now := time.Now()
	cutoff := now.Add(-s.window)

	for _, tracker := range s.userSearches {
		recentSearches := 0
		for _, t := range tracker.searches {
			if t.After(cutoff) {
				recentSearches++
			}
		}
		if recentSearches > 0 {
			activeUsers++
			totalSearches += recentSearches
		}
	}

	return map[string]interface{}{
		"enabled":              true,
		"max_searches_per_min": s.maxPerMinute,
		"window":               s.window.String(),
		"tracked_users":        totalUsers,
		"active_users":         activeUsers,
		"total_searches":       totalSearches,
	}
}

// cleanupRoutine periodically removes inactive user trackers
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

// cleanup removes trackers for users who haven't searched recently
func (s *SearchRateLimiter) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	inactivityThreshold := 30 * time.Minute
	removed := 0

	for accountID, tracker := range s.userSearches {
		if now.Sub(tracker.lastActivity) > inactivityThreshold {
			delete(s.userSearches, accountID)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[%s-SEARCH-LIMITER] Cleaned up %d inactive user trackers",
			s.protocol, removed)
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
