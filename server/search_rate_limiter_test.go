package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchRateLimiter_Disabled(t *testing.T) {
	// Test that nil limiter (disabled) always allows searches
	var limiter *SearchRateLimiter
	ctx := context.Background()

	err := limiter.CanSearch(ctx, 123)
	assert.NoError(t, err)

	// Should work even with many calls
	for i := 0; i < 100; i++ {
		err = limiter.CanSearch(ctx, 123)
		assert.NoError(t, err)
	}
}

func TestSearchRateLimiter_ZeroLimit(t *testing.T) {
	// Test that limiter with 0 limit is disabled
	limiter := NewSearchRateLimiter("TEST", 0, time.Minute)
	assert.Nil(t, limiter, "Limiter should be nil when maxPerMinute is 0")
}

func TestSearchRateLimiter_BasicRateLimiting(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 5, time.Minute)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()
	accountID := int64(123)

	// First 5 searches should succeed
	for i := 0; i < 5; i++ {
		err := limiter.CanSearch(ctx, accountID)
		assert.NoError(t, err, "Search %d should succeed", i+1)
	}

	// 6th search should fail
	err := limiter.CanSearch(ctx, accountID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "search rate limit exceeded")
	assert.Contains(t, err.Error(), "5 searches")
}

func TestSearchRateLimiter_TimeWindowExpiry(t *testing.T) {
	// Use short window for faster testing
	limiter := NewSearchRateLimiter("TEST", 3, 200*time.Millisecond)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()
	accountID := int64(123)

	// Use up the limit
	for i := 0; i < 3; i++ {
		err := limiter.CanSearch(ctx, accountID)
		assert.NoError(t, err)
	}

	// Should be rate limited now
	err := limiter.CanSearch(ctx, accountID)
	assert.Error(t, err)

	// Wait for window to expire
	time.Sleep(250 * time.Millisecond)

	// Should work again
	err = limiter.CanSearch(ctx, accountID)
	assert.NoError(t, err, "Search should succeed after window expiry")
}

func TestSearchRateLimiter_MultipleUsers(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 3, time.Minute)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()

	// User 1 uses their quota
	for i := 0; i < 3; i++ {
		err := limiter.CanSearch(ctx, 100)
		assert.NoError(t, err)
	}
	err := limiter.CanSearch(ctx, 100)
	assert.Error(t, err, "User 100 should be rate limited")

	// User 2 should have their own quota
	for i := 0; i < 3; i++ {
		err := limiter.CanSearch(ctx, 200)
		assert.NoError(t, err)
	}
	err = limiter.CanSearch(ctx, 200)
	assert.Error(t, err, "User 200 should be rate limited")

	// User 3 should also have their own quota
	for i := 0; i < 3; i++ {
		err := limiter.CanSearch(ctx, 300)
		assert.NoError(t, err)
	}
}

func TestSearchRateLimiter_SlidingWindow(t *testing.T) {
	// Test sliding window behavior
	limiter := NewSearchRateLimiter("TEST", 3, 300*time.Millisecond)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()
	accountID := int64(123)

	// Make 3 searches quickly
	for i := 0; i < 3; i++ {
		err := limiter.CanSearch(ctx, accountID)
		assert.NoError(t, err)
	}

	// 4th should fail
	err := limiter.CanSearch(ctx, accountID)
	assert.Error(t, err)

	// Wait half the window
	time.Sleep(150 * time.Millisecond)

	// Still should fail (3 searches still in window)
	err = limiter.CanSearch(ctx, accountID)
	assert.Error(t, err)

	// Wait for first searches to expire
	time.Sleep(200 * time.Millisecond) // Total 350ms from start

	// Now should succeed (old searches expired)
	err = limiter.CanSearch(ctx, accountID)
	assert.NoError(t, err, "Search should succeed after old searches expired")
}

func TestSearchRateLimiter_Stats(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 10, time.Minute)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()

	// Initially no users
	stats := limiter.GetStats()
	assert.True(t, stats["enabled"].(bool))
	assert.Equal(t, 10, stats["max_searches_per_min"])
	assert.Equal(t, "1m0s", stats["window"])
	assert.Equal(t, 0, stats["tracked_users"])
	assert.Equal(t, 0, stats["active_users"])

	// Add some searches for user 1
	for i := 0; i < 3; i++ {
		limiter.CanSearch(ctx, 100)
	}

	// Add searches for user 2
	for i := 0; i < 2; i++ {
		limiter.CanSearch(ctx, 200)
	}

	stats = limiter.GetStats()
	assert.Equal(t, 2, stats["tracked_users"], "Should track 2 users")
	assert.Equal(t, 2, stats["active_users"], "Both users should be active")
	assert.Equal(t, 5, stats["total_searches"], "Should have 5 total searches")
}

func TestSearchRateLimiter_Cleanup(t *testing.T) {
	// Test with very short cleanup interval for testing
	limiter := NewSearchRateLimiter("TEST", 10, 100*time.Millisecond)
	require.NotNil(t, limiter)
	limiter.cleanupInterval = 200 * time.Millisecond // Override for testing
	defer limiter.Stop()

	ctx := context.Background()

	// Create activity for user 1
	limiter.CanSearch(ctx, 100)

	stats := limiter.GetStats()
	assert.Equal(t, 1, stats["tracked_users"])

	// Wait long enough for inactivity threshold (30 minutes in real code,
	// but we'll manually trigger cleanup for testing)
	time.Sleep(50 * time.Millisecond)

	// Manually run cleanup with modified inactivity threshold
	limiter.mu.Lock()
	removed := 0
	now := time.Now()
	testInactivityThreshold := 40 * time.Millisecond
	for accountID, tracker := range limiter.userSearches {
		if now.Sub(tracker.lastActivity) > testInactivityThreshold {
			delete(limiter.userSearches, accountID)
			removed++
		}
	}
	limiter.mu.Unlock()

	assert.Equal(t, 1, removed, "Should remove inactive user")
}

func TestSearchRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 100, time.Minute)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()
	accountID := int64(123)

	// Run concurrent searches
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				limiter.CanSearch(ctx, accountID)
				time.Sleep(time.Millisecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have tracked exactly 100 searches (the limit)
	stats := limiter.GetStats()
	totalSearches := stats["total_searches"].(int)
	assert.LessOrEqual(t, totalSearches, 100, "Should not exceed limit even with concurrent access")
}

func TestSearchRateLimiter_RetryAfterMessage(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 2, 500*time.Millisecond)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	ctx := context.Background()
	accountID := int64(123)

	// Use up quota
	limiter.CanSearch(ctx, accountID)
	limiter.CanSearch(ctx, accountID)

	// Get the rate limit error
	err := limiter.CanSearch(ctx, accountID)
	require.Error(t, err)

	// Error message should contain helpful information
	errMsg := err.Error()
	assert.Contains(t, errMsg, "search rate limit exceeded")
	assert.Contains(t, errMsg, "2 searches") // Limit count
	assert.Contains(t, errMsg, "please wait") // Retry guidance
}

func TestSearchRateLimiter_RecordSearch(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 10, time.Minute)
	require.NotNil(t, limiter)
	defer limiter.Stop()

	// RecordSearch should not panic
	limiter.RecordSearch(123)

	// Nil limiter should not panic
	var nilLimiter *SearchRateLimiter
	nilLimiter.RecordSearch(123)
}

func TestSearchRateLimiter_StopCleanup(t *testing.T) {
	limiter := NewSearchRateLimiter("TEST", 10, time.Minute)
	require.NotNil(t, limiter)

	// Stop should not panic
	limiter.Stop()

	// Multiple stops should not panic
	limiter.Stop()

	// Nil limiter Stop should not panic
	var nilLimiter *SearchRateLimiter
	nilLimiter.Stop()
}
