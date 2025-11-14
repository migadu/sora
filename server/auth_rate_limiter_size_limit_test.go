package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestIPUsernameSizeLimit tests that max_ip_username_entries enforces size limit with LRU eviction
func TestIPUsernameSizeLimit(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 10 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour, // Don't cleanup during test
		MaxIPUsernameEntries:     5,             // Small limit for testing
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	ctx := context.Background()

	// Add 5 entries (at limit)
	for i := 1; i <= 5; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1234}

		// First failure - creates tracking entry
		limiter.RecordAuthAttempt(ctx, addr, username, false)
	}

	// Verify we have exactly 5 entries
	limiter.ipUsernameMu.RLock()
	entriesCount := len(limiter.blockedIPUsernames)
	limiter.ipUsernameMu.RUnlock()

	if entriesCount != 5 {
		t.Fatalf("Expected 5 entries, got %d", entriesCount)
	}

	// Add 6th entry - should evict oldest (user1)
	time.Sleep(10 * time.Millisecond) // Ensure FirstFailure times are different
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1234}
	limiter.RecordAuthAttempt(ctx, addr, "user6@example.com", false)

	// Still should have 5 entries
	limiter.ipUsernameMu.RLock()
	entriesCount = len(limiter.blockedIPUsernames)
	user1Key := "192.168.1.100|user1@example.com"
	user6Key := "192.168.1.100|user6@example.com"
	_, user1Exists := limiter.blockedIPUsernames[user1Key]
	_, user6Exists := limiter.blockedIPUsernames[user6Key]
	limiter.ipUsernameMu.RUnlock()

	if entriesCount != 5 {
		t.Errorf("Expected 5 entries after eviction, got %d", entriesCount)
	}

	if user1Exists {
		t.Errorf("user1 should have been evicted (oldest entry)")
	}

	if !user6Exists {
		t.Errorf("user6 should exist (newest entry)")
	}

	// Verify user2-user5 still exist
	limiter.ipUsernameMu.RLock()
	for i := 2; i <= 5; i++ {
		key := fmt.Sprintf("192.168.1.100|user%d@example.com", i)
		if _, exists := limiter.blockedIPUsernames[key]; !exists {
			t.Errorf("user%d should still exist", i)
		}
	}
	limiter.ipUsernameMu.RUnlock()
}

// TestIPSizeLimit tests that max_ip_entries enforces size limit with LRU eviction
func TestIPSizeLimit(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     10,
		IPBlockDuration:      30 * time.Minute,
		IPWindowDuration:     30 * time.Minute,
		CacheCleanupInterval: 1 * time.Hour, // Don't cleanup during test
		MaxIPEntries:         3,             // Small limit for testing
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	ctx := context.Background()

	// Add 3 IPs (at limit)
	for i := 1; i <= 3; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}
		limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
		time.Sleep(10 * time.Millisecond) // Ensure FirstFailure times are different
	}

	// Verify we have exactly 3 entries
	limiter.ipMu.RLock()
	entriesCount := len(limiter.ipFailureCounts)
	limiter.ipMu.RUnlock()

	if entriesCount != 3 {
		t.Fatalf("Expected 3 IP entries, got %d", entriesCount)
	}

	// Add 4th IP - should evict oldest (192.168.1.1)
	time.Sleep(10 * time.Millisecond)
	addr4 := &net.TCPAddr{IP: net.ParseIP("192.168.1.4"), Port: 1234}
	limiter.RecordAuthAttempt(ctx, addr4, "user@example.com", false)

	// Still should have 3 entries
	limiter.ipMu.RLock()
	entriesCount = len(limiter.ipFailureCounts)
	_, ip1Exists := limiter.ipFailureCounts["192.168.1.1"]
	_, ip4Exists := limiter.ipFailureCounts["192.168.1.4"]
	limiter.ipMu.RUnlock()

	if entriesCount != 3 {
		t.Errorf("Expected 3 entries after eviction, got %d", entriesCount)
	}

	if ip1Exists {
		t.Errorf("192.168.1.1 should have been evicted (oldest entry)")
	}

	if !ip4Exists {
		t.Errorf("192.168.1.4 should exist (newest entry)")
	}

	// Verify 192.168.1.2 and 192.168.1.3 still exist
	limiter.ipMu.RLock()
	if _, exists := limiter.ipFailureCounts["192.168.1.2"]; !exists {
		t.Errorf("192.168.1.2 should still exist")
	}
	if _, exists := limiter.ipFailureCounts["192.168.1.3"]; !exists {
		t.Errorf("192.168.1.3 should still exist")
	}
	limiter.ipMu.RUnlock()
}

// TestUsernameSizeLimit tests that max_username_entries enforces size limit with LRU eviction
func TestUsernameSizeLimit(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 10,
		UsernameWindowDuration: 60 * time.Minute,
		CacheCleanupInterval:   1 * time.Hour, // Don't cleanup during test
		MaxUsernameEntries:     4,             // Small limit for testing
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	ctx := context.Background()

	// Add 4 usernames (at limit) from different IPs
	for i := 1; i <= 4; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		ip := fmt.Sprintf("192.168.1.%d", i)
		addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}
		limiter.RecordAuthAttempt(ctx, addr, username, false)
		time.Sleep(10 * time.Millisecond) // Ensure FirstFailure times are different
	}

	// Verify we have exactly 4 entries
	limiter.usernameMu.RLock()
	entriesCount := len(limiter.usernameFailureCounts)
	limiter.usernameMu.RUnlock()

	if entriesCount != 4 {
		t.Fatalf("Expected 4 username entries, got %d", entriesCount)
	}

	// Add 5th username - should evict oldest (user1@example.com)
	time.Sleep(10 * time.Millisecond)
	addr5 := &net.TCPAddr{IP: net.ParseIP("192.168.1.5"), Port: 1234}
	limiter.RecordAuthAttempt(ctx, addr5, "user5@example.com", false)

	// Still should have 4 entries
	limiter.usernameMu.RLock()
	entriesCount = len(limiter.usernameFailureCounts)
	_, user1Exists := limiter.usernameFailureCounts["user1@example.com"]
	_, user5Exists := limiter.usernameFailureCounts["user5@example.com"]
	limiter.usernameMu.RUnlock()

	if entriesCount != 4 {
		t.Errorf("Expected 4 entries after eviction, got %d", entriesCount)
	}

	if user1Exists {
		t.Errorf("user1@example.com should have been evicted (oldest entry)")
	}

	if !user5Exists {
		t.Errorf("user5@example.com should exist (newest entry)")
	}

	// Verify user2-user4 still exist
	limiter.usernameMu.RLock()
	for i := 2; i <= 4; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		if _, exists := limiter.usernameFailureCounts[username]; !exists {
			t.Errorf("%s should still exist", username)
		}
	}
	limiter.usernameMu.RUnlock()
}

// TestSizeLimitDisabled tests that setting limits to 0 disables size-based eviction
func TestSizeLimitDisabled(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 10 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour,
		MaxIPUsernameEntries:     0, // Disabled - unlimited
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1234}

	// Add 100 entries (should not be limited)
	for i := 1; i <= 100; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		limiter.RecordAuthAttempt(ctx, addr, username, false)
	}

	// Verify we have all 100 entries
	limiter.ipUsernameMu.RLock()
	entriesCount := len(limiter.blockedIPUsernames)
	limiter.ipUsernameMu.RUnlock()

	if entriesCount != 100 {
		t.Errorf("Expected 100 entries (unlimited), got %d", entriesCount)
	}
}

// TestEvictionOrderByFirstFailure tests that eviction uses FirstFailure time (oldest first)
func TestEvictionOrderByFirstFailure(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 10 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour,
		MaxIPUsernameEntries:     3,
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1234}

	// Add entries with explicit timing
	times := []time.Time{
		time.Now().Add(-10 * time.Minute), // oldest
		time.Now().Add(-5 * time.Minute),  // middle
		time.Now().Add(-1 * time.Minute),  // newest
	}

	// Manually create entries with specific FirstFailure times
	limiter.ipUsernameMu.Lock()
	for i, t := range times {
		username := fmt.Sprintf("user%d@example.com", i+1)
		key := fmt.Sprintf("192.168.1.100|%s", username)
		limiter.blockedIPUsernames[key] = &BlockedIPUsernameInfo{
			FailureCount: 1,
			FirstFailure: t,
			LastFailure:  t,
			Protocol:     "test",
			IP:           "192.168.1.100",
			Username:     username,
		}
	}
	limiter.ipUsernameMu.Unlock()

	// Add 4th entry - should evict user1 (oldest FirstFailure)
	time.Sleep(10 * time.Millisecond)
	limiter.RecordAuthAttempt(ctx, addr, "user4@example.com", false)

	// Verify user1 was evicted, others remain
	limiter.ipUsernameMu.RLock()
	_, user1Exists := limiter.blockedIPUsernames["192.168.1.100|user1@example.com"]
	_, user2Exists := limiter.blockedIPUsernames["192.168.1.100|user2@example.com"]
	_, user3Exists := limiter.blockedIPUsernames["192.168.1.100|user3@example.com"]
	_, user4Exists := limiter.blockedIPUsernames["192.168.1.100|user4@example.com"]
	entriesCount := len(limiter.blockedIPUsernames)
	limiter.ipUsernameMu.RUnlock()

	if entriesCount != 3 {
		t.Errorf("Expected 3 entries, got %d", entriesCount)
	}

	if user1Exists {
		t.Errorf("user1 should have been evicted (had oldest FirstFailure time)")
	}
	if !user2Exists {
		t.Errorf("user2 should still exist")
	}
	if !user3Exists {
		t.Errorf("user3 should still exist")
	}
	if !user4Exists {
		t.Errorf("user4 should exist (newest entry)")
	}
}
