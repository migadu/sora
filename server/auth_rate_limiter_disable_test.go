package server

import (
	"context"
	"testing"
	"time"
)

// TestAuthRateLimiter_DisableByZero tests that setting max attempts to 0 disables blocking
func TestAuthRateLimiter_DisableByZero(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0, // Disable Tier 1
		MaxAttemptsPerIP:         0, // Disable Tier 2
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		IPBlockDuration:          5 * time.Minute,
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      2,
		InitialDelay:             200 * time.Millisecond,
		MaxDelay:                 5 * time.Second,
		DelayMultiplier:          2.0,
		CacheCleanupInterval:     1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("test", "", "", config)
	defer limiter.Stop()

	ctx := context.Background()
	testAddr := &StringAddr{Addr: "1.2.3.4:12345"}

	// Attempt 100 failed authentications - should never block
	for i := 0; i < 100; i++ {
		// Check if can attempt (should always be allowed)
		err := limiter.CanAttemptAuth(ctx, testAddr, "user@example.com")
		if err != nil {
			t.Fatalf("Attempt %d: Authentication should be allowed when both tiers disabled, but got: %v", i+1, err)
		}

		// Record failure
		limiter.RecordAuthAttempt(ctx, testAddr, "user@example.com", false)
	}

	// Verify no blocking occurred
	stats := limiter.GetStats(ctx, 5*time.Minute)
	blockedIPs := stats["blocked_ips"].(int)
	blockedIPUsernames := stats["blocked_ip_usernames"].(int)

	if blockedIPs > 0 {
		t.Errorf("Expected 0 blocked IPs when MaxAttemptsPerIP=0, got %d", blockedIPs)
	}
	if blockedIPUsernames > 0 {
		t.Errorf("Expected 0 blocked IP+usernames when MaxAttemptsPerIPUsername=0, got %d", blockedIPUsernames)
	}

	t.Logf("✓ Both blocking tiers disabled by setting max_attempts to 0")
}

// TestAuthRateLimiter_DisableTier1Only tests disabling only Tier 1
func TestAuthRateLimiter_DisableTier1Only(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0, // Disable Tier 1
		MaxAttemptsPerIP:         3, // Enable Tier 2
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		IPBlockDuration:          5 * time.Minute,
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      2,
		InitialDelay:             200 * time.Millisecond,
		MaxDelay:                 5 * time.Second,
		DelayMultiplier:          2.0,
		CacheCleanupInterval:     1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("test", "", "", config)
	defer limiter.Stop()

	ctx := context.Background()
	testAddr := &StringAddr{Addr: "1.2.3.4:12345"}

	// Attempt 3 failed authentications - should trigger Tier 2 but not Tier 1
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, testAddr, "user@example.com", false)
	}

	// Fourth attempt should be blocked by Tier 2 (IP-only)
	err := limiter.CanAttemptAuth(ctx, testAddr, "user@example.com")
	if err == nil {
		t.Fatal("Expected IP blocking (Tier 2) to occur, but authentication was allowed")
	}

	// Verify stats
	stats := limiter.GetStats(ctx, 5*time.Minute)
	blockedIPs := stats["blocked_ips"].(int)
	blockedIPUsernames := stats["blocked_ip_usernames"].(int)

	if blockedIPs != 1 {
		t.Errorf("Expected 1 blocked IP, got %d", blockedIPs)
	}
	if blockedIPUsernames > 0 {
		t.Errorf("Expected 0 blocked IP+usernames when Tier 1 disabled, got %d", blockedIPUsernames)
	}

	t.Logf("✓ Tier 1 disabled, Tier 2 works correctly")
}

// TestAuthRateLimiter_DisableTier2Only tests disabling only Tier 2
func TestAuthRateLimiter_DisableTier2Only(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3, // Enable Tier 1
		MaxAttemptsPerIP:         0, // Disable Tier 2
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		IPBlockDuration:          5 * time.Minute,
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      2,
		InitialDelay:             200 * time.Millisecond,
		MaxDelay:                 5 * time.Second,
		DelayMultiplier:          2.0,
		CacheCleanupInterval:     1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("test", "", "", config)
	defer limiter.Stop()

	ctx := context.Background()
	testAddr := &StringAddr{Addr: "1.2.3.4:12345"}

	// Attempt 3 failed authentications for same IP+username - should trigger Tier 1
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, testAddr, "user@example.com", false)
	}

	// Fourth attempt should be blocked by Tier 1 (IP+username)
	err := limiter.CanAttemptAuth(ctx, testAddr, "user@example.com")
	if err == nil {
		t.Fatal("Expected IP+username blocking (Tier 1) to occur, but authentication was allowed")
	}

	// Different user from same IP should still be allowed (Tier 2 disabled)
	err = limiter.CanAttemptAuth(ctx, testAddr, "another@example.com")
	if err != nil {
		t.Errorf("Different user should be allowed when Tier 2 disabled, but got: %v", err)
	}

	// Verify stats
	stats := limiter.GetStats(ctx, 5*time.Minute)
	blockedIPs := stats["blocked_ips"].(int)
	blockedIPUsernames := stats["blocked_ip_usernames"].(int)

	if blockedIPs > 0 {
		t.Errorf("Expected 0 blocked IPs when Tier 2 disabled, got %d", blockedIPs)
	}
	if blockedIPUsernames != 1 {
		t.Errorf("Expected 1 blocked IP+username, got %d", blockedIPUsernames)
	}

	t.Logf("✓ Tier 2 disabled, Tier 1 works correctly")
}
