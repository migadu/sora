package server

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestAuthRateLimiter_TwoTierBlocking_SharedIP tests the two-tier blocking system
// protects users on shared IPs (corporate gateways) while still catching distributed attacks
func TestAuthRateLimiter_TwoTierBlocking_SharedIP(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: Fast IP+username blocking (protects shared IPs)
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2: Slow IP-only blocking (catches distributed attacks)
		MaxAttemptsPerIP: 50,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		MaxAttemptsPerUsername: 5,
		UsernameWindowDuration: 30 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	sharedIP := &StringAddr{Addr: "1.2.3.4:12345"} // Corporate gateway

	// Scenario: Corporate network with 3 users behind same IP
	user1 := "alice@example.com"
	user2 := "bob@example.com"
	user3 := "charlie@example.com" // This user will have wrong password

	// User 3 (charlie) tries wrong password 3 times
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, sharedIP, user3, false)
	}

	// User 3 should be blocked (IP+username block)
	err := limiter.CanAttemptAuth(ctx, sharedIP, user3)
	if err == nil {
		t.Error("User 3 should be blocked after 3 failures (Tier 1: IP+username)")
	}

	// User 1 and User 2 should NOT be blocked (different usernames)
	err1 := limiter.CanAttemptAuth(ctx, sharedIP, user1)
	if err1 != nil {
		t.Errorf("User 1 should NOT be blocked (different username): %v", err1)
	}

	err2 := limiter.CanAttemptAuth(ctx, sharedIP, user2)
	if err2 != nil {
		t.Errorf("User 2 should NOT be blocked (different username): %v", err2)
	}

	// User 1 successfully authenticates
	limiter.RecordAuthAttempt(ctx, sharedIP, user1, true)

	// User 1 should still be allowed
	err = limiter.CanAttemptAuth(ctx, sharedIP, user1)
	if err != nil {
		t.Errorf("User 1 should be allowed after successful auth: %v", err)
	}

	t.Logf("✓ Tier 1 (IP+username blocking) protects legitimate users on shared IPs")
}

// TestAuthRateLimiter_TwoTierBlocking_DistributedAttack tests Tier 2 blocking
// catches attacks trying many usernames from same IP
func TestAuthRateLimiter_TwoTierBlocking_DistributedAttack(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: Fast IP+username blocking
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2: Slow IP-only blocking (low threshold for testing)
		MaxAttemptsPerIP: 10, // Low threshold for testing
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		MaxAttemptsPerUsername: 5,
		UsernameWindowDuration: 30 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	attackerIP := &StringAddr{Addr: "6.6.6.6:12345"}

	// Attacker tries 4 different users, 3 attempts each (= 12 total failures)
	users := []string{"user1@example.com", "user2@example.com", "user3@example.com", "user4@example.com"}
	for _, user := range users {
		for i := 0; i < 3; i++ {
			limiter.RecordAuthAttempt(ctx, attackerIP, user, false)
		}
	}

	// Each individual user should be blocked by Tier 1
	for _, user := range users {
		err := limiter.CanAttemptAuth(ctx, attackerIP, user)
		if err == nil {
			t.Errorf("User %s should be blocked by Tier 1 (IP+username)", user)
		}
	}

	// Entire IP should also be blocked by Tier 2 (exceeded 10 total failures)
	// Try with a NEW username that hasn't been tried before
	newUser := "newuser@example.com"
	err := limiter.CanAttemptAuth(ctx, attackerIP, newUser)
	if err == nil {
		t.Error("Entire IP should be blocked by Tier 2 after 12 total failures (threshold: 10)")
	}

	t.Logf("✓ Tier 2 (IP-only blocking) catches distributed attacks trying many users from same IP")
}

// TestAuthRateLimiter_TwoTierBlocking_Cleanup tests cleanup of IP+username entries
func TestAuthRateLimiter_TwoTierBlocking_Cleanup(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: Fast IP+username blocking with short window for testing
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  100 * time.Millisecond, // Short for testing
		IPUsernameWindowDuration: 100 * time.Millisecond,

		// Tier 2: Slow IP-only blocking
		MaxAttemptsPerIP: 50,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		MaxAttemptsPerUsername: 5,
		UsernameWindowDuration: 30 * time.Minute,
		CacheCleanupInterval:   50 * time.Millisecond, // Fast cleanup for testing
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "1.2.3.4:12345"}
	username := "test@example.com"

	// Trigger IP+username block
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, ip, username, false)
	}

	// Should be blocked
	err := limiter.CanAttemptAuth(ctx, ip, username)
	if err == nil {
		t.Error("Should be blocked initially")
	}

	// Wait for block to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again (block expired)
	err = limiter.CanAttemptAuth(ctx, ip, username)
	if err != nil {
		t.Errorf("Should be allowed after block expires: %v", err)
	}

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Check stats to verify cleanup happened
	stats := limiter.GetStats(ctx, 1*time.Minute)
	blockedCount, _ := stats["blocked_ip_usernames"].(int)
	if blockedCount != 0 {
		t.Errorf("Cleanup should have removed expired blocks, got %d blocked entries", blockedCount)
	}

	t.Logf("✓ IP+username blocks are properly cleaned up after expiration")
}

// TestAuthRateLimiter_TwoTierBlocking_SuccessfulAuthClears tests that successful
// authentication clears both Tier 1 and Tier 2 tracking
func TestAuthRateLimiter_TwoTierBlocking_SuccessfulAuthClears(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2
		MaxAttemptsPerIP: 10,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		MaxAttemptsPerUsername: 5,
		UsernameWindowDuration: 30 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "1.2.3.4:12345"}
	username := "test@example.com"

	// Record 2 failures (not blocked yet)
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	limiter.RecordAuthAttempt(ctx, ip, username, false)

	// Check stats - should have tracking entries
	stats := limiter.GetStats(ctx, 1*time.Minute)
	blockedIPUsernameCount := stats["blocked_ip_usernames"].(int)
	trackedIPs := stats["tracked_ips"].(int)

	if blockedIPUsernameCount == 0 {
		t.Error("Should have IP+username tracking entry")
	}
	if trackedIPs == 0 {
		t.Error("Should have IP tracking entry")
	}

	// Successful authentication
	limiter.RecordAuthAttempt(ctx, ip, username, true)

	// Check stats - tracking should be cleared
	stats = limiter.GetStats(ctx, 1*time.Minute)
	blockedIPUsernameCount = stats["blocked_ip_usernames"].(int)
	trackedIPs = stats["tracked_ips"].(int)

	if blockedIPUsernameCount != 0 {
		t.Errorf("IP+username tracking should be cleared after success, got %d", blockedIPUsernameCount)
	}
	if trackedIPs != 0 {
		t.Errorf("IP tracking should be cleared after success, got %d", trackedIPs)
	}

	t.Logf("✓ Successful authentication clears both Tier 1 and Tier 2 tracking")
}

// TestAuthRateLimiter_TwoTierBlocking_Stats tests statistics collection for two-tier system
func TestAuthRateLimiter_TwoTierBlocking_Stats(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		MaxAttemptsPerIP: 10,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		MaxAttemptsPerUsername: 5,
		UsernameWindowDuration: 30 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Create blocks of different types
	ip1 := &StringAddr{Addr: "1.1.1.1:12345"}
	ip2 := &StringAddr{Addr: "2.2.2.2:12345"}

	// Tier 1: Block IP+username
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, ip1, "user1@example.com", false)
	}

	// Tier 2: Accumulate failures for IP-only block (but don't reach threshold)
	for i := 0; i < 5; i++ {
		limiter.RecordAuthAttempt(ctx, ip2, "user2@example.com", false)
	}

	stats := limiter.GetStats(ctx, 1*time.Minute)

	// Verify config is reported correctly
	configStats := stats["config"].(map[string]any)
	if configStats["max_attempts_per_ip_username"].(int) != 3 {
		t.Error("Config should show max_attempts_per_ip_username = 3")
	}
	if configStats["max_attempts_per_ip"].(int) != 10 {
		t.Error("Config should show max_attempts_per_ip = 10")
	}

	// Verify counts
	blockedIPUsernameCount := stats["blocked_ip_usernames"].(int)
	if blockedIPUsernameCount == 0 {
		t.Error("Should have at least one IP+username block")
	}

	trackedIPs := stats["tracked_ips"].(int)
	if trackedIPs == 0 {
		t.Error("Should have tracked IPs")
	}

	t.Logf("✓ Stats correctly report two-tier blocking configuration and counts")
	t.Logf("  - Blocked IP+usernames: %d", blockedIPUsernameCount)
	t.Logf("  - Tracked IPs: %d", trackedIPs)
}
