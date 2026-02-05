package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestAuthRateLimiterBasicIPBlocking tests that IPs are blocked after exceeding max_attempts_per_ip (Tier 2)
func TestAuthRateLimiterBasicIPBlocking(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     3, // Tier 2: Block after 3 failures
		IPBlockDuration:      5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.100:12345"}

	// Record 2 failures - should not block yet
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)

	err := limiter.CanAttemptAuth(ctx, addr, "user@example.com")
	if err != nil {
		t.Errorf("Should not block after 2 failures (threshold 3): %v", err)
	}

	// Record 3rd failure - should trigger Tier 2 IP block
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)

	err = limiter.CanAttemptAuth(ctx, addr, "user@example.com")
	if err == nil {
		t.Error("Should block IP after 3 failures (threshold 3)")
	}

	// Different IP should still work
	addr2 := &StringAddr{Addr: "192.168.1.101:12345"}
	err = limiter.CanAttemptAuth(ctx, addr2, "user@example.com")
	if err != nil {
		t.Errorf("Different IP should not be blocked: %v", err)
	}
}

// TestAuthRateLimiterProgressiveDelays tests that delays increase exponentially
func TestAuthRateLimiterProgressiveDelays(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		DelayStartThreshold:  2, // Start delays after 2 failures
		InitialDelay:         100 * time.Millisecond,
		MaxDelay:             1 * time.Second,
		DelayMultiplier:      2.0, // Double each time
		MaxAttemptsPerIP:     10,  // High threshold so we don't block
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.200:12345"}

	// Record first failure - no delay yet
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay1 := limiter.GetAuthenticationDelay(addr)
	if delay1 != 0 {
		t.Errorf("First failure should have no delay, got %v", delay1)
	}

	// Record second failure - still no delay (threshold is 2)
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay2 := limiter.GetAuthenticationDelay(addr)
	if delay2 != 100*time.Millisecond {
		t.Errorf("After 2 failures should have initial delay (100ms), got %v", delay2)
	}

	// Record third failure - delay should double
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay3 := limiter.GetAuthenticationDelay(addr)
	if delay3 != 200*time.Millisecond {
		t.Errorf("After 3 failures should have 200ms delay, got %v", delay3)
	}

	// Record fourth failure - delay should double again
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay4 := limiter.GetAuthenticationDelay(addr)
	if delay4 != 400*time.Millisecond {
		t.Errorf("After 4 failures should have 400ms delay, got %v", delay4)
	}

	// Record fifth failure - delay should double again
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay5 := limiter.GetAuthenticationDelay(addr)
	if delay5 != 800*time.Millisecond {
		t.Errorf("After 5 failures should have 800ms delay, got %v", delay5)
	}
}

// TestAuthRateLimiterUsernameTracking tests username failure tracking (for statistics only, not blocking)
func TestAuthRateLimiterUsernameTracking(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 3, // Track failures but don't block
		UsernameWindowDuration: 30 * time.Minute,
		MaxAttemptsPerIP:       10, // High threshold so IP doesn't block first
		IPWindowDuration:       15 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	username := "target@example.com"

	// Record failures from different IPs
	addr1 := &StringAddr{Addr: "192.168.1.100:12345"}
	addr2 := &StringAddr{Addr: "192.168.1.101:12345"}
	addr3 := &StringAddr{Addr: "192.168.1.102:12345"}

	limiter.RecordAuthAttempt(ctx, addr1, username, false)
	limiter.RecordAuthAttempt(ctx, addr2, username, false)
	limiter.RecordAuthAttempt(ctx, addr3, username, false)

	// Username tracking is for statistics only - should NOT block authentication
	// This prevents DoS attacks where attacker locks out legitimate users
	err := limiter.CanAttemptAuth(ctx, addr1, username)
	if err != nil {
		t.Errorf("Should not block based on username failures (prevents DoS): %v", err)
	}

	// Should allow from any IP (username blocking removed to prevent DoS)
	err = limiter.CanAttemptAuth(ctx, addr3, username)
	if err != nil {
		t.Errorf("Should not block username from any IP (prevents DoS): %v", err)
	}

	// Verify username failure count is tracked (for monitoring/statistics)
	count := limiter.getUsernameFailureCount(username)
	if count != 3 {
		t.Errorf("Username failure count should be 3, got %d", count)
	}

	// Successful auth should clear username failures
	limiter.RecordAuthAttempt(ctx, addr1, username, true)
	count = limiter.getUsernameFailureCount(username)
	if count != 0 {
		t.Errorf("Username failure count should be 0 after success, got %d", count)
	}
}

// TestAuthRateLimiterSuccessResetsFailures tests that successful auth clears failures
func TestAuthRateLimiterSuccessResetsFailures(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerIP:       3,
		IPBlockDuration:        5 * time.Minute,
		MaxAttemptsPerUsername: 5,
		IPWindowDuration:       15 * time.Minute,
		UsernameWindowDuration: 30 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.100:12345"}
	username := "user@example.com"

	// Record 2 failures
	limiter.RecordAuthAttempt(ctx, addr, username, false)
	limiter.RecordAuthAttempt(ctx, addr, username, false)

	// Record success - should clear failures
	limiter.RecordAuthAttempt(ctx, addr, username, true)

	// Should not have any delays or blocks now
	start := time.Now()
	err := limiter.CanAttemptAuth(ctx, addr, username)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("Should not block after success: %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Should have no delay after success, got %v", elapsed)
	}

	// Verify username failures were also cleared
	stats := limiter.GetStats(ctx, 30*time.Minute)
	configMap := stats["config"].(map[string]any)
	if configMap["max_attempts_per_username"].(int) > 0 {
		// Username tracking is enabled, check count
		tracked := stats["tracked_usernames"].(int)
		if tracked > 0 {
			t.Errorf("Username failures should be cleared after success, got %d tracked", tracked)
		}
	}
}

// TestAuthRateLimiterDisabled tests that disabled limiter allows all attempts
func TestAuthRateLimiterDisabled(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:          false, // Disabled
		MaxAttemptsPerIP: 1,     // Would block after 1 failure if enabled
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.100:12345"}

	// Record many failures
	for i := 0; i < 10; i++ {
		limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	}

	// Should still allow attempts since disabled
	err := limiter.CanAttemptAuth(ctx, addr, "user@example.com")
	if err != nil {
		t.Errorf("Disabled limiter should allow all attempts: %v", err)
	}
}

// TestAuthRateLimiterMaxDelayCapEnforced tests that delays don't exceed max_delay
func TestAuthRateLimiterMaxDelayCapEnforced(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		DelayStartThreshold:  1,
		InitialDelay:         100 * time.Millisecond,
		MaxDelay:             300 * time.Millisecond, // Cap at 300ms
		DelayMultiplier:      2.0,
		MaxAttemptsPerIP:     10,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.100:12345"}

	// Record failures and check delay increases then caps
	// After 1st: 100ms
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay1 := limiter.GetAuthenticationDelay(addr)
	if delay1 != 100*time.Millisecond {
		t.Errorf("After 1 failure should have 100ms delay, got %v", delay1)
	}

	// After 2nd: 200ms
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay2 := limiter.GetAuthenticationDelay(addr)
	if delay2 != 200*time.Millisecond {
		t.Errorf("After 2 failures should have 200ms delay, got %v", delay2)
	}

	// After 3rd: would be 400ms but capped to 300ms
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay3 := limiter.GetAuthenticationDelay(addr)
	if delay3 != 300*time.Millisecond {
		t.Errorf("After 3 failures should be capped at 300ms, got %v", delay3)
	}

	// After 4th: would be 600ms but still capped to 300ms
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	delay4 := limiter.GetAuthenticationDelay(addr)
	if delay4 != 300*time.Millisecond {
		t.Errorf("After 4 failures should still be capped at 300ms, got %v", delay4)
	}
}

// TestAuthRateLimiterGetStats tests that stats are returned correctly
func TestAuthRateLimiterGetStats(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerIP:       3,
		IPBlockDuration:        5 * time.Minute,
		MaxAttemptsPerUsername: 5,
		IPWindowDuration:       15 * time.Minute,
		UsernameWindowDuration: 30 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr1 := &StringAddr{Addr: "192.168.1.100:12345"}
	addr2 := &StringAddr{Addr: "192.168.1.101:12345"}

	// Record some failures
	limiter.RecordAuthAttempt(ctx, addr1, "user1@example.com", false)
	limiter.RecordAuthAttempt(ctx, addr1, "user1@example.com", false)
	limiter.RecordAuthAttempt(ctx, addr2, "user2@example.com", false)

	// Block one IP
	limiter.RecordAuthAttempt(ctx, addr1, "user1@example.com", false)

	stats := limiter.GetStats(ctx, 30*time.Minute)

	// Check required fields
	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Error("Stats should show enabled=true")
	}

	if blockedIPs, ok := stats["blocked_ips"].(int); !ok || blockedIPs != 1 {
		t.Errorf("Stats should show 1 blocked IP, got %v", stats["blocked_ips"])
	}

	if trackedIPs, ok := stats["tracked_ips"].(int); !ok || trackedIPs < 2 {
		t.Errorf("Stats should show at least 2 tracked IPs, got %v", stats["tracked_ips"])
	}

	if trackedUsernames, ok := stats["tracked_usernames"].(int); !ok || trackedUsernames < 2 {
		t.Errorf("Stats should show at least 2 tracked usernames, got %v", stats["tracked_usernames"])
	}

	// Check config is included
	if _, ok := stats["config"]; !ok {
		t.Error("Stats should include config section")
	}
}

// TestAuthRateLimiterCleanupExpiredEntries tests that cleanup removes old entries
func TestAuthRateLimiterCleanupExpiredEntries(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     3,
		IPBlockDuration:      100 * time.Millisecond, // Very short for testing
		IPWindowDuration:     100 * time.Millisecond,
		CacheCleanupInterval: 50 * time.Millisecond, // Frequent cleanup
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	addr := &StringAddr{Addr: "192.168.1.100:12345"}

	// Block an IP
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	}

	// Verify it's blocked
	err := limiter.CanAttemptAuth(ctx, addr, "user@example.com")
	if err == nil {
		t.Error("IP should be blocked")
	}

	// Wait for block to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Should not be blocked anymore
	err = limiter.CanAttemptAuth(ctx, addr, "user@example.com")
	if err != nil {
		t.Errorf("IP should not be blocked after expiry: %v", err)
	}

	// Stats should show 0 blocked IPs after cleanup
	stats := limiter.GetStats(ctx, 30*time.Minute)
	if blockedIPs, ok := stats["blocked_ips"].(int); ok && blockedIPs > 0 {
		t.Errorf("Stats should show 0 blocked IPs after cleanup, got %d", blockedIPs)
	}
}

// TestAuthRateLimiterUsernameCleanup tests that username failure tracking is cleaned up
func TestAuthRateLimiterUsernameCleanup(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 5,
		MaxAttemptsPerIP:       10,
		IPWindowDuration:       100 * time.Millisecond,
		UsernameWindowDuration: 100 * time.Millisecond, // Very short for testing
		CacheCleanupInterval:   50 * time.Millisecond,  // Frequent cleanup
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Record failures for multiple usernames
	for i := 0; i < 10; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		addr := &StringAddr{Addr: fmt.Sprintf("192.168.1.%d:12345", i+1)}
		limiter.RecordAuthAttempt(ctx, addr, username, false)
	}

	// Verify usernames are tracked
	stats := limiter.GetStats(ctx, 30*time.Minute)
	trackedUsernames, ok := stats["tracked_usernames"].(int)
	if !ok {
		t.Fatal("tracked_usernames not found in stats")
	}
	if trackedUsernames != 10 {
		t.Errorf("Expected 10 tracked usernames, got %d", trackedUsernames)
	}
	t.Logf("Initial tracked usernames: %d", trackedUsernames)

	// Wait for username window to expire and cleanup to run
	// UsernameWindowDuration=100ms, cleanup every 50ms
	time.Sleep(200 * time.Millisecond)

	// Verify usernames were cleaned up
	stats = limiter.GetStats(ctx, 30*time.Minute)
	trackedUsernamesAfter, ok := stats["tracked_usernames"].(int)
	if !ok {
		t.Fatal("tracked_usernames not found in stats")
	}
	if trackedUsernamesAfter != 0 {
		t.Errorf("Expected 0 tracked usernames after cleanup, got %d - USERNAME TRACKING NOT CLEANED UP!", trackedUsernamesAfter)
	}
	t.Logf("Tracked usernames after cleanup: %d", trackedUsernamesAfter)
}

// TestAuthRateLimiterCompleteMemoryCleanup tests that ALL tracking maps are cleaned up (no memory leak)
func TestAuthRateLimiterCompleteMemoryCleanup(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 5,
		MaxAttemptsPerIP:       3, // Block after 3 failures
		IPBlockDuration:        100 * time.Millisecond,
		DelayStartThreshold:    2, // Start delays after 2 failures
		InitialDelay:           10 * time.Millisecond,
		DelayMultiplier:        2.0,
		MaxDelay:               100 * time.Millisecond,
		IPWindowDuration:       100 * time.Millisecond,
		UsernameWindowDuration: 100 * time.Millisecond,
		CacheCleanupInterval:   50 * time.Millisecond, // Cleanup every 50ms
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Scenario 1: Create IP blocks (blockedIPs map)
	// Record 3 failures to trigger fast block
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("10.0.1.%d:12345", i)
		addr := &StringAddr{Addr: ip}
		username := fmt.Sprintf("user%d@example.com", i)

		// 3 failures = block
		for j := 0; j < 3; j++ {
			limiter.RecordAuthAttempt(ctx, addr, username, false)
		}
	}

	// Scenario 2: Create IP failure tracking without blocks (ipFailureCounts map)
	// Record 2 failures (below block threshold) to track failures only
	for i := 10; i < 20; i++ {
		ip := fmt.Sprintf("10.0.2.%d:12345", i)
		addr := &StringAddr{Addr: ip}
		username := fmt.Sprintf("user%d@example.com", i)

		// 2 failures = tracked but not blocked
		for j := 0; j < 2; j++ {
			limiter.RecordAuthAttempt(ctx, addr, username, false)
		}
	}

	// Scenario 3: Create username tracking (usernameFailureCounts map)
	// Already created above, but add more
	for i := 30; i < 40; i++ {
		ip := fmt.Sprintf("10.0.3.%d:12345", i)
		addr := &StringAddr{Addr: ip}
		username := fmt.Sprintf("user%d@example.com", i)

		limiter.RecordAuthAttempt(ctx, addr, username, false)
	}

	// Verify all three maps have entries
	stats := limiter.GetStats(ctx, 30*time.Minute)

	blockedIPs, _ := stats["blocked_ips"].(int)
	trackedIPs, _ := stats["tracked_ips"].(int)
	trackedUsernames, _ := stats["tracked_usernames"].(int)

	t.Logf("Before cleanup: blocked_ips=%d, tracked_ips=%d, tracked_usernames=%d",
		blockedIPs, trackedIPs, trackedUsernames)

	if blockedIPs == 0 {
		t.Error("Expected some blocked IPs before cleanup")
	}
	if trackedIPs == 0 {
		t.Error("Expected some tracked IPs before cleanup")
	}
	if trackedUsernames == 0 {
		t.Error("Expected some tracked usernames before cleanup")
	}

	// Wait for ALL entries to expire and cleanup to run
	// Max window is 100ms, cleanup runs every 50ms
	// Wait 300ms to ensure multiple cleanup cycles
	time.Sleep(300 * time.Millisecond)

	// Verify ALL maps are cleaned up (no memory leak)
	stats = limiter.GetStats(ctx, 30*time.Minute)

	blockedIPsAfter, _ := stats["blocked_ips"].(int)
	trackedIPsAfter, _ := stats["tracked_ips"].(int)
	trackedUsernamesAfter, _ := stats["tracked_usernames"].(int)

	t.Logf("After cleanup: blocked_ips=%d, tracked_ips=%d, tracked_usernames=%d",
		blockedIPsAfter, trackedIPsAfter, trackedUsernamesAfter)

	if blockedIPsAfter != 0 {
		t.Errorf("MEMORY LEAK: Expected 0 blocked IPs after cleanup, got %d", blockedIPsAfter)
	}
	if trackedIPsAfter != 0 {
		t.Errorf("MEMORY LEAK: Expected 0 tracked IPs after cleanup, got %d", trackedIPsAfter)
	}
	if trackedUsernamesAfter != 0 {
		t.Errorf("MEMORY LEAK: Expected 0 tracked usernames after cleanup, got %d", trackedUsernamesAfter)
	}
}

// TestAuthRateLimiterContinuousCleanup tests that cleanup prevents unbounded growth
func TestAuthRateLimiterContinuousCleanup(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 10,
		MaxAttemptsPerIP:       5,
		IPBlockDuration:        200 * time.Millisecond,
		IPWindowDuration:       200 * time.Millisecond,
		UsernameWindowDuration: 200 * time.Millisecond,
		CacheCleanupInterval:   50 * time.Millisecond, // Cleanup every 50ms
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Simulate continuous failed login attempts over 1 second
	// This simulates high attack traffic
	done := make(chan bool)
	go func() {
		for i := 0; i < 200; i++ {
			ip := fmt.Sprintf("10.0.%d.%d:12345", i/256, i%256)
			addr := &StringAddr{Addr: ip}
			username := fmt.Sprintf("user%d@example.com", i%50) // 50 unique usernames

			limiter.RecordAuthAttempt(ctx, addr, username, false)
			time.Sleep(5 * time.Millisecond)
		}
		done <- true
	}()

	<-done

	// Wait for cleanup to stabilize
	time.Sleep(300 * time.Millisecond)

	// Verify maps didn't grow unbounded
	stats := limiter.GetStats(ctx, 30*time.Minute)

	blockedIPs, _ := stats["blocked_ips"].(int)
	trackedIPs, _ := stats["tracked_ips"].(int)
	trackedUsernames, _ := stats["tracked_usernames"].(int)

	t.Logf("Final state: blocked_ips=%d, tracked_ips=%d, tracked_usernames=%d",
		blockedIPs, trackedIPs, trackedUsernames)

	// With 200ms TTL and continuous cleanup, should not have all 200 IPs
	// Should be much smaller (most expired and cleaned up)
	if trackedIPs > 100 {
		t.Errorf("MEMORY LEAK: Too many tracked IPs (%d), cleanup not working efficiently", trackedIPs)
	}
	if trackedUsernames > 50 {
		t.Errorf("MEMORY LEAK: Too many tracked usernames (%d), cleanup not working efficiently", trackedUsernames)
	}
	if blockedIPs > 100 {
		t.Errorf("MEMORY LEAK: Too many blocked IPs (%d), cleanup not working efficiently", blockedIPs)
	}
}

// TestAuthRateLimiterConcurrentAccess tests thread safety
func TestAuthRateLimiterConcurrentAccess(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     10,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Run concurrent auth attempts from multiple goroutines
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			addr := &StringAddr{Addr: net.JoinHostPort("192.168.1."+string(rune(100+id)), "12345")}
			for j := 0; j < 5; j++ {
				limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
				limiter.CanAttemptAuth(ctx, addr, "user@example.com")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not crash - just verify we can get stats
	stats := limiter.GetStats(ctx, 30*time.Minute)
	if stats == nil {
		t.Error("Should be able to get stats after concurrent access")
	}
}

// TestAuthRateLimiterWithTrustedNetworks tests that limiter can be created with trusted networks config
func TestAuthRateLimiterWithTrustedNetworks(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     3,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"10.0.0.0/8", "192.168.1.0/24"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", "", "", cfg, trustedNets)
	if limiter == nil {
		t.Fatal("Failed to create limiter with trusted networks")
	}
	defer limiter.Stop()

	// Just verify the limiter was created successfully with trusted networks
	// Actual trusted network enforcement is tested in integration tests where
	// the WithProxy methods are used (CanAttemptAuthWithProxy, RecordAuthAttemptWithProxy)
	t.Log("Successfully created auth rate limiter with trusted networks config")
}

// TestAuthRateLimiterTrustedNetworksWithProxy tests that trusted networks bypass rate limiting when using proxy methods
func TestAuthRateLimiterTrustedNetworksWithProxy(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     1, // Block after just 1 failure
		IPBlockDuration:      5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"10.0.0.0/8", "192.168.1.0/24"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", "", "", cfg, trustedNets)
	if limiter == nil {
		t.Fatal("Failed to create limiter with trusted networks")
	}
	defer limiter.Stop()

	ctx := context.Background()

	// Create mock connections for trusted and untrusted IPs
	// Using mock connections that return specific local addresses

	// Test 1: Trusted IP from 192.168.1.0/24 should never be blocked
	trustedConn := &testAuthConn{localAddr: "0.0.0.0:0", remoteAddr: "192.168.1.100:12345"}

	// Record many failures from trusted IP
	for i := 0; i < 10; i++ {
		limiter.RecordAuthAttemptWithProxy(ctx, trustedConn, nil, "user@example.com", false)
	}

	// Should still be allowed
	err := limiter.CanAttemptAuthWithProxy(ctx, trustedConn, nil, "user@example.com")
	if err != nil {
		t.Errorf("Trusted IP (192.168.1.100) should never be blocked, got: %v", err)
	}

	// Test 2: Trusted IP from 10.0.0.0/8 should also never be blocked
	trustedConn2 := &testAuthConn{localAddr: "0.0.0.0:0", remoteAddr: "10.5.10.20:12345"}

	for i := 0; i < 10; i++ {
		limiter.RecordAuthAttemptWithProxy(ctx, trustedConn2, nil, "user@example.com", false)
	}

	err = limiter.CanAttemptAuthWithProxy(ctx, trustedConn2, nil, "user@example.com")
	if err != nil {
		t.Errorf("Trusted IP (10.5.10.20) should never be blocked, got: %v", err)
	}

	// Test 3: Untrusted IP should be blocked after threshold
	untrustedConn := &testAuthConn{localAddr: "0.0.0.0:0", remoteAddr: "8.8.8.8:12345"}

	limiter.RecordAuthAttemptWithProxy(ctx, untrustedConn, nil, "user@example.com", false)

	err = limiter.CanAttemptAuthWithProxy(ctx, untrustedConn, nil, "user@example.com")
	if err == nil {
		t.Error("Untrusted IP (8.8.8.8) should be blocked after 1 failure (threshold 1)")
	}

	t.Logf("Correctly blocked untrusted IP: %v", err)
}

// TestAuthRateLimiterProxyProtocolInfo tests rate limiting with proxy protocol info
func TestAuthRateLimiterProxyProtocolInfo(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		MaxAttemptsPerIP:     2,
		IPBlockDuration:      5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"127.0.0.0/8"} // Trust localhost/proxy
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", "", "", cfg, trustedNets)
	if limiter == nil {
		t.Fatal("Failed to create limiter")
	}
	defer limiter.Stop()

	ctx := context.Background()

	// Simulate proxy scenario: connection comes from trusted proxy but real client IP is untrusted
	proxyConn := &testAuthConn{localAddr: "0.0.0.0:0", remoteAddr: "127.0.0.1:12345"}

	// Proxy protocol info indicates real client IP
	proxyInfo := &ProxyProtocolInfo{
		SrcIP:   "203.0.113.50",
		SrcPort: 54321,
	}

	// Record failures - should track real client IP (203.0.113.50), not proxy IP
	limiter.RecordAuthAttemptWithProxy(ctx, proxyConn, proxyInfo, "user@example.com", false)
	limiter.RecordAuthAttemptWithProxy(ctx, proxyConn, proxyInfo, "user@example.com", false)

	// Should be blocked based on real client IP
	err := limiter.CanAttemptAuthWithProxy(ctx, proxyConn, proxyInfo, "user@example.com")
	if err == nil {
		t.Error("Real client IP (203.0.113.50) should be blocked after 2 failures")
	}

	// Different real client IP through same proxy should work
	proxyInfo2 := &ProxyProtocolInfo{
		SrcIP:   "203.0.113.51",
		SrcPort: 54322,
	}

	err = limiter.CanAttemptAuthWithProxy(ctx, proxyConn, proxyInfo2, "user@example.com")
	if err != nil {
		t.Errorf("Different client IP should not be blocked: %v", err)
	}
}

// mockConn implements net.Conn for testing
type testAuthConn struct {
	localAddr  string
	remoteAddr string
}

func (m *testAuthConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *testAuthConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *testAuthConn) Close() error                       { return nil }
func (m *testAuthConn) LocalAddr() net.Addr                { return &StringAddr{Addr: m.localAddr} }
func (m *testAuthConn) RemoteAddr() net.Addr               { return &StringAddr{Addr: m.remoteAddr} }
func (m *testAuthConn) SetDeadline(t time.Time) error      { return nil }
func (m *testAuthConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *testAuthConn) SetWriteDeadline(t time.Time) error { return nil }

// ========== IP+USERNAME BLOCKING TESTS (TIER 1) ==========

// TestAuthRateLimiter_IPUsernameBlocking_Basic tests basic IP+username blocking (Tier 1)
func TestAuthRateLimiter_IPUsernameBlocking_Basic(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         100,
		IPBlockDuration:          15 * time.Minute,
		IPWindowDuration:         15 * time.Minute,
		CacheCleanupInterval:     1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "1.2.3.4:12345"}
	username := "test@example.com"

	// Record 3 failures
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	limiter.RecordAuthAttempt(ctx, ip, username, false)

	err := limiter.CanAttemptAuth(ctx, ip, username)
	if err == nil {
		t.Error("Should block IP+username after 3 failures")
	} else {
		t.Logf("Correctly blocked: %v", err)
	}
}

// TestAuthRateLimiter_IPUsernameBlocking_IsolatesUsers tests that IP+username blocking
// only blocks specific user from specific IP, not other users from same IP
func TestAuthRateLimiter_IPUsernameBlocking_IsolatesUsers(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: IP+username blocking (fast)
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2: High threshold
		MaxAttemptsPerIP: 100,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	sharedIP := &StringAddr{Addr: "10.20.30.40:12345"}

	user1 := "alice@example.com"
	user2 := "bob@example.com"
	user3 := "charlie@example.com"

	// User1 fails 3 times - should be blocked
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, sharedIP, user1, false)
	}

	// User1 should be blocked
	err := limiter.CanAttemptAuth(ctx, sharedIP, user1)
	if err == nil {
		t.Error("User1 should be blocked after 3 failures")
	}

	// User2 and User3 should NOT be blocked (different usernames)
	err = limiter.CanAttemptAuth(ctx, sharedIP, user2)
	if err != nil {
		t.Errorf("User2 should NOT be blocked (different username): %v", err)
	}

	err = limiter.CanAttemptAuth(ctx, sharedIP, user3)
	if err != nil {
		t.Errorf("User3 should NOT be blocked (different username): %v", err)
	}

	// User2 can successfully authenticate
	limiter.RecordAuthAttempt(ctx, sharedIP, user2, true)
	err = limiter.CanAttemptAuth(ctx, sharedIP, user2)
	if err != nil {
		t.Errorf("User2 should still work after successful auth: %v", err)
	}

	t.Logf("✓ IP+username blocking correctly isolates users on shared IP")
}

// TestAuthRateLimiter_IPUsernameBlocking_DifferentIPsSameUser tests that
// blocking one IP+username combo doesn't block same username from different IP
func TestAuthRateLimiter_IPUsernameBlocking_DifferentIPsSameUser(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		MaxAttemptsPerIP: 100,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	username := "test@example.com"
	ip1 := &StringAddr{Addr: "1.1.1.1:12345"}
	ip2 := &StringAddr{Addr: "2.2.2.2:12345"}

	// Fail 3 times from IP1 - blocks IP1+username
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, ip1, username, false)
	}

	// IP1 should be blocked for this username
	err := limiter.CanAttemptAuth(ctx, ip1, username)
	if err == nil {
		t.Error("IP1+username should be blocked")
	}

	// Same username from IP2 should NOT be blocked (different IP)
	err = limiter.CanAttemptAuth(ctx, ip2, username)
	if err != nil {
		t.Errorf("IP2+username should NOT be blocked (different IP): %v", err)
	}

	// User can successfully auth from IP2
	limiter.RecordAuthAttempt(ctx, ip2, username, true)
	err = limiter.CanAttemptAuth(ctx, ip2, username)
	if err != nil {
		t.Errorf("IP2+username should work after successful auth: %v", err)
	}

	t.Logf("✓ IP+username blocking correctly isolates by IP")
}

// TestAuthRateLimiter_IPUsernameBlocking_SuccessClears tests that successful
// authentication clears IP+username failure tracking
func TestAuthRateLimiter_IPUsernameBlocking_SuccessClears(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		MaxAttemptsPerIP: 100,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "1.2.3.4:12345"}
	username := "test@example.com"

	// Record 2 failures (not blocked yet)
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	limiter.RecordAuthAttempt(ctx, ip, username, false)

	// Check stats - should have IP+username tracking entry
	stats := limiter.GetStats(ctx, 1*time.Minute)
	blockedIPUsernameCount := stats["blocked_ip_usernames"].(int)
	if blockedIPUsernameCount == 0 {
		t.Error("Should have IP+username tracking entry after failures")
	}

	// Successful authentication should clear tracking
	limiter.RecordAuthAttempt(ctx, ip, username, true)

	// Check stats - should be cleared
	stats = limiter.GetStats(ctx, 1*time.Minute)
	blockedIPUsernameCount = stats["blocked_ip_usernames"].(int)
	if blockedIPUsernameCount != 0 {
		t.Errorf("IP+username tracking should be cleared after success, got %d", blockedIPUsernameCount)
	}

	// Can continue with more attempts without accumulating
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	limiter.RecordAuthAttempt(ctx, ip, username, false)
	err := limiter.CanAttemptAuth(ctx, ip, username)
	if err != nil {
		t.Errorf("Should not block after success reset: %v", err)
	}

	t.Logf("✓ Successful authentication clears IP+username tracking")
}

// TestAuthRateLimiter_IPUsernameBlocking_EmptyUsername tests that empty username
// doesn't trigger IP+username blocking (falls back to IP-only)
func TestAuthRateLimiter_IPUsernameBlocking_EmptyUsername(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: IP+username (should not trigger for empty username)
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2: IP-only (should trigger)
		MaxAttemptsPerIP: 4,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "1.2.3.4:12345"}

	// Record 3 failures with empty username
	// Should NOT trigger Tier 1 (threshold 2) because username is empty
	// Should eventually trigger Tier 2 (threshold 4)
	limiter.RecordAuthAttempt(ctx, ip, "", false)
	limiter.RecordAuthAttempt(ctx, ip, "", false)
	limiter.RecordAuthAttempt(ctx, ip, "", false)

	// Should not be blocked yet (Tier 2 threshold is 4)
	err := limiter.CanAttemptAuth(ctx, ip, "")
	if err != nil {
		t.Errorf("Should not block after 3 failures (Tier 2 threshold is 4): %v", err)
	}

	// 4th failure should trigger Tier 2 block
	limiter.RecordAuthAttempt(ctx, ip, "", false)
	err = limiter.CanAttemptAuth(ctx, ip, "")
	if err == nil {
		t.Error("Should block after 4 failures (Tier 2 threshold)")
	}

	t.Logf("✓ Empty username correctly uses Tier 2 (IP-only) blocking")
}

// TestAuthRateLimiter_TierInteraction_BothTiersActive tests interaction when both
// Tier 1 and Tier 2 are active with different thresholds
func TestAuthRateLimiter_TierInteraction_BothTiersActive(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: Fast IP+username blocking
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,

		// Tier 2: Slower IP-only blocking
		MaxAttemptsPerIP: 10,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "5.5.5.5:12345"}

	// Attacker tries 4 different users, 3 attempts each (= 12 total)
	users := []string{"user1@example.com", "user2@example.com", "user3@example.com", "user4@example.com"}

	for _, user := range users {
		for i := 0; i < 3; i++ {
			limiter.RecordAuthAttempt(ctx, ip, user, false)
		}
	}

	// Each individual user should be blocked by Tier 1
	for _, user := range users {
		err := limiter.CanAttemptAuth(ctx, ip, user)
		if err == nil {
			t.Errorf("User %s should be blocked by Tier 1 (IP+username)", user)
		}
	}

	// Entire IP should ALSO be blocked by Tier 2 (12 > 10 threshold)
	// Try with a NEW username that hasn't been tried
	newUser := "newuser@example.com"
	err := limiter.CanAttemptAuth(ctx, ip, newUser)
	if err == nil {
		t.Error("Entire IP should be blocked by Tier 2 after 12 total failures (threshold 10)")
	}

	t.Logf("✓ Both tiers work together: Tier 1 blocks specific users, Tier 2 blocks entire IP")
}

// TestAuthRateLimiter_TierInteraction_Tier2OnlyWhenDisabledTier1 tests that when
// Tier 1 is disabled (MaxAttemptsPerIPUsername=0), only Tier 2 applies
func TestAuthRateLimiter_TierInteraction_Tier2OnlyWhenDisabledTier1(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: DISABLED
		MaxAttemptsPerIPUsername: 0,

		// Tier 2: IP-only blocking
		MaxAttemptsPerIP: 5,
		IPBlockDuration:  15 * time.Minute,
		IPWindowDuration: 15 * time.Minute,

		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	ip := &StringAddr{Addr: "7.7.7.7:12345"}

	// Try 3 users, 2 failures each (6 total)
	users := []string{"user1@example.com", "user2@example.com", "user3@example.com"}
	for _, user := range users {
		limiter.RecordAuthAttempt(ctx, ip, user, false)
		limiter.RecordAuthAttempt(ctx, ip, user, false)
	}

	// Individual users should NOT be blocked (Tier 1 disabled)
	// But IP should be blocked (Tier 2: 6 > 5)
	for _, user := range users {
		err := limiter.CanAttemptAuth(ctx, ip, user)
		// Should be blocked by Tier 2 (IP-only), not Tier 1
		if err == nil {
			t.Errorf("User %s should be blocked by Tier 2 (IP-only) after 6 total failures", user)
		}
	}

	// Verify stats show no IP+username blocks
	stats := limiter.GetStats(ctx, 1*time.Minute)
	blockedIPUsernameCount := stats["blocked_ip_usernames"].(int)
	if blockedIPUsernameCount != 0 {
		t.Errorf("Should have no IP+username blocks when Tier 1 disabled, got %d", blockedIPUsernameCount)
	}

	blockedIPs := stats["blocked_ips"].(int)
	if blockedIPs == 0 {
		t.Error("Should have IP blocks from Tier 2")
	}

	t.Logf("✓ Tier 2 works independently when Tier 1 is disabled")
}

// TestAuthRateLimiter_IPUsernameBlocking_Cleanup tests that IP+username blocks
// are properly cleaned up after expiration
func TestAuthRateLimiter_IPUsernameBlocking_CleanupExpired(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled: true,

		// Tier 1: Very short duration for testing
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  100 * time.Millisecond,
		IPUsernameWindowDuration: 100 * time.Millisecond,

		// Tier 2: High threshold
		MaxAttemptsPerIP: 100,
		IPBlockDuration:  1 * time.Minute,
		IPWindowDuration: 1 * time.Minute,

		CacheCleanupInterval: 50 * time.Millisecond, // Fast cleanup
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()

	// Create multiple IP+username blocks
	for i := 1; i <= 5; i++ {
		ip := &StringAddr{Addr: fmt.Sprintf("10.0.0.%d:12345", i)}
		username := fmt.Sprintf("user%d@example.com", i)

		// Trigger block
		limiter.RecordAuthAttempt(ctx, ip, username, false)
		limiter.RecordAuthAttempt(ctx, ip, username, false)
	}

	// Verify blocks exist
	stats := limiter.GetStats(ctx, 1*time.Minute)
	blockedCount := stats["blocked_ip_usernames"].(int)
	if blockedCount == 0 {
		t.Error("Should have IP+username blocks initially")
	}
	t.Logf("Initially blocked: %d IP+username combinations", blockedCount)

	// Wait for blocks to expire and cleanup to run
	time.Sleep(250 * time.Millisecond)

	// Verify cleanup removed expired blocks
	stats = limiter.GetStats(ctx, 1*time.Minute)
	blockedCountAfter := stats["blocked_ip_usernames"].(int)
	if blockedCountAfter != 0 {
		t.Errorf("Cleanup should have removed expired IP+username blocks, got %d remaining", blockedCountAfter)
	}

	t.Logf("✓ IP+username blocks properly cleaned up after expiration")
}
