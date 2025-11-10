package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestAuthRateLimiterBasicIPBlocking tests that IPs are blocked after exceeding fast_block_threshold
func TestAuthRateLimiterBasicIPBlocking(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		FastBlockThreshold:   3, // Block after 3 failures
		FastBlockDuration:    5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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

	// Record 3rd failure - should trigger fast block
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
		FastBlockThreshold:   10,  // High threshold so we don't block
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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

// TestAuthRateLimiterUsernameBlocking tests username-based blocking
func TestAuthRateLimiterUsernameBlocking(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 3, // Block username after 3 failures
		UsernameWindowDuration: 30 * time.Minute,
		FastBlockThreshold:     10, // High threshold so IP doesn't block first
		IPWindowDuration:       15 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	username := "target@example.com"

	// Record 2 failures from different IPs
	addr1 := &StringAddr{Addr: "192.168.1.100:12345"}
	addr2 := &StringAddr{Addr: "192.168.1.101:12345"}

	limiter.RecordAuthAttempt(ctx, addr1, username, false)
	limiter.RecordAuthAttempt(ctx, addr2, username, false)

	// Should still allow attempts
	err := limiter.CanAttemptAuth(ctx, addr1, username)
	if err != nil {
		t.Errorf("Should not block username after 2 failures: %v", err)
	}

	// Third failure - should block username
	limiter.RecordAuthAttempt(ctx, addr1, username, false)

	err = limiter.CanAttemptAuth(ctx, addr1, username)
	if err == nil {
		t.Error("Should block username after 3 failures")
	}

	// Should block from any IP
	addr3 := &StringAddr{Addr: "192.168.1.102:12345"}
	err = limiter.CanAttemptAuth(ctx, addr3, username)
	if err == nil {
		t.Error("Should block username from all IPs after 3 failures")
	}

	// Different username should work
	err = limiter.CanAttemptAuth(ctx, addr1, "other@example.com")
	if err != nil {
		t.Errorf("Different username should not be blocked: %v", err)
	}
}

// TestAuthRateLimiterSuccessResetsFailures tests that successful auth clears failures
func TestAuthRateLimiterSuccessResetsFailures(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		FastBlockThreshold:     3,
		FastBlockDuration:      5 * time.Minute,
		MaxAttemptsPerUsername: 5,
		IPWindowDuration:       15 * time.Minute,
		UsernameWindowDuration: 30 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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
		Enabled:            false, // Disabled
		FastBlockThreshold: 1,     // Would block after 1 failure if enabled
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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
		FastBlockThreshold:   10,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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
		FastBlockThreshold:     3,
		FastBlockDuration:      5 * time.Minute,
		MaxAttemptsPerUsername: 5,
		IPWindowDuration:       15 * time.Minute,
		UsernameWindowDuration: 30 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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
		FastBlockThreshold:   3,
		FastBlockDuration:    100 * time.Millisecond, // Very short for testing
		IPWindowDuration:     100 * time.Millisecond,
		CacheCleanupInterval: 50 * time.Millisecond, // Frequent cleanup
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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

// TestAuthRateLimiterConcurrentAccess tests thread safety
func TestAuthRateLimiterConcurrentAccess(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		FastBlockThreshold:   10,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", cfg)
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
		FastBlockThreshold:   3,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"10.0.0.0/8", "192.168.1.0/24"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", cfg, trustedNets)
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
		FastBlockThreshold:   1, // Block after just 1 failure
		FastBlockDuration:    5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"10.0.0.0/8", "192.168.1.0/24"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", cfg, trustedNets)
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
		FastBlockThreshold:   2,
		FastBlockDuration:    5 * time.Minute,
		IPWindowDuration:     15 * time.Minute,
		CacheCleanupInterval: 1 * time.Minute,
	}

	trustedNets := []string{"127.0.0.0/8"} // Trust localhost/proxy
	limiter := NewAuthRateLimiterWithTrustedNetworks("imap", cfg, trustedNets)
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
