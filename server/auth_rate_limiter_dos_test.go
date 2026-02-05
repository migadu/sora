package server

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestAuthRateLimiter_DoSPrevention verifies that username tracking does not block
// legitimate users with correct passwords, preventing DoS attacks where an attacker
// can lock out users by attempting wrong passwords.
//
// This test reproduces the bug reported where same password would sometimes succeed
// and sometimes fail due to username blocking triggered by other clients' failed attempts.
func TestAuthRateLimiter_DoSPrevention(t *testing.T) {
	cfg := config.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 3, // Track failures but don't block
		UsernameWindowDuration: 30 * time.Minute,
		MaxAttemptsPerIP:       10, // High threshold so IP doesn't block
		IPWindowDuration:       15 * time.Minute,
	}

	limiter := NewAuthRateLimiter("imap", "", "", cfg)
	defer limiter.Stop()

	ctx := context.Background()
	username := "victim@example.com"

	// Simulate attacker attempting wrong passwords from different IPs
	attacker1 := &StringAddr{Addr: "1.2.3.4:12345"}
	attacker2 := &StringAddr{Addr: "5.6.7.8:12345"}
	attacker3 := &StringAddr{Addr: "9.10.11.12:12345"}

	limiter.RecordAuthAttempt(ctx, attacker1, username, false)
	limiter.RecordAuthAttempt(ctx, attacker2, username, false)
	limiter.RecordAuthAttempt(ctx, attacker3, username, false)

	// Verify username has 3 failures tracked
	count := limiter.getUsernameFailureCount(username)
	if count != 3 {
		t.Errorf("Expected 3 username failures, got %d", count)
	}

	// CRITICAL: Legitimate user with CORRECT password should NOT be blocked
	// even though username has 3 failures from attackers
	legitimateUser := &StringAddr{Addr: "192.168.1.100:12345"}
	err := limiter.CanAttemptAuth(ctx, legitimateUser, username)
	if err != nil {
		t.Errorf("Legitimate user should NOT be blocked by username failures: %v", err)
		t.Error("This would allow DoS attacks where attacker locks out legitimate users")
	}

	// Simulate successful authentication with correct password
	limiter.RecordAuthAttempt(ctx, legitimateUser, username, true)

	// Username failures should be cleared after successful auth
	count = limiter.getUsernameFailureCount(username)
	if count != 0 {
		t.Errorf("Username failures should be cleared after success, got %d", count)
	}

	t.Logf("✓ DoS prevention working: legitimate users not blocked by username tracking")
}
