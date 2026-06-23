package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// exemptTestConfig returns a rate-limiter config with a fast Tier-1 threshold so tests can
// trip blocking quickly. CleanupInterval is non-zero to avoid a zero-duration ticker.
func exemptTestConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3, // Tier 1: block after 3 failures
		IPUsernameBlockDuration:  time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         50,
		IPBlockDuration:          time.Minute,
		IPWindowDuration:         5 * time.Minute,
		MaxAttemptsPerUsername:   100,
		UsernameWindowDuration:   5 * time.Minute,
		CleanupInterval:          time.Minute,
		DelayStartThreshold:      100, // keep progressive delays out of the way
		DelayMultiplier:          2.0,
		MaxDelay:                 time.Second,
	}
}

// hammerTier1 records n failed attempts for the same IP+username.
func hammerTier1(limiter *AuthRateLimiter, addr net.Addr, user string, n int) {
	ctx := context.Background()
	for i := 0; i < n; i++ {
		limiter.RecordAuthAttempt(ctx, addr, user, false)
	}
}

// TestAuthRateLimiter_ExemptNetworks_FallbackWhenUnset confirms backward compatibility:
// when exempt_networks is unset (nil), the limiter falls back to the trusted_networks
// passed in, so an RFC1918 IP remains exempt (unchanged pre-M2 behavior).
func TestAuthRateLimiter_ExemptNetworks_FallbackWhenUnset(t *testing.T) {
	cfg := exemptTestConfig() // ExemptNetworks left nil
	limiter := NewAuthRateLimiterWithTrustedNetworks("TEST", "", "", cfg, []string{"10.0.0.0/8"})
	defer limiter.Stop()

	if !limiter.isRateLimitExempt("10.1.2.3") {
		t.Error("exempt_networks unset must fall back to trusted_networks; 10.1.2.3 should be exempt")
	}

	addr := &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 1234}
	hammerTier1(limiter, addr, "user@example.com", 10)
	if err := limiter.CanAttemptAuth(context.Background(), addr, "user@example.com"); err != nil {
		t.Fatalf("trusted RFC1918 IP should never be blocked under fallback, got: %v", err)
	}
}

// TestAuthRateLimiter_ExemptNetworks_EmptyExemptsNobody is the M2 decoupling proof: an
// explicitly empty exempt_networks exempts NOBODY, even an IP that is in trusted_networks.
// Before the fix, the same RFC1918 IP would have been silently exempt from rate limiting.
func TestAuthRateLimiter_ExemptNetworks_EmptyExemptsNobody(t *testing.T) {
	cfg := exemptTestConfig()
	cfg.ExemptNetworks = []string{} // explicit empty (non-nil) => exempt nobody
	// trusted_networks is still broad (e.g. it must list proxy hops for PROXY/XCLIENT),
	// but that must NOT grant rate-limit exemption anymore.
	limiter := NewAuthRateLimiterWithTrustedNetworks("TEST", "", "", cfg, []string{"10.0.0.0/8"})
	defer limiter.Stop()

	if limiter.isRateLimitExempt("10.1.2.3") {
		t.Error("explicit empty exempt_networks must exempt nobody, even RFC1918")
	}

	addr := &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 1234}
	hammerTier1(limiter, addr, "victim@example.com", 3) // hit Tier-1 threshold
	if err := limiter.CanAttemptAuth(context.Background(), addr, "victim@example.com"); err == nil {
		t.Fatal("RFC1918 IP must be rate-limited when exempt_networks=[] (decoupled from trusted_networks)")
	}
}

// TestAuthRateLimiter_ExemptNetworks_NarrowListOverridesTrusted confirms a narrow
// exempt_networks exempts only its members — a host that is in trusted_networks (allowed to
// send PROXY/XCLIENT) but outside exempt_networks is still rate-limited.
func TestAuthRateLimiter_ExemptNetworks_NarrowListOverridesTrusted(t *testing.T) {
	cfg := exemptTestConfig()
	cfg.ExemptNetworks = []string{"10.0.0.5/32"} // only the webmail host is exempt
	limiter := NewAuthRateLimiterWithTrustedNetworks("TEST", "", "", cfg, []string{"10.0.0.0/8"})
	defer limiter.Stop()

	// The configured exempt host is never blocked.
	exemptAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 1234}
	hammerTier1(limiter, exemptAddr, "user@example.com", 10)
	if err := limiter.CanAttemptAuth(context.Background(), exemptAddr, "user@example.com"); err != nil {
		t.Fatalf("the configured exempt host 10.0.0.5 should never be blocked, got: %v", err)
	}

	// A different RFC1918 host (trusted for PROXY but not exempt) is still rate-limited.
	otherAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.6"), Port: 1234}
	hammerTier1(limiter, otherAddr, "victim@example.com", 3)
	if err := limiter.CanAttemptAuth(context.Background(), otherAddr, "victim@example.com"); err == nil {
		t.Fatal("10.0.0.6 is in trusted_networks but not exempt_networks; it must still be rate-limited (M2)")
	}
}
