package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestAuthRateLimiter_TrustedNetworks_BothTiers verifies that trusted networks
// are exempted from BOTH Tier 1 (IP+username) and Tier 2 (IP-only) rate limiting
func TestAuthRateLimiter_TrustedNetworks_BothTiers(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,           // Tier 1: Block after 3 failures
		IPUsernameBlockDuration:  time.Minute, // Tier 1: 1 minute block
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         3,           // Tier 2: Block after 3 failures
		IPBlockDuration:          time.Minute, // Tier 2: 1 minute block
		IPWindowDuration:         5 * time.Minute,
		MaxAttemptsPerUsername:   100,
		UsernameWindowDuration:   5 * time.Minute,
		CleanupInterval:          time.Minute,
		DelayStartThreshold:      2,
		DelayMultiplier:          2.0,
		MaxDelay:                 8 * time.Second,
	}

	trustedNetworks := []string{"10.0.0.0/8", "192.168.1.0/24"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("TEST", cfg, trustedNetworks)
	defer limiter.Stop()

	ctx := context.Background()
	trustedAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 12345}       // In 10.0.0.0/8
	untrustedAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.42"), Port: 12345} // Not in trusted networks

	// TEST 1: Trusted network should never be blocked by Tier 1 (IP+username)
	t.Run("TrustedNetwork_Tier1_NoBlock", func(t *testing.T) {
		// Make 10 failed attempts from trusted network (way more than Tier 1 threshold of 3)
		for i := 0; i < 10; i++ {
			err := limiter.CanAttemptAuth(ctx, trustedAddr, "user@example.com")
			if err != nil {
				t.Fatalf("Attempt %d: Trusted network should never be blocked (Tier 1), got error: %v", i+1, err)
			}
			limiter.RecordAuthAttempt(ctx, trustedAddr, "user@example.com", false)
		}

		// Verify 11th attempt still works
		err := limiter.CanAttemptAuth(ctx, trustedAddr, "user@example.com")
		if err != nil {
			t.Fatalf("Trusted network should never be blocked (Tier 1), got error: %v", err)
		}
		t.Log("✓ Trusted network correctly exempted from Tier 1 (IP+username) blocking")
	})

	// TEST 2: Trusted network should never be blocked by Tier 2 (IP-only)
	t.Run("TrustedNetwork_Tier2_NoBlock", func(t *testing.T) {
		trustedAddr2 := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

		// Make 10 failed attempts from trusted network with DIFFERENT usernames
		// This should trigger Tier 2 (IP-only) blocking, but trusted IPs should be exempt
		for i := 0; i < 10; i++ {
			username := "user" + string(rune('a'+i)) + "@example.com"
			err := limiter.CanAttemptAuth(ctx, trustedAddr2, username)
			if err != nil {
				t.Fatalf("Attempt %d: Trusted network should never be blocked (Tier 2), got error: %v", i+1, err)
			}
			limiter.RecordAuthAttempt(ctx, trustedAddr2, username, false)
		}

		// Verify 11th attempt with yet another username still works
		err := limiter.CanAttemptAuth(ctx, trustedAddr2, "anotheruser@example.com")
		if err != nil {
			t.Fatalf("Trusted network should never be blocked (Tier 2), got error: %v", err)
		}
		t.Log("✓ Trusted network correctly exempted from Tier 2 (IP-only) blocking")
	})

	// TEST 3: Verify untrusted network DOES get blocked by Tier 1
	t.Run("UntrustedNetwork_Tier1_Blocks", func(t *testing.T) {
		// Make 3 failed attempts (hitting Tier 1 threshold)
		for i := 0; i < 3; i++ {
			limiter.RecordAuthAttempt(ctx, untrustedAddr, "victim@example.com", false)
		}

		// 4th attempt should be blocked
		err := limiter.CanAttemptAuth(ctx, untrustedAddr, "victim@example.com")
		if err == nil {
			t.Fatal("Untrusted network should be blocked by Tier 1 after 3 failures")
		}
		t.Logf("✓ Untrusted network correctly blocked by Tier 1: %v", err)
	})

	// TEST 4: Verify untrusted network DOES get blocked by Tier 2
	t.Run("UntrustedNetwork_Tier2_Blocks", func(t *testing.T) {
		untrustedAddr2 := &net.TCPAddr{IP: net.ParseIP("198.51.100.50"), Port: 12345}

		// Make 3 failed attempts with DIFFERENT usernames (triggers Tier 2)
		for i := 0; i < 3; i++ {
			username := "tier2user" + string(rune('a'+i)) + "@example.com"
			limiter.RecordAuthAttempt(ctx, untrustedAddr2, username, false)
		}

		// 4th attempt should be blocked at IP level
		err := limiter.CanAttemptAuth(ctx, untrustedAddr2, "newuser@example.com")
		if err == nil {
			t.Fatal("Untrusted network should be blocked by Tier 2 after 3 failures across users")
		}
		t.Logf("✓ Untrusted network correctly blocked by Tier 2: %v", err)
	})

	// TEST 5: Verify IsIPBlocked (TCP-level) also respects trusted networks
	t.Run("TrustedNetwork_TCPLevel_NoBlock", func(t *testing.T) {
		trustedAddr3 := &net.TCPAddr{IP: net.ParseIP("10.0.0.99"), Port: 12345}

		// Force some failures to make sure it would be blocked if it weren't trusted
		for i := 0; i < 10; i++ {
			limiter.RecordAuthAttempt(ctx, trustedAddr3, "tcptest@example.com", false)
		}

		// Check TCP-level blocking
		if limiter.IsIPBlocked(trustedAddr3) {
			t.Fatal("Trusted network should never be blocked at TCP level")
		}
		t.Log("✓ Trusted network correctly exempted from TCP-level (IsIPBlocked) checks")
	})
}

// TestAuthRateLimiter_TrustedNetworks_NoRecording verifies that auth attempts
// from trusted networks are not even recorded in failure tracking
func TestAuthRateLimiter_TrustedNetworks_NoRecording(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         3,
		IPBlockDuration:          time.Minute,
		IPWindowDuration:         5 * time.Minute,
		MaxAttemptsPerUsername:   100,
		UsernameWindowDuration:   5 * time.Minute,
		CleanupInterval:          time.Minute,
		DelayStartThreshold:      2,
		DelayMultiplier:          2.0,
		MaxDelay:                 8 * time.Second,
	}

	trustedNetworks := []string{"172.16.0.0/12"}
	limiter := NewAuthRateLimiterWithTrustedNetworks("TEST", cfg, trustedNetworks)
	defer limiter.Stop()

	ctx := context.Background()
	trustedAddr := &net.TCPAddr{IP: net.ParseIP("172.16.10.20"), Port: 12345}

	// Record 5 failed attempts from trusted network
	for i := 0; i < 5; i++ {
		limiter.RecordAuthAttempt(ctx, trustedAddr, "norecord@example.com", false)
	}

	// Get stats - should show zero failures because trusted IPs aren't tracked
	stats := limiter.GetStats(ctx, 5*time.Minute)

	// Check if there are any IP failures recorded
	if ipFailures, ok := stats["ip_failures"].(map[string]int); ok {
		if count, exists := ipFailures["172.16.10.20"]; exists && count > 0 {
			t.Errorf("Trusted network failures should not be recorded, found %d failures", count)
		}
	}

	// Check if there are any IP+username failures recorded
	if ipUsernameFailures, ok := stats["ip_username_failures"].(map[string]int); ok {
		key := "172.16.10.20|norecord@example.com"
		if count, exists := ipUsernameFailures[key]; exists && count > 0 {
			t.Errorf("Trusted network IP+username failures should not be recorded, found %d failures", count)
		}
	}

	t.Log("✓ Trusted network auth attempts are correctly not recorded in failure tracking")
}
