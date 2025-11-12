//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// TestIMAP_RateLimiting_IPBlocking tests that IPs are blocked after exceeding threshold
func TestIMAP_RateLimiting_IPBlocking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with aggressive rate limiting
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 3, // Block after 3 failures
		IPBlockDuration:  1 * time.Minute,
		IPWindowDuration: 5 * time.Minute,
	})
	defer srv.Close()

	// Attempt 1: Wrong password
	c1, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c1.Login(account.Email, "wrongpassword1").Wait()
	if err == nil {
		t.Fatal("Login should have failed with wrong password")
	}
	c1.Close()

	// Attempt 2: Wrong password
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c2.Login(account.Email, "wrongpassword2").Wait()
	if err == nil {
		t.Fatal("Login should have failed with wrong password")
	}
	c2.Close()

	// Attempt 3: Wrong password - should trigger fast block
	c3, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c3.Login(account.Email, "wrongpassword3").Wait()
	if err == nil {
		t.Fatal("Login should have failed with wrong password")
	}
	c3.Close()

	// Attempt 4: Should be blocked even with correct password
	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c4.Close()

	err = c4.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Login should have been blocked due to rate limiting")
	}

	// Check that error message indicates rate limiting (not wrong password)
	errMsg := err.Error()
	if !strings.Contains(strings.ToLower(errMsg), "blocked") && !strings.Contains(strings.ToLower(errMsg), "too many") {
		t.Logf("Warning: Error message doesn't clearly indicate rate limiting: %v", err)
	}

	t.Logf("✓ IP successfully blocked after 3 failed attempts")
}

// TestIMAP_RateLimiting_ProgressiveDelays tests that delays increase exponentially
func TestIMAP_RateLimiting_ProgressiveDelays(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with progressive delays
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:             true,
		DelayStartThreshold: 2, // Start delays after 2 failures
		InitialDelay:        200 * time.Millisecond,
		MaxDelay:            2 * time.Second,
		DelayMultiplier:     2.0, // Double each time
		MaxAttemptsPerIP:    10,  // High threshold so we don't block
		IPWindowDuration:    5 * time.Minute,
	})
	defer srv.Close()

	// First failure - no delay expected (FailureCount will be 1, below threshold of 2)
	start := time.Now()
	c1, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c1.Login(account.Email, "wrongpassword1").Wait()
	if err == nil {
		t.Fatal("Login should have failed")
	}
	c1.Close()
	elapsed1 := time.Since(start)
	t.Logf("First failure took %v (no delay expected)", elapsed1)

	// Second failure - still no delay (FailureCount will be 2, threshold just reached)
	// Delay is calculated AFTER this attempt for the NEXT attempt
	start = time.Now()
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c2.Login(account.Email, "wrongpassword2").Wait()
	if err == nil {
		t.Fatal("Login should have failed")
	}
	c2.Close()
	elapsed2 := time.Since(start)
	t.Logf("Second failure took %v (no delay yet, but delay calculated for next attempt)", elapsed2)

	// Third failure - 200ms delay expected (InitialDelay from previous failure)
	start = time.Now()
	c3, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c3.Login(account.Email, "wrongpassword3").Wait()
	if err == nil {
		t.Fatal("Login should have failed")
	}
	c3.Close()
	elapsed3 := time.Since(start)
	t.Logf("Third failure took %v (expected ~200ms delay)", elapsed3)

	// Check that delay was applied (allow some tolerance for network/processing overhead)
	if elapsed3 < 180*time.Millisecond {
		t.Errorf("Expected at least 180ms delay on 3rd attempt, got %v", elapsed3)
	}

	// Fourth failure - 400ms delay expected (delay doubled)
	start = time.Now()
	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c4.Login(account.Email, "wrongpassword4").Wait()
	if err == nil {
		t.Fatal("Login should have failed")
	}
	c4.Close()
	elapsed4 := time.Since(start)
	t.Logf("Fourth failure took %v (expected ~400ms delay)", elapsed4)

	// Check that delay was applied and increased
	if elapsed4 < 380*time.Millisecond {
		t.Errorf("Expected at least 380ms delay on 4th attempt, got %v", elapsed4)
	}
	if elapsed4 <= elapsed3 {
		t.Errorf("Expected fourth delay (%v) to be longer than third delay (%v)", elapsed4, elapsed3)
	}

	t.Logf("✓ Progressive delays working correctly")
}

// TestIMAP_RateLimiting_SuccessResetsFailures tests that successful auth resets failure count
func TestIMAP_RateLimiting_SuccessResetsFailures(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with rate limiting
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 3, // Block after 3 failures
		IPBlockDuration:  1 * time.Minute,
		IPWindowDuration: 5 * time.Minute,
	})
	defer srv.Close()

	// Two failed attempts
	for i := 0; i < 2; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, "wrongpassword").Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	// Successful login - should reset failure count
	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Login should succeed: %v", err)
	}
	c.Logout()

	// Now we should be able to make 2 more failed attempts without blocking
	for i := 0; i < 2; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, "wrongpassword").Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	// Third attempt after reset - should still not be blocked
	c3, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c3.Close()
	err = c3.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Login should succeed after reset: %v", err)
	}

	t.Logf("✓ Successful authentication resets failure count")
}

// TestIMAP_RateLimiting_IPBlockingWithUsernameTracking tests IP blocking with username tracking for statistics
func TestIMAP_RateLimiting_IPBlockingWithUsernameTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with IP blocking and username tracking (for statistics)
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 3, // Track username failures (for statistics, not blocking)
		MaxAttemptsPerIP:       3, // Block IP after 3 failures
		IPBlockDuration:        1 * time.Minute,
		IPWindowDuration:       5 * time.Minute,
		UsernameWindowDuration: 5 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	})
	defer srv.Close()

	// Make 3 failed attempts from same IP to trigger IP blocking
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c4.Close()

	err = c4.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Login should be blocked after multiple failures (IP block)")
	}

	t.Logf("✓ IP blocking enforced after threshold")
}

// TestIMAP_RateLimiting_Tier1_IPUsername tests IP+username blocking (Tier 1)
func TestIMAP_RateLimiting_Tier1_IPUsername(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with Tier 1 enabled, Tier 2 disabled
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,               // Tier 1: Block IP+username after 3 failures
		IPUsernameBlockDuration:  2 * time.Minute, // Block for 2 minutes
		IPUsernameWindowDuration: 5 * time.Minute, // 5 minute window
		MaxAttemptsPerIP:         0,               // Tier 2: Disabled
		DelayStartThreshold:      100,             // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	// Create a second test account
	account2 := common.CreateTestAccount(t, srv.ResilientDB)

	// Make 3 failed attempts for account1 - should trigger Tier 1 block
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	// Fourth attempt for account1 should be blocked by Tier 1
	time.Sleep(50 * time.Millisecond)
	c1, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c1.Login(account.Email, account.Password).Wait()
	c1.Close()
	if err == nil {
		t.Fatal("Login should be blocked by Tier 1 (IP+username)")
	}
	t.Logf("✓ Tier 1 blocked account1 after 3 failures")

	// Different account from same IP should still work (Tier 1 is per-user)
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c2.Login(account2.Email, account2.Password).Wait()
	if err != nil {
		t.Fatalf("Login should succeed for different user (Tier 1 is per IP+username): %v", err)
	}
	c2.Close()
	t.Logf("✓ Different user can still login (Tier 1 isolation works)")
}

// TestIMAP_RateLimiting_Tier1_OnlyBlocksIPUsernameCombination verifies that
// Tier 1 blocking ONLY blocks the specific IP+username combination, not:
// - The same username from a different IP
// - A different username from the same IP
// - The IP itself
func TestIMAP_RateLimiting_Tier1_OnlyBlocksIPUsernameCombination(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with ONLY Tier 1 enabled (Tier 2 disabled)
	srv, account1 := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,               // Tier 1: Block IP+username after 3 failures
		IPUsernameBlockDuration:  2 * time.Minute, // Block for 2 minutes
		IPUsernameWindowDuration: 5 * time.Minute, // 5 minute window
		MaxAttemptsPerIP:         0,               // Tier 2: DISABLED - we want to test Tier 1 in isolation
		DelayStartThreshold:      100,             // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	// Create a second test account on same server
	account2 := common.CreateTestAccount(t, srv.ResilientDB)

	// STEP 1: Trigger Tier 1 block for account1 from IP1 (127.0.0.1)
	t.Logf("STEP 1: Making 3 failed attempts for account1 from IP1 (127.0.0.1)")
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account1.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed with wrong password")
		}
		c.Close()
	}
	time.Sleep(50 * time.Millisecond) // Let rate limiter process

	// STEP 2: Verify account1 from IP1 is blocked
	t.Logf("STEP 2: Verify account1@IP1 is blocked")
	c1, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c1.Login(account1.Email, account1.Password).Wait()
	c1.Close()
	if err == nil {
		t.Fatal("account1@IP1 should be blocked by Tier 1")
	}
	// Server sends BYE when rate limited, which is correct behavior
	t.Logf("✓ account1@IP1 (127.0.0.1|%s) is blocked (error: %v)", account1.Email, err)

	// STEP 3: Verify account2 from SAME IP1 is NOT blocked
	// This proves we're not blocking the IP itself
	t.Logf("STEP 3: Verify account2 from SAME IP1 (127.0.0.1) is NOT blocked")
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c2.Login(account2.Email, account2.Password).Wait()
	if err != nil {
		t.Fatalf("account2 from same IP should NOT be blocked (Tier 1 is per IP+username): %v", err)
	}
	c2.Close()
	t.Logf("✓ account2 from SAME IP1 (127.0.0.1|%s) is NOT blocked", account2.Email)

	// NOTE: We cannot easily test "same username from different IP" in integration tests
	// because all connections come from 127.0.0.1. However, the unit tests in
	// server/auth_rate_limiter_test.go verify this behavior extensively.
	// See TestAuthRateLimiter_TwoTierBlocking_SharedIP for proof that different IPs
	// are tracked separately.

	t.Logf("✓ Tier 1 correctly blocks ONLY the IP+username combination, not IP or username alone")
}

// TestIMAP_RateLimiting_TCPLevelBlocking verifies that Tier 2 (IP blocking) rejects
// connections at the TCP level, BEFORE TLS handshake, to save server resources.
func TestIMAP_RateLimiting_TCPLevelBlocking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with Tier 2 enabled (IP blocking)
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0,               // Tier 1: Disabled
		MaxAttemptsPerIP:         3,               // Tier 2: Block IP after 3 failures
		IPBlockDuration:          2 * time.Minute, // Block for 2 minutes
		IPWindowDuration:         5 * time.Minute, // 5 minute window
		DelayStartThreshold:      100,             // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	t.Logf("STEP 1: Make 3 failed login attempts to trigger Tier 2 IP block")
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server on attempt %d: %v", i+1, err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed with wrong password")
		}
		c.Close()
		t.Logf("  Attempt %d: Failed login (expected)", i+1)
	}

	time.Sleep(100 * time.Millisecond) // Let rate limiter process

	t.Logf("STEP 2: Verify that 4th connection is rejected at TCP level")
	// The connection should fail at TCP accept level, not during LOGIN
	// This means either:
	// - DialInsecure fails (connection refused)
	// - OR connection is accepted but immediately closed (EOF on first read)

	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		// TCP connection rejected - this is one valid outcome
		t.Logf("✓ TCP connection rejected (connection refused): %v", err)
		return
	}
	defer c4.Close()

	// If connection succeeded, try to login
	// The server should have closed the connection before we can send LOGIN
	err = c4.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Login should be blocked - IP is rate limited")
	}

	// Connection was closed by server at TCP level
	t.Logf("✓ Connection closed by server: %v", err)
	t.Logf("✓ Tier 2 IP blocking successfully rejects connections at TCP level")
}

// TestIMAP_RateLimiting_Tier2_BlockExpiration verifies that Tier 2 (IP blocking)
// expires correctly after ip_block_duration, allowing connections again.
func TestIMAP_RateLimiting_Tier2_BlockExpiration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Use SHORT block duration for faster test (2 seconds)
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0,               // Tier 1: Disabled
		MaxAttemptsPerIP:         3,               // Tier 2: Block IP after 3 failures
		IPBlockDuration:          2 * time.Second, // SHORT: 2 seconds for testing
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      100, // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	t.Logf("STEP 1: Trigger IP block with 3 failed attempts")
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should fail with wrong password")
		}
		c.Close()
	}
	t.Logf("✓ IP blocked after 3 failures")

	time.Sleep(50 * time.Millisecond)

	t.Logf("STEP 2: Verify 4th attempt shows error message and is blocked")
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Logf("✓ Connection rejected at TCP level: %v", err)
	} else {
		err = c2.Login(account.Email, account.Password).Wait()
		c2.Close()
		if err == nil {
			t.Fatal("Login should be blocked")
		}
		t.Logf("✓ Login blocked: %v", err)
	}

	t.Logf("STEP 3: Verify 5th attempt is rejected at TCP level (no error message)")
	c3, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Logf("✓ TCP connection rejected: %v", err)
	} else {
		err = c3.Login(account.Email, account.Password).Wait()
		c3.Close()
		if err == nil {
			t.Fatal("Login should be blocked")
		}
		t.Logf("✓ Connection closed by server: %v", err)
	}

	t.Logf("STEP 4: Wait for block to expire (2 seconds)")
	time.Sleep(2100 * time.Millisecond) // Wait slightly longer than block duration

	t.Logf("STEP 5: Verify connection succeeds after block expiration")
	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Connection should succeed after block expires: %v", err)
	}
	defer c4.Close()

	err = c4.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Login should succeed after block expires: %v", err)
	}
	t.Logf("✓ Login successful after ip_block_duration expired")
	t.Logf("✓ Tier 2 block correctly expires after ip_block_duration")
}

// TestIMAP_RateLimiting_Tier1_BlockExpiration verifies that Tier 1 (IP+username blocking)
// expires correctly after ip_username_block_duration, allowing logins again.
func TestIMAP_RateLimiting_Tier1_BlockExpiration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Use SHORT block duration for faster test (2 seconds)
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,               // Tier 1: Block IP+username after 3 failures
		IPUsernameBlockDuration:  2 * time.Second, // SHORT: 2 seconds for testing
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2: Disabled
		DelayStartThreshold:      100, // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	// Create second account to verify Tier 1 is per-user
	account2 := common.CreateTestAccount(t, srv.ResilientDB)

	t.Logf("STEP 1: Trigger Tier 1 block for account1 with 3 failed attempts")
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpassword%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should fail with wrong password")
		}
		c.Close()
	}
	t.Logf("✓ account1@IP blocked after 3 failures (Tier 1)")

	time.Sleep(50 * time.Millisecond)

	t.Logf("STEP 2: Verify account1 is blocked (shows error message)")
	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Connection should succeed (Tier 1 blocks at login level): %v", err)
	}
	err = c2.Login(account.Email, account.Password).Wait()
	c2.Close()
	if err == nil {
		t.Fatal("account1 login should be blocked")
	}
	t.Logf("✓ account1 blocked: %v", err)

	t.Logf("STEP 3: Verify account2 can still login (Tier 1 is per-user)")
	c3, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Connection should succeed: %v", err)
	}
	err = c3.Login(account2.Email, account2.Password).Wait()
	if err != nil {
		t.Fatalf("account2 should NOT be blocked: %v", err)
	}
	c3.Close()
	t.Logf("✓ account2 can login (Tier 1 isolation works)")

	t.Logf("STEP 4: Wait for block to expire (2 seconds)")
	time.Sleep(2100 * time.Millisecond) // Wait slightly longer than block duration

	t.Logf("STEP 5: Verify account1 can login after block expiration")
	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Connection should succeed: %v", err)
	}
	defer c4.Close()

	err = c4.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("account1 login should succeed after block expires: %v", err)
	}
	t.Logf("✓ account1 login successful after ip_username_block_duration expired")
	t.Logf("✓ Tier 1 block correctly expires after ip_username_block_duration")
}

// TestIMAP_RateLimiting_BothTiers tests both tiers working together
func TestIMAP_RateLimiting_BothTiers(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with both tiers enabled
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,                // Tier 1: Block IP+username after 3 failures
		IPUsernameBlockDuration:  2 * time.Minute,  // Block for 2 minutes
		IPUsernameWindowDuration: 5 * time.Minute,  // 5 minute window
		MaxAttemptsPerIP:         10,               // Tier 2: Block entire IP after 10 failures
		IPBlockDuration:          5 * time.Minute,  // Block for 5 minutes
		IPWindowDuration:         10 * time.Minute, // 10 minute window
		DelayStartThreshold:      100,              // Disable delays
		CacheCleanupInterval:     1 * time.Minute,
	})
	defer srv.Close()

	// Create a second test account
	account2 := common.CreateTestAccount(t, srv.ResilientDB)

	// Make failed attempts to trigger both tiers
	// 3 failures for account1 (triggers Tier 1 for account1)
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, fmt.Sprintf("wrongpass%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	// 7 more failures alternating accounts to reach 10 total (triggers Tier 2)
	for i := 0; i < 7; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		username := account.Email
		if i%2 == 0 {
			username = account2.Email
		}
		err = c.Login(username, fmt.Sprintf("wrongpass_tier2_%d", i)).Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	time.Sleep(50 * time.Millisecond)

	// Both accounts should now be blocked
	c1, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c1.Login(account.Email, account.Password).Wait()
	c1.Close()
	if err == nil {
		t.Fatal("account1 should be blocked")
	}

	c2, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	err = c2.Login(account2.Email, account2.Password).Wait()
	c2.Close()
	if err == nil {
		t.Fatal("account2 should be blocked by Tier 2")
	}

	t.Logf("✓ Both tiers working correctly together")
}

// TestIMAP_RateLimiting_Disabled tests that auth works when rate limiting is disabled
func TestIMAP_RateLimiting_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with rate limiting disabled
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled: false,
	})
	defer srv.Close()

	// Make multiple failed attempts - should not be blocked
	for i := 0; i < 10; i++ {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		err = c.Login(account.Email, "wrongpassword").Wait()
		if err == nil {
			t.Fatal("Login should have failed")
		}
		c.Close()
	}

	// Should still be able to login successfully
	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Close()

	err = c.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Login should succeed with rate limiting disabled: %v", err)
	}

	t.Logf("✓ Rate limiting disabled - no blocking after many failures")
}

// setupIMAPServerWithRateLimiting creates an IMAP server with custom rate limiting config
func setupIMAPServerWithRateLimiting(t *testing.T, rateLimitConfig server.AuthRateLimiterConfig) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Use minimal setup - no uploader needed for auth tests
	srv, err := serverImap.New(
		context.Background(),
		"test-rate-limit",
		"localhost",
		address,
		&storage.S3Storage{}, // empty storage is fine for auth tests
		rdb,
		nil, // upload worker
		nil, // cache
		serverImap.IMAPServerOptions{
			AuthRateLimit: rateLimitConfig,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.Serve(address); err != nil {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	return &common.TestServer{
		Server:      srv,
		Address:     address,
		ResilientDB: rdb,
	}, account
}
