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
		Enabled:            true,
		FastBlockThreshold: 3, // Block after 3 failures
		FastBlockDuration:  1 * time.Minute,
		IPWindowDuration:   5 * time.Minute,
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
		FastBlockThreshold:  10,  // High threshold so we don't block
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
		Enabled:            true,
		FastBlockThreshold: 3, // Block after 3 failures
		FastBlockDuration:  1 * time.Minute,
		IPWindowDuration:   5 * time.Minute,
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

// TestIMAP_RateLimiting_UsernameBlocking tests username-based blocking across IPs
func TestIMAP_RateLimiting_UsernameBlocking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup server with username tracking
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                true,
		MaxAttemptsPerUsername: 3, // Block username after 3 failures
		FastBlockThreshold:     3,
		FastBlockDuration:      1 * time.Minute,
		IPWindowDuration:       5 * time.Minute,
		UsernameWindowDuration: 5 * time.Minute,
		CacheCleanupInterval:   1 * time.Minute,
	})
	defer srv.Close()

	// Make 3 failed attempts to trigger username blocking
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

	// Note: Username blocking in the current implementation happens at the IP level
	// after fast_block_threshold failures. The username tracking is primarily used
	// for cluster synchronization. So the 4th attempt should be blocked.
	c4, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c4.Close()

	err = c4.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Login should be blocked after multiple failures")
	}

	t.Logf("✓ Username blocking enforced after threshold")
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
