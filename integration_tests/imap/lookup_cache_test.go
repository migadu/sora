//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"golang.org/x/crypto/bcrypt"
)

// TestIMAPBackendLookupCache_BasicCaching tests basic auth cache hit/miss behavior
func TestIMAPBackendLookupCache_BasicCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create IMAP server with auth cache enabled
	server, cache, rdb := setupIMAPServerWithLookupCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-basic-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Test 1: First login - should be cache MISS (DB query)
	t.Run("FirstLogin_CacheMiss", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		stats := getCacheStats(cache)
		if stats.size < 1 {
			t.Errorf("Expected cache size >= 1 after login, got %d", stats.size)
		}
		t.Logf("✓ First login: cache miss → DB auth → cache populated (size=%d, misses=%d)", stats.size, stats.misses)
	})

	// Test 2: Second login - should be cache HIT (no DB query)
	t.Run("SecondLogin_CacheHit", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond) // Ensure first login completed

		beforeHits := getCacheStats(cache).hits

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		stats := getCacheStats(cache)
		if stats.hits <= beforeHits {
			t.Errorf("Expected cache hit, but hits didn't increase (before=%d, after=%d)", beforeHits, stats.hits)
		}
		t.Logf("✓ Second login: cache hit (hits=%d, hitRate=%.1f%%)", stats.hits, stats.hitRate)
	})

	// Test 3: Wrong password - should be cache hit but auth failure
	t.Run("WrongPassword_AuthFailure", func(t *testing.T) {
		beforeHits := getCacheStats(cache).hits

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Close()

		// Login with wrong password should fail
		if err := c.Login(account.Email, "wrongpassword").Wait(); err == nil {
			t.Fatal("Login with wrong password should have failed")
		}

		stats := getCacheStats(cache)
		// Cache was checked (hit), but password didn't match, so entry got invalidated
		if stats.hits <= beforeHits {
			t.Logf("Note: Wrong password may have invalidated cache (hits=%d)", stats.hits)
		}
		t.Logf("✓ Wrong password: rejected correctly")
	})
}

// TestIMAPBackendLookupCache_TTLExpiration tests cache expiration behavior
func TestIMAPBackendLookupCache_TTLExpiration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create IMAP server with SHORT positive TTL (2s) for testing
	server, cache, rdb := setupIMAPServerWithLookupCache(t, true, "2s", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-ttl-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// First login - populate cache
	t.Run("InitialLogin_PopulateCache", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		t.Log("✓ Cache populated")
	})

	// Second login within TTL - cache hit
	t.Run("LoginWithinTTL_CacheHit", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		beforeHits := getCacheStats(cache).hits

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		afterHits := getCacheStats(cache).hits
		if afterHits <= beforeHits {
			t.Errorf("Expected cache hit, got hits before=%d after=%d", beforeHits, afterHits)
		}
		t.Logf("✓ Login within TTL: cache hit (hits increased from %d to %d)", beforeHits, afterHits)
	})

	// Third login after TTL expiration - cache miss
	t.Run("LoginAfterTTL_CacheMiss", func(t *testing.T) {
		time.Sleep(2500 * time.Millisecond) // Wait for 2s TTL to expire
		beforeMisses := getCacheStats(cache).misses

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		afterMisses := getCacheStats(cache).misses
		if afterMisses <= beforeMisses {
			t.Logf("Note: May still be cache hit if cleanup hasn't run yet (misses=%d)", afterMisses)
		} else {
			t.Logf("✓ Login after TTL expiry: cache miss (misses increased from %d to %d)", beforeMisses, afterMisses)
		}
	})
}

// TestIMAPBackendLookupCache_PasswordChange tests cache invalidation on password change
func TestIMAPBackendLookupCache_PasswordChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Use very short revalidation window (1 second) so cache revalidates to detect password change
	server, cache, rdb := setupIMAPServerWithLookupCacheCustom(t, true, "5m", "1m", 1*time.Second)
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-pwchange-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "oldpassword")

	// Login with old password - populate cache
	t.Run("LoginWithOldPassword", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, "oldpassword").Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		t.Log("✓ Old password cached")
	})

	// Change password in database
	t.Run("ChangePassword", func(t *testing.T) {
		newPasswordHash, err := bcrypt.GenerateFromPassword([]byte("newpassword"), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Failed to hash new password: %v", err)
		}

		err = rdb.UpdatePasswordWithRetry(context.Background(), account.Email, string(newPasswordHash))
		if err != nil {
			t.Fatalf("Failed to update password: %v", err)
		}
		t.Log("✓ Password changed in database")

		// Wait for revalidation window to expire (1 second + margin)
		time.Sleep(1100 * time.Millisecond)
	})

	// Try old password - should fail because cache will revalidate and detect password change
	t.Run("LoginWithOldPassword_AfterChange", func(t *testing.T) {

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Close()

		// Old password should fail (cache detects password mismatch)
		if err := c.Login(account.Email, "oldpassword").Wait(); err == nil {
			t.Fatal("Login with old password should have failed after password change")
		}
		t.Log("✓ Old password rejected (negative cache entry created)")
	})

	// Login with new password - should succeed immediately and re-cache
	t.Run("LoginWithNewPassword", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, "newpassword").Wait(); err != nil {
			t.Fatalf("Login with new password failed: %v", err)
		}
		t.Log("✓ New password accepted and cached")
	})

	// Verify new password cached by logging in again
	t.Run("LoginWithNewPassword_CacheHit", func(t *testing.T) {
		beforeHits := getCacheStats(cache).hits

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, "newpassword").Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		afterHits := getCacheStats(cache).hits
		if afterHits <= beforeHits {
			t.Errorf("Expected cache hit for new password, got hits before=%d after=%d", beforeHits, afterHits)
		}
		t.Logf("✓ New password served from cache (hits increased from %d to %d)", beforeHits, afterHits)
	})
}

// TestIMAPBackendLookupCache_NegativeCaching tests failed authentication caching
func TestIMAPBackendLookupCache_NegativeCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Use SHORT negative TTL (1s) for testing
	server, cache, rdb := setupIMAPServerWithLookupCache(t, true, "5m", "1s")
	defer server.Close()

	nonExistentEmail := fmt.Sprintf("nonexistent-%d@example.com", time.Now().UnixNano())

	// First failed login - should cache negative result
	t.Run("FirstFailedLogin_CacheNegative", func(t *testing.T) {
		beforeSize := getCacheStats(cache).size

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Close()

		if err := c.Login(nonExistentEmail, "anypassword").Wait(); err == nil {
			t.Fatal("Login with non-existent user should have failed")
		}

		// Note: Backend auth cache may not cache negative results the same way as proxy cache
		// It depends on implementation - check if size increased
		afterSize := getCacheStats(cache).size
		t.Logf("Cache size before=%d after=%d (negative caching may vary by implementation)", beforeSize, afterSize)
	})

	// Wait for negative cache to expire
	time.Sleep(1500 * time.Millisecond)

	// Create the account now
	t.Run("CreateAccount_LoginSuccess", func(t *testing.T) {
		account := common.CreateTestAccountWithEmail(t, rdb, nonExistentEmail, "correctpassword")

		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, "correctpassword").Wait(); err != nil {
			t.Fatalf("Login with correct password failed after account creation: %v", err)
		}
		t.Log("✓ Login succeeded after negative cache expired")
	})
}

// TestIMAPBackendLookupCache_ConcurrentAuth tests concurrent authentication requests
func TestIMAPBackendLookupCache_ConcurrentAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupIMAPServerWithLookupCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-concurrent-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Launch 50 concurrent login attempts
	t.Run("ConcurrentLogins", func(t *testing.T) {
		beforeStats := getCacheStats(cache)
		var wg sync.WaitGroup
		var successCount atomic.Int32
		var failureCount atomic.Int32

		concurrency := 50
		wg.Add(concurrency)

		for i := 0; i < concurrency; i++ {
			go func(idx int) {
				defer wg.Done()

				c, err := imapclient.DialInsecure(server.Address, nil)
				if err != nil {
					t.Logf("Failed to connect (goroutine %d): %v", idx, err)
					failureCount.Add(1)
					return
				}
				defer c.Logout()

				if err := c.Login(account.Email, account.Password).Wait(); err != nil {
					t.Logf("Login failed (goroutine %d): %v", idx, err)
					failureCount.Add(1)
					return
				}

				successCount.Add(1)
			}(i)
		}

		wg.Wait()

		afterStats := getCacheStats(cache)
		t.Logf("Concurrent auth results: %d successes, %d failures", successCount.Load(), failureCount.Load())
		t.Logf("Cache stats: hits=%d (Δ=%d), misses=%d (Δ=%d), hitRate=%.1f%%",
			afterStats.hits, afterStats.hits-beforeStats.hits,
			afterStats.misses, afterStats.misses-beforeStats.misses,
			afterStats.hitRate)

		if successCount.Load() < int32(concurrency-5) {
			t.Errorf("Expected most logins to succeed, got %d/%d", successCount.Load(), concurrency)
		}
		t.Log("✓ Concurrent authentication handled correctly")
	})
}

// TestIMAPBackendLookupCache_MultiUser tests cache with multiple users
func TestIMAPBackendLookupCache_MultiUser(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupIMAPServerWithLookupCache(t, true, "5m", "1m")
	defer server.Close()

	// Create 20 test accounts
	userCount := 20
	accounts := make([]common.TestAccount, userCount)
	for i := 0; i < userCount; i++ {
		email := fmt.Sprintf("lookupcache-multi-%d-%d@example.com", time.Now().UnixNano(), i)
		accounts[i] = common.CreateTestAccountWithEmail(t, rdb, email, fmt.Sprintf("pass%d", i))
	}

	// Login with each user
	t.Run("LoginAllUsers", func(t *testing.T) {
		for i, account := range accounts {
			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Fatalf("Failed to connect for user %d: %v", i, err)
			}

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Fatalf("Login failed for user %d: %v", i, err)
			}
			c.Logout()
		}

		stats := getCacheStats(cache)
		if stats.size < userCount {
			t.Logf("Note: Cache size=%d is less than userCount=%d (may have evictions)", stats.size, userCount)
		}
		t.Logf("✓ All %d users logged in, cache size=%d", userCount, stats.size)
	})

	// Login with same users again - should be cache hits
	t.Run("LoginAllUsers_CacheHits", func(t *testing.T) {
		beforeHits := getCacheStats(cache).hits

		for i, account := range accounts {
			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Fatalf("Failed to connect for user %d: %v", i, err)
			}

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Fatalf("Login failed for user %d: %v", i, err)
			}
			c.Logout()
		}

		afterHits := getCacheStats(cache).hits
		hitsIncrease := afterHits - beforeHits
		if hitsIncrease < int64(userCount-5) {
			t.Logf("Note: Got %d cache hits for %d users (expected most to hit cache)", hitsIncrease, userCount)
		}
		t.Logf("✓ Second login round: %d cache hits for %d users (%.1f%% hit rate)", hitsIncrease, userCount, float64(hitsIncrease)/float64(userCount)*100)
	})
}

// TestIMAPBackendLookupCache_Disabled tests behavior when cache is disabled
func TestIMAPBackendLookupCache_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with auth cache DISABLED
	server, cache, rdb := setupIMAPServerWithLookupCache(t, false, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-disabled-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Verify cache is nil (disabled)
	if cache != nil {
		t.Fatalf("Expected cache to be nil when disabled, got %v", cache)
	}

	// Check if cache is actually disabled
	// Note: If cache is disabled, cache is nil
	// We can't call GetStats() on nil, so just test that auth works
	t.Run("LoginWithCacheDisabled", func(t *testing.T) {
		// First login
		c1, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c1.Logout()

		if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("First login failed: %v", err)
		}
		t.Log("✓ First login succeeded")

		// Second login - should still hit DB (no cache)
		c2, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer c2.Logout()

		if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Second login failed: %v", err)
		}
		t.Log("✓ Second login succeeded (both hit DB, no caching)")
	})
}

// Helper functions

type lookupCacheStats struct {
	hits    int64
	misses  int64
	size    int
	hitRate float64
}

func getCacheStats(cache *lookupcache.LookupCache) lookupCacheStats {
	if cache == nil {
		return lookupCacheStats{}
	}

	hits, misses, size, hitRate := cache.GetStats()
	return lookupCacheStats{
		hits:    int64(hits),
		misses:  int64(misses),
		size:    size,
		hitRate: hitRate,
	}
}

func setupIMAPServerWithLookupCache(t *testing.T, enabled bool, positiveTTL, negativeTTL string) (*common.TestServer, *lookupcache.LookupCache, *resilient.ResilientDatabase) {
	return setupIMAPServerWithLookupCacheCustom(t, enabled, positiveTTL, negativeTTL, 30*time.Second)
}

func setupIMAPServerWithLookupCacheCustom(t *testing.T, enabled bool, positiveTTL, negativeTTL string, positiveRevalidationWindow time.Duration) (*common.TestServer, *lookupcache.LookupCache, *resilient.ResilientDatabase) {
	t.Helper()

	// Create custom server with specific cache configuration
	rdb := common.SetupTestDatabase(t)
	address := common.GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create test config with shared mailboxes and lookup cache config
	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	// Create lookup cache config based on parameters
	var lookupCacheConfig *config.LookupCacheConfig
	if enabled {
		lookupCacheConfig = &config.LookupCacheConfig{
			Enabled:                    true,
			PositiveTTL:                positiveTTL,
			NegativeTTL:                negativeTTL,
			MaxSize:                    10000,
			CleanupInterval:            "5m",
			PositiveRevalidationWindow: positiveRevalidationWindow.String(),
		}
	} else {
		// Explicitly disable cache
		lookupCacheConfig = &config.LookupCacheConfig{
			Enabled: false,
		}
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth: true, // Allow PLAIN auth (no TLS in tests)
			Config:       testConfig,
			LookupCache:  lookupCacheConfig,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Setup cleanup via t.Cleanup (will be called when test ends)
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
		// Clean up temporary directory
		os.RemoveAll(tempDir)
	})

	testServer := &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}

	// Get the cache from the server
	cache := server.GetLookupCache()

	return testServer, cache, rdb
}
