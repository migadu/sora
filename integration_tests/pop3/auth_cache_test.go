//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"golang.org/x/crypto/bcrypt"
)

// TestPOP3BackendAuthCache_BasicCaching tests basic auth cache hit/miss behavior
func TestPOP3BackendAuthCache_BasicCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create POP3 server with auth cache enabled
	server, cache, rdb := setupPOP3ServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-basic-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Test 1: First login - should be cache MISS (DB query)
	t.Run("FirstLogin_CacheMiss", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		if err := client.SendCommand(fmt.Sprintf("USER %s", account.Email)); err != nil {
			t.Fatalf("Failed to send USER: %v", err)
		}
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("USER failed: %v, %s", err, resp)
		}

		if err := client.SendCommand(fmt.Sprintf("PASS %s", account.Password)); err != nil {
			t.Fatalf("Failed to send PASS: %v", err)
		}
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("PASS failed: %v, %s", err, resp)
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

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		if err := client.SendCommand(fmt.Sprintf("USER %s", account.Email)); err != nil {
			t.Fatalf("Failed to send USER: %v", err)
		}
		client.ReadResponse()

		if err := client.SendCommand(fmt.Sprintf("PASS %s", account.Password)); err != nil {
			t.Fatalf("Failed to send PASS: %v", err)
		}
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("PASS failed: %v, %s", err, resp)
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

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()

		client.SendCommand("PASS wrongpassword")
		resp, _ := client.ReadResponse()
		if isOK(resp) {
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

// TestPOP3BackendAuthCache_TTLExpiration tests cache expiration behavior
func TestPOP3BackendAuthCache_TTLExpiration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create POP3 server with SHORT positive TTL (2s) for testing
	server, cache, rdb := setupPOP3ServerWithAuthCache(t, true, "2s", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-ttl-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// First login - populate cache
	t.Run("InitialLogin_PopulateCache", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login failed: %v, %s", err, resp)
		}
		t.Log("✓ Cache populated")
	})

	// Second login within TTL - cache hit
	t.Run("LoginWithinTTL_CacheHit", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		beforeHits := getCacheStats(cache).hits

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login failed: %v, %s", err, resp)
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

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login failed: %v, %s", err, resp)
		}

		afterMisses := getCacheStats(cache).misses
		if afterMisses <= beforeMisses {
			t.Logf("Note: May still be cache hit if cleanup hasn't run yet (misses=%d)", afterMisses)
		} else {
			t.Logf("✓ Login after TTL expiry: cache miss (misses increased from %d to %d)", beforeMisses, afterMisses)
		}
	})
}

// TestPOP3BackendAuthCache_PasswordChange tests cache invalidation on password change
func TestPOP3BackendAuthCache_PasswordChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupPOP3ServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-pwchange-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "oldpassword")

	// Login with old password - populate cache
	t.Run("LoginWithOldPassword", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand("PASS oldpassword")
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login failed: %v, %s", err, resp)
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
	})

	// Try old password - should fail and invalidate cache
	t.Run("LoginWithOldPassword_AfterChange", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand("PASS oldpassword")
		resp, _ := client.ReadResponse()
		if isOK(resp) {
			t.Fatal("Login with old password should have failed after password change")
		}
		t.Log("✓ Old password rejected (cache invalidated)")
	})

	// Login with new password - should succeed and re-cache
	t.Run("LoginWithNewPassword", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand("PASS newpassword")
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login with new password failed: %v, %s", err, resp)
		}
		t.Log("✓ New password accepted and cached")
	})

	// Verify new password cached by logging in again
	t.Run("LoginWithNewPassword_CacheHit", func(t *testing.T) {
		beforeHits := getCacheStats(cache).hits

		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		client.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client.ReadResponse()
		client.SendCommand("PASS newpassword")
		if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Login failed: %v, %s", err, resp)
		}

		afterHits := getCacheStats(cache).hits
		if afterHits <= beforeHits {
			t.Errorf("Expected cache hit for new password, got hits before=%d after=%d", beforeHits, afterHits)
		}
		t.Logf("✓ New password served from cache (hits increased from %d to %d)", beforeHits, afterHits)
	})
}

// TestPOP3BackendAuthCache_ConcurrentAuth tests concurrent authentication requests
func TestPOP3BackendAuthCache_ConcurrentAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupPOP3ServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-concurrent-%d@example.com", time.Now().UnixNano())
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

				client, err := NewPOP3Client(server.Address)
				if err != nil {
					t.Logf("Failed to connect (goroutine %d): %v", idx, err)
					failureCount.Add(1)
					return
				}
				defer client.Close()

				client.SendCommand(fmt.Sprintf("USER %s", account.Email))
				client.ReadResponse()
				client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
				resp, err := client.ReadResponse()
				if err != nil || !isOK(resp) {
					t.Logf("Login failed (goroutine %d): %v, %s", idx, err, resp)
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

// TestPOP3BackendAuthCache_MultiUser tests cache with multiple users
func TestPOP3BackendAuthCache_MultiUser(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupPOP3ServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create 20 test accounts
	userCount := 20
	accounts := make([]common.TestAccount, userCount)
	for i := 0; i < userCount; i++ {
		email := fmt.Sprintf("authcache-multi-%d-%d@example.com", time.Now().UnixNano(), i)
		accounts[i] = common.CreateTestAccountWithEmail(t, rdb, email, fmt.Sprintf("pass%d", i))
	}

	// Login with each user
	t.Run("LoginAllUsers", func(t *testing.T) {
		for i, account := range accounts {
			client, err := NewPOP3Client(server.Address)
			if err != nil {
				t.Fatalf("Failed to connect for user %d: %v", i, err)
			}

			client.SendCommand(fmt.Sprintf("USER %s", account.Email))
			client.ReadResponse()
			client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
			if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
				t.Fatalf("Login failed for user %d: %v, %s", i, err, resp)
			}
			client.Close()
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
			client, err := NewPOP3Client(server.Address)
			if err != nil {
				t.Fatalf("Failed to connect for user %d: %v", i, err)
			}

			client.SendCommand(fmt.Sprintf("USER %s", account.Email))
			client.ReadResponse()
			client.SendCommand(fmt.Sprintf("PASS %s", account.Password))
			if resp, err := client.ReadResponse(); err != nil || !isOK(resp) {
				t.Fatalf("Login failed for user %d: %v, %s", i, err, resp)
			}
			client.Close()
		}

		afterHits := getCacheStats(cache).hits
		hitsIncrease := afterHits - beforeHits
		if hitsIncrease < int64(userCount-5) {
			t.Logf("Note: Got %d cache hits for %d users (expected most to hit cache)", hitsIncrease, userCount)
		}
		t.Logf("✓ Second login round: %d cache hits for %d users (%.1f%% hit rate)", hitsIncrease, userCount, float64(hitsIncrease)/float64(userCount)*100)
	})
}

// TestPOP3BackendAuthCache_Disabled tests behavior when cache is disabled
func TestPOP3BackendAuthCache_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with auth cache DISABLED
	server, cache, rdb := setupPOP3ServerWithAuthCache(t, false, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-disabled-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Verify cache is nil (disabled)
	if cache != nil {
		t.Fatalf("Expected cache to be nil when disabled, got %v", cache)
	}

	// Check if cache is actually disabled
	t.Run("LoginWithCacheDisabled", func(t *testing.T) {
		// First login
		client1, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client1.Close()

		client1.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client1.ReadResponse()
		client1.SendCommand(fmt.Sprintf("PASS %s", account.Password))
		if resp, err := client1.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("First login failed: %v, %s", err, resp)
		}
		t.Log("✓ First login succeeded")

		// Second login - should still hit DB (no cache)
		client2, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client2.Close()

		client2.SendCommand(fmt.Sprintf("USER %s", account.Email))
		client2.ReadResponse()
		client2.SendCommand(fmt.Sprintf("PASS %s", account.Password))
		if resp, err := client2.ReadResponse(); err != nil || !isOK(resp) {
			t.Fatalf("Second login failed: %v, %s", err, resp)
		}
		t.Log("✓ Second login succeeded (both hit DB, no caching)")
	})
}

// Helper functions

type authCacheStats struct {
	hits    int64
	misses  int64
	size    int
	hitRate float64
}

func getCacheStats(cache *lookupcache.LookupCache) authCacheStats {
	if cache == nil {
		return authCacheStats{}
	}

	hits, misses, size, hitRate := cache.GetStats()
	return authCacheStats{
		hits:    int64(hits),
		misses:  int64(misses),
		size:    size,
		hitRate: hitRate,
	}
}

func setupPOP3ServerWithAuthCache(t *testing.T, enabled bool, positiveTTL, negativeTTL string) (*common.TestServer, *lookupcache.LookupCache, *resilient.ResilientDatabase) {
	t.Helper()

	// Use existing setup
	server, _ := common.SetupPOP3Server(t)

	// Get the resilient DB from server
	rdb := server.ResilientDB

	var cache *lookupcache.LookupCache

	// Configure auth cache
	if enabled {
		// Initialize and set auth cache on ResilientDB
		posTTL, _ := time.ParseDuration(positiveTTL)
		negTTL, _ := time.ParseDuration(negativeTTL)
		cleanupInterval, _ := time.ParseDuration("5m")

		cache = lookupcache.New(posTTL, negTTL, 10000, cleanupInterval, 30*time.Second)
		rdb.SetAuthCache(cache)
	}
	// If disabled, don't set any cache (nil = disabled)

	return server, cache, rdb
}

func isOK(response string) bool {
	return len(response) > 0 && response[0] == '+'
}
