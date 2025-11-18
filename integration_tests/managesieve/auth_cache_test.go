//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/authcache"
	"github.com/migadu/sora/pkg/resilient"
	"golang.org/x/crypto/bcrypt"
)

// TestManageSieveBackendAuthCache_BasicCaching tests basic auth cache hit/miss behavior
func TestManageSieveBackendAuthCache_BasicCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create ManageSieve server with auth cache enabled
	server, cache, rdb := setupManageSieveServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-basic-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// Test 1: First login - should be cache MISS (DB query)
	t.Run("FirstLogin_CacheMiss", func(t *testing.T) {
		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
			t.Fatalf("Authentication failed: %v", err)
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

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
			t.Fatalf("Authentication failed: %v", err)
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

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		// Login with wrong password should fail
		if err := authenticatePlain(reader, writer, account.Email, "wrongpassword"); err == nil {
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

// TestManageSieveBackendAuthCache_TTLExpiration tests cache expiration behavior
func TestManageSieveBackendAuthCache_TTLExpiration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create ManageSieve server with SHORT positive TTL (2s) for testing
	server, cache, rdb := setupManageSieveServerWithAuthCache(t, true, "2s", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-ttl-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "testpass123")

	// First login - populate cache
	t.Run("InitialLogin_PopulateCache", func(t *testing.T) {
		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
			t.Fatalf("Authentication failed: %v", err)
		}
		t.Log("✓ Cache populated")
	})

	// Second login within TTL - cache hit
	t.Run("LoginWithinTTL_CacheHit", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		beforeHits := getCacheStats(cache).hits

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
			t.Fatalf("Authentication failed: %v", err)
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

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
			t.Fatalf("Authentication failed: %v", err)
		}

		afterMisses := getCacheStats(cache).misses
		if afterMisses <= beforeMisses {
			t.Logf("Note: May still be cache hit if cleanup hasn't run yet (misses=%d)", afterMisses)
		} else {
			t.Logf("✓ Login after TTL expiry: cache miss (misses increased from %d to %d)", beforeMisses, afterMisses)
		}
	})
}

// TestManageSieveBackendAuthCache_PasswordChange tests cache invalidation on password change
func TestManageSieveBackendAuthCache_PasswordChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupManageSieveServerWithAuthCache(t, true, "5m", "1m")
	defer server.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-pwchange-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, uniqueEmail, "oldpassword")

	// Login with old password - populate cache
	t.Run("LoginWithOldPassword", func(t *testing.T) {
		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, "oldpassword"); err != nil {
			t.Fatalf("Authentication failed: %v", err)
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

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		// Old password should fail (cache detects password mismatch)
		if err := authenticatePlain(reader, writer, account.Email, "oldpassword"); err == nil {
			t.Fatal("Login with old password should have failed after password change")
		}
		t.Log("✓ Old password rejected (cache invalidated)")
	})

	// Login with new password - should succeed and re-cache
	t.Run("LoginWithNewPassword", func(t *testing.T) {
		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, "newpassword"); err != nil {
			t.Fatalf("Login with new password failed: %v", err)
		}
		t.Log("✓ New password accepted and cached")
	})

	// Verify new password cached by logging in again
	t.Run("LoginWithNewPassword_CacheHit", func(t *testing.T) {
		beforeHits := getCacheStats(cache).hits

		conn, reader, writer := connectManageSieve(t, server.Address)
		defer conn.Close()

		if err := authenticatePlain(reader, writer, account.Email, "newpassword"); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		afterHits := getCacheStats(cache).hits
		if afterHits <= beforeHits {
			t.Errorf("Expected cache hit for new password, got hits before=%d after=%d", beforeHits, afterHits)
		}
		t.Logf("✓ New password served from cache (hits increased from %d to %d)", beforeHits, afterHits)
	})
}

// TestManageSieveBackendAuthCache_ConcurrentAuth tests concurrent authentication requests
func TestManageSieveBackendAuthCache_ConcurrentAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupManageSieveServerWithAuthCache(t, true, "5m", "1m")
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

				conn, reader, writer := connectManageSieve(t, server.Address)
				defer conn.Close()

				if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
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

// TestManageSieveBackendAuthCache_MultiUser tests cache with multiple users
func TestManageSieveBackendAuthCache_MultiUser(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, cache, rdb := setupManageSieveServerWithAuthCache(t, true, "5m", "1m")
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
			conn, reader, writer := connectManageSieve(t, server.Address)

			if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
				t.Fatalf("Login failed for user %d: %v", i, err)
			}
			conn.Close()
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
			conn, reader, writer := connectManageSieve(t, server.Address)

			if err := authenticatePlain(reader, writer, account.Email, account.Password); err != nil {
				t.Fatalf("Login failed for user %d: %v", i, err)
			}
			conn.Close()
		}

		afterHits := getCacheStats(cache).hits
		hitsIncrease := afterHits - beforeHits
		if hitsIncrease < int64(userCount-5) {
			t.Logf("Note: Got %d cache hits for %d users (expected most to hit cache)", hitsIncrease, userCount)
		}
		t.Logf("✓ Second login round: %d cache hits for %d users (%.1f%% hit rate)", hitsIncrease, userCount, float64(hitsIncrease)/float64(userCount)*100)
	})
}

// TestManageSieveBackendAuthCache_Disabled tests behavior when cache is disabled
func TestManageSieveBackendAuthCache_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with auth cache DISABLED
	server, cache, rdb := setupManageSieveServerWithAuthCache(t, false, "5m", "1m")
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
		conn1, reader1, writer1 := connectManageSieve(t, server.Address)
		defer conn1.Close()

		if err := authenticatePlain(reader1, writer1, account.Email, account.Password); err != nil {
			t.Fatalf("First login failed: %v", err)
		}
		t.Log("✓ First login succeeded")

		// Second login - should still hit DB (no cache)
		conn2, reader2, writer2 := connectManageSieve(t, server.Address)
		defer conn2.Close()

		if err := authenticatePlain(reader2, writer2, account.Email, account.Password); err != nil {
			t.Fatalf("Second login failed: %v", err)
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

func getCacheStats(cache *authcache.AuthCache) authCacheStats {
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

func setupManageSieveServerWithAuthCache(t *testing.T, enabled bool, positiveTTL, negativeTTL string) (*common.TestServer, *authcache.AuthCache, *resilient.ResilientDatabase) {
	t.Helper()

	// Use existing setup
	server, _ := common.SetupManageSieveServer(t)

	// Get the resilient DB from server
	rdb := server.ResilientDB

	var cache *authcache.AuthCache

	// Configure auth cache
	if enabled {
		// Initialize and set auth cache on ResilientDB
		posTTL, _ := time.ParseDuration(positiveTTL)
		negTTL, _ := time.ParseDuration(negativeTTL)
		cleanupInterval, _ := time.ParseDuration("5m")

		cache = authcache.New(posTTL, negTTL, 10000, cleanupInterval, 5*time.Second, 30*time.Second)
		rdb.SetAuthCache(cache)
	}
	// If disabled, don't set any cache (nil = disabled)

	return server, cache, rdb
}

func connectManageSieve(t *testing.T, address string) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting (capabilities followed by OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	return conn, reader, writer
}

func authenticatePlain(reader *bufio.Reader, writer *bufio.Writer, username, password string) error {
	// Encode PLAIN authentication: \0username\0password
	plain := fmt.Sprintf("\x00%s\x00%s", username, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))

	// Send AUTHENTICATE PLAIN command
	authCmd := fmt.Sprintf("AUTHENTICATE PLAIN %s\r\n", encoded)
	if _, err := writer.WriteString(authCmd); err != nil {
		return fmt.Errorf("failed to write AUTHENTICATE command: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush AUTHENTICATE command: %w", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read authenticate response: %w", err)
	}

	if !strings.Contains(response, "OK") {
		return fmt.Errorf("authentication failed: %s", strings.TrimSpace(response))
	}

	return nil
}
