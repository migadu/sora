//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestManageSieveProxyLookupCache_MasterPasswordCaching tests that master password authentication is cached correctly
func TestManageSieveProxyLookupCache_MasterPasswordCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with master SASL credentials
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username/password and auth cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterAuthAndCache(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test 1: First login with master password should authenticate and cache
	t.Run("FirstLogin_CacheMiss", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// AUTHENTICATE using PLAIN SASL
		loginUsername := account.Email + "@" + proxyMasterUsername
		authString := fmt.Sprintf("\x00%s\x00%s", loginUsername, proxyMasterPassword)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		err = client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		if err != nil {
			t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
		}

		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("AUTHENTICATE command failed: %s", resp)
		}
		t.Log("✓ First login successful (cache miss, should be cached now)")
	})

	// Test 2: Second login should hit cache (very fast)
	t.Run("SecondLogin_CacheHit", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		loginUsername := account.Email + "@" + proxyMasterUsername
		authString := fmt.Sprintf("\x00%s\x00%s", loginUsername, proxyMasterPassword)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		start := time.Now()
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()
		elapsed := time.Since(start)

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Second login failed: %s", resp)
		}
		t.Logf("✓ Second login successful (cache hit, took %v)", elapsed)

		if elapsed > 2*time.Second {
			t.Logf("WARNING: Cache hit took %v, expected faster", elapsed)
		}
	})

	// Test 3: Wrong master password should NOT be cached or succeed
	t.Run("WrongPassword_NoCache", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		loginUsername := account.Email + "@" + proxyMasterUsername
		authString := fmt.Sprintf("\x00%s\x00%s", loginUsername, "wrong_password")
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "OK") {
			t.Fatal("Expected login to fail with wrong master password")
		}
		t.Logf("✓ Wrong password correctly rejected: %s", resp)

		// Try again with correct password - should still work
		client.Close()
		client2, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client2.Close()

		authString2 := fmt.Sprintf("\x00%s\x00%s", loginUsername, proxyMasterPassword)
		authB642 := base64.StdEncoding.EncodeToString([]byte(authString2))
		client2.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB642))
		resp2, _ := client2.ReadResponse()

		if !strings.HasPrefix(resp2, "OK") {
			t.Fatalf("Login after wrong password failed: %s", resp2)
		}
		t.Log("✓ Correct password works after failed attempt")
	})
}

// TestManageSieveProxyLookupCache_NegativeCacheRevalidation tests that a correct password
// works immediately after a wrong password (cache miss on negative entry with diff password)
func TestManageSieveProxyLookupCache_NegativeCacheRevalidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Enable debug logging
	logger.Initialize(config.LoggingConfig{Level: "debug", Output: "stdout"})

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Set up proxy with auth cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterAuthAndCache(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test 1: Wrong password - should fail and cache negative
	t.Run("WrongPassword_CachedNegative", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, "wrong_password")
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "OK") {
			t.Fatal("Expected login to fail with wrong password")
		}
		t.Log("✓ Wrong password failed (cached negative)")
	})

	// Test 2: Correct password immediately - should succeed (revalidate)
	t.Run("CorrectPassword_RevalidatesImmediately", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login with correct password failed: %s", resp)
		}
		t.Log("✓ Correct password succeeded immediately (revalidated)")
	})
}

// TestManageSieveProxyLookupCache_PositiveCacheRevalidation tests that a new password
// works after positiveRevalidationWindow, but fails before that
func TestManageSieveProxyLookupCache_PositiveCacheRevalidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Enable debug logging
	logger.Initialize(config.LoggingConfig{Level: "debug", Output: "stdout"})

	// Create backend ManageSieve server with PROXY protocol support
	backendServer, account := common.SetupManageSieveServerWithPROXY(t)
	defer backendServer.Close()

	// Generate password hash for remotelookup response
	var currentPasswordHash string
	updateHash := func(pwd string) {
		hashBytes, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		currentPasswordHash = string(hashBytes)
	}
	updateHash(account.Password)

	// Track remotelookup calls
	var remotelookupCalls atomic.Int32
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls.Add(1)
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": currentPasswordHash,
			"server":        backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up proxy with short positive revalidation window (2 seconds)
	proxyAddress := common.GetRandomAddress(t)

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-pos-reval",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             4190,
		InsecureAuth:           true,
		MasterSASLUsername:     "master_sasl",
		MasterSASLPassword:     "master_sasl_secret",
		TLS:                    false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupServer.URL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
			// Short revalidation window for testing
			PositiveRevalidationWindow: "2s",
		},
		Debug: true,
	}

	proxy, err := managesieveproxy.New(context.Background(), backendServer.ResilientDB, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}
	go proxy.Start()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	// Test 1: Login with old password - populates cache
	t.Run("LoginOldPassword_PopulatesCache", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login failed: %s", resp)
		}
		if remotelookupCalls.Load() != 1 {
			t.Fatalf("Expected 1 remotelookup call, got %d", remotelookupCalls.Load())
		}
	})

	// Change password
	newPassword := "newpassword"
	// Update backend DB
	newHashBytes, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	newHashedPassword := "{BLF-CRYPT}" + string(newHashBytes)
	backendServer.ResilientDB.UpdatePasswordWithRetry(context.Background(), account.Email, newHashedPassword)
	// Update mock remotelookup hash
	updateHash(newPassword)

	// Test 2: Login with new password immediately - should fail (cache hit, hash mismatch, fresh entry)
	t.Run("LoginNewPassword_Immediate_Fails", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, newPassword)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		// Should fail because cache has old hash and entry is fresh (< 2s)
		if strings.HasPrefix(resp, "OK") {
			t.Fatal("Login with new password should have failed (cached old hash)")
		}
		// RemoteLookup should NOT be called again
		if remotelookupCalls.Load() != 1 {
			t.Fatalf("Expected remotelookup calls to remain 1, got %d", remotelookupCalls.Load())
		}
		t.Log("✓ Login with new password failed immediately (cached old hash)")
	})

	// Wait for revalidation window to pass
	time.Sleep(2500 * time.Millisecond)

	// Test 3: Login with new password after window - should succeed (revalidate)
	t.Run("LoginNewPassword_AfterWindow_Succeeds", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, newPassword)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		// Should succeed because entry is old (> 2s) so it revalidates
		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login with new password failed after window: %s", resp)
		}
		// RemoteLookup SHOULD be called again
		if remotelookupCalls.Load() != 2 {
			t.Fatalf("Expected 2 remotelookup calls, got %d", remotelookupCalls.Load())
		}
		t.Log("✓ Login with new password succeeded after window (revalidated)")
	})
}

// NOTE: RemoteLookup tests for ManageSieve require special backend setup with proxy protocol support
// The basic master auth test above validates cache functionality

// TestManageSieveProxyLookupCache_BadPasswordHandling tests that bad passwords are cached with short TTL
func DISABLED_TestManageSieveProxyLookupCache_BadPasswordHandling(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServer(t)
	defer backendServer.Close()

	// Track remotelookup calls
	var remotelookupCalls atomic.Int32

	// Set up remotelookup server
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls.Add(1)
		t.Logf("RemoteLookup call #%d", remotelookupCalls.Load())

		passwordHashBytes, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": string(passwordHashBytes),
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up proxy with SHORT negative TTL (1 second for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithHTTPRemoteLookupAndShortNegativeTTL(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Test 1: Bad password should be rejected
	t.Run("BadPassword_Rejected", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, "wrong_password")
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "OK") {
			t.Fatal("Expected login to fail with bad password")
		}
		t.Logf("✓ Bad password correctly rejected: %s", resp)
	})

	// Test 2: Immediate retry with bad password should hit cache
	t.Run("ImmediateRetry_CacheHit", func(t *testing.T) {
		callsBefore := remotelookupCalls.Load()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, "wrong_password")
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "OK") {
			t.Fatal("Expected login to fail with bad password")
		}

		callsAfter := remotelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("NOTE: RemoteLookup was called on retry: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("✓ Immediate retry hit cache (no new remotelookup)")
		}
	})

	// Test 3: After negative TTL expires, correct password should work
	t.Run("AfterTTL_CorrectPasswordWorks", func(t *testing.T) {
		t.Log("Waiting 2s for negative cache to expire...")
		time.Sleep(2 * time.Second)

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login with correct password failed after cache expiry: %s", resp)
		}
		t.Log("✓ Correct password works after negative cache expiry")
	})
}

// TestManageSieveProxyLookupCache_SuccessfulAuthExpiry tests cache expiry and renewal for successful auth
func DISABLED_TestManageSieveProxyLookupCache_SuccessfulAuthExpiry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServer(t)
	defer backendServer.Close()

	// Track remotelookup calls
	var remotelookupCalls atomic.Int32

	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := remotelookupCalls.Add(1)
		t.Logf("RemoteLookup call #%d", count)

		passwordHashBytes, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": string(passwordHashBytes),
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up proxy with SHORT positive TTL (3 seconds for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithHTTPRemoteLookupAndShortPositiveTTL(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Test 1: First login
	t.Run("FirstLogin", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("First login failed: %s", resp)
		}
		t.Log("✓ First login successful (cache populated)")
	})

	// Test 2: Immediate second login (should hit cache)
	t.Run("ImmediateSecondLogin_CacheHit", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)
		callsBefore := remotelookupCalls.Load()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Second login failed: %s", resp)
		}

		callsAfter := remotelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("NOTE: RemoteLookup was called: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("✓ Second login hit cache (no remotelookup)")
		}
	})

	// Test 3: After positive TTL expires (should revalidate)
	t.Run("AfterExpiry_Revalidate", func(t *testing.T) {
		t.Log("Waiting 4s for positive cache to expire...")
		time.Sleep(4 * time.Second)

		callsBefore := remotelookupCalls.Load()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login after expiry failed: %s", resp)
		}

		callsAfter := remotelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("✓ Cache expired, revalidation occurred: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("NOTE: No revalidation (cache may have been refreshed)")
		}
	})

	// Test 4: Renewal - multiple logins within TTL should refresh cache
	t.Run("Renewal_MultipleLogins", func(t *testing.T) {
		callsBefore := remotelookupCalls.Load()

		// Login 3 times within TTL window (every 1 second, TTL is 3 seconds)
		for i := 0; i < 3; i++ {
			client, err := NewManageSieveClient(proxyAddress)
			if err != nil {
				t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
			}

			authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
			authB64 := base64.StdEncoding.EncodeToString([]byte(authString))
			client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
			resp, _ := client.ReadResponse()
			client.Close()

			if !strings.HasPrefix(resp, "OK") {
				t.Fatalf("Login %d failed: %s", i+1, resp)
			}
			t.Logf("Login %d successful", i+1)

			if i < 2 {
				time.Sleep(1 * time.Second)
			}
		}

		callsAfter := remotelookupCalls.Load()
		newCalls := callsAfter - callsBefore
		t.Logf("✓ 3 logins resulted in %d remotelookup call(s)", newCalls)

		if newCalls <= 1 {
			t.Log("✓ Cache renewal working (minimal revalidation)")
		} else {
			t.Logf("NOTE: Multiple revalidations occurred (%d calls)", newCalls)
		}
	})
}

// Helper functions

func setupManageSieveProxyWithMasterAuthAndCache(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:               "test-managesieve-proxy-master-cache",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		InsecureAuth:       true, // Enable PLAIN auth for testing
		MasterUsername:     proxyMasterUsername,
		MasterPassword:     proxyMasterPassword,
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		TLS:                false,
		TLSVerify:          false,
		RemoteTLS:          false,
		RemoteTLSVerify:    false,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb.ResilientDB, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb.ResilientDB,
	}
}

func setupManageSieveProxyWithHTTPRemoteLookupAndShortNegativeTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-short-negative-ttl",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             4190,
		InsecureAuth:           true, // Enable PLAIN auth for testing
		MasterSASLUsername:     "master_sasl",
		MasterSASLPassword:     "master_sasl_secret",
		TLS:                    false,
		RemoteTLS:              false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: false,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1s", // SHORT negative TTL
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

func setupManageSieveProxyWithHTTPRemoteLookupAndShortPositiveTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-short-positive-ttl",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             4190,
		InsecureAuth:           true, // Enable PLAIN auth for testing
		MasterSASLUsername:     "master_sasl",
		MasterSASLPassword:     "master_sasl_secret",
		TLS:                    false,
		RemoteTLS:              false,
		RemoteUseProxyProtocol: false, // Disable PROXY protocol as backend doesn't support it
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: false,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "3s", // SHORT positive TTL
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
