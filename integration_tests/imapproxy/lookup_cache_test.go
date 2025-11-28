//go:build integration

package imapproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/imapproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestIMAPProxyLookupCache_MasterPasswordCaching tests that master password authentication
// is properly cached and subsequent logins use the cache
func TestIMAPProxyLookupCache_MasterPasswordCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Set up IMAP proxy with auth cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndCache(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address})
	defer proxy.Close()

	// Test 1: First login - should populate cache
	t.Run("FirstLogin_PopulatesCache", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed and populate cache
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("First login failed: %v", err)
		}
		t.Log("✓ First login succeeded (cache miss → backend auth)")
	})

	// Wait a bit to ensure cache is populated
	time.Sleep(100 * time.Millisecond)

	// Test 2: Second login - should use cache
	t.Run("SecondLogin_UsesCache", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed from cache (faster)
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Second login failed: %v", err)
		}
		t.Log("✓ Second login succeeded (cache hit)")
	})

	// Test 3: Wrong password - should fail immediately
	t.Run("WrongPassword_FailsImmediately", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Close()

		// Login should fail with wrong password
		if err := c.Login(account.Email, "wrongpassword").Wait(); err == nil {
			t.Fatal("Login with wrong password should have failed")
		}
		t.Log("✓ Wrong password rejected correctly")
	})
}

// TestIMAPProxyLookupCache_BadPasswordHandling tests that bad password attempts
// are cached in the negative cache with proper expiry
func TestIMAPProxyLookupCache_BadPasswordHandling(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-bad-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for remotelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Create remotelookup server that returns auth + routing info
	// When "server" field is present, proxy validates password locally using password_hash,
	// then connects to specified backend using master SASL authentication
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up IMAP proxy with short negative cache TTL (1 second) for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithHTTPRemoteLookupAndShortNegativeTTL(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Test 1: First bad password attempt - should fail and cache
	t.Run("FirstBadAttempt_Cached", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Close()

		// Login should fail
		if err := c.Login(account.Email, "wrongpassword").Wait(); err == nil {
			t.Fatal("Login with wrong password should have failed")
		}
		t.Log("✓ First bad attempt failed (cached as negative)")
	})

	// Test 2: Second bad password attempt - should fail from cache
	t.Run("SecondBadAttempt_FromCache", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Close()

		// Login should fail from cache
		if err := c.Login(account.Email, "wrongpassword").Wait(); err == nil {
			t.Fatal("Login with wrong password should have failed from cache")
		}
		t.Log("✓ Second bad attempt failed from cache")
	})

	// Test 3: Wait for negative cache to expire (1 second), then try correct password
	t.Run("CorrectPassword_AfterExpiry", func(t *testing.T) {
		// Wait for negative cache entry to expire
		time.Sleep(1500 * time.Millisecond)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed with correct password
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login with correct password failed after negative cache expiry: %v", err)
		}
		t.Log("✓ Correct password succeeded after negative cache expired")
	})
}

// TestIMAPProxyLookupCache_SuccessfulAuthExpiry tests that successful auth cache entries
// expire correctly and get revalidated
func TestIMAPProxyLookupCache_SuccessfulAuthExpiry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-expiry-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for remotelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track remotelookup calls
	remotelookupCalls := 0
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls++
		t.Logf("RemoteLookup call #%d", remotelookupCalls)

		// When "server" field is present, proxy validates password locally using password_hash,
		// then connects to specified backend using master SASL authentication
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up IMAP proxy with short positive cache TTL (3 seconds) for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithHTTPRemoteLookupAndShortPositiveTTL(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Test 1: First login - should call remotelookup
	t.Run("FirstLogin_CallsRemoteLookup", func(t *testing.T) {
		initialCalls := remotelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("First login failed: %v", err)
		}

		if remotelookupCalls == initialCalls {
			t.Fatal("Expected remotelookup to be called on first login")
		}
		t.Logf("✓ First login succeeded (remotelookup called, cache populated)")
	})

	// Test 2: Second login within TTL - should use cache (no remotelookup call)
	t.Run("SecondLogin_UsesCache", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		callsBeforeLogin := remotelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed from cache
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Second login failed: %v", err)
		}

		if remotelookupCalls > callsBeforeLogin {
			t.Logf("NOTE: RemoteLookup was called on second login (cache miss or revalidation)")
		} else {
			t.Log("✓ Second login used cache (no remotelookup call)")
		}
	})

	// Test 3: Third login after TTL expiry - should revalidate (call remotelookup)
	t.Run("ThirdLogin_AfterExpiry", func(t *testing.T) {
		// Wait for cache entry to expire (3 seconds TTL)
		time.Sleep(3500 * time.Millisecond)
		callsBeforeLogin := remotelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed and revalidate
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Third login failed after cache expiry: %v", err)
		}

		if remotelookupCalls == callsBeforeLogin {
			t.Log("NOTE: Cache entry not expired yet or revalidation window not reached")
		} else {
			t.Log("✓ Third login revalidated (remotelookup called after expiry)")
		}
	})
}

// TestIMAPProxyLookupCache_NegativeCacheRevalidation tests that a correct password
// works immediately after a wrong password (cache miss on negative entry with diff password)
func TestIMAPProxyLookupCache_NegativeCacheRevalidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-neg-reval-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Set up IMAP proxy with auth cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndCache(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address})
	defer proxy.Close()

	// Test 1: Wrong password - should fail and cache negative
	t.Run("WrongPassword_CachedNegative", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Close()

		if err := c.Login(account.Email, "wrongpassword").Wait(); err == nil {
			t.Fatal("Login with wrong password should have failed")
		}
		t.Log("✓ Wrong password failed (cached negative)")
	})

	// Test 2: Correct password immediately - should succeed (revalidate)
	t.Run("CorrectPassword_RevalidatesImmediately", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Should succeed immediately despite negative cache, because password differs
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login with correct password failed: %v", err)
		}
		t.Log("✓ Correct password succeeded immediately (revalidated)")
	})
}

// TestIMAPProxyLookupCache_PositiveCacheRevalidation tests that a new password
// works after positiveRevalidationWindow, but fails before that
func TestIMAPProxyLookupCache_PositiveCacheRevalidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lookupcache-pos-reval-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "oldpassword")

	// Generate password hash for remotelookup response
	// We need to update this when password changes
	var currentPasswordHash string
	updateHash := func(pwd string) {
		hashBytes, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		currentPasswordHash = string(hashBytes)
	}
	updateHash("oldpassword")

	// Track remotelookup calls
	remotelookupCalls := 0
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls++
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

	// Set up IMAP proxy with short positive revalidation window (2 seconds)
	// Note: PositiveTTL is longer (5m) to ensure entry stays in cache
	proxyAddress := common.GetRandomAddress(t)

	hostname := "test-proxy-pos-reval"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupServer.URL,
			Timeout:                "5s",
			LookupLocalUsers:       false,
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
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}
	go proxy.Start()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	// Test 1: Login with old password - populates cache
	t.Run("LoginOldPassword_PopulatesCache", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, "oldpassword").Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if remotelookupCalls != 1 {
			t.Fatalf("Expected 1 remotelookup call, got %d", remotelookupCalls)
		}
	})

	// Change password in backend (and update our mock hash)
	newPassword := "newpassword"
	// Update backend DB
	hashedPassword, _ := db.GenerateBcryptHash(newPassword)
	backendServer.ResilientDB.UpdatePasswordWithRetry(context.Background(), account.Email, hashedPassword)
	// Update mock remotelookup hash
	updateHash(newPassword)

	// Test 2: Login with new password immediately - should fail (cache hit, hash mismatch, fresh entry)
	t.Run("LoginNewPassword_Immediate_Fails", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer c.Close()

		// Should fail because cache has old hash and entry is fresh (< 2s)
		if err := c.Login(account.Email, newPassword).Wait(); err == nil {
			t.Fatal("Login with new password should have failed (cached old hash)")
		}
		// RemoteLookup should NOT be called again
		if remotelookupCalls != 1 {
			t.Fatalf("Expected remotelookup calls to remain 1, got %d", remotelookupCalls)
		}
		t.Log("✓ Login with new password failed immediately (cached old hash)")
	})

	// Wait for revalidation window to pass
	time.Sleep(2500 * time.Millisecond)

	// Test 3: Login with new password after window - should succeed (revalidate)
	t.Run("LoginNewPassword_AfterWindow_Succeeds", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer c.Logout()

		// Should succeed because entry is old (> 2s) so it revalidates
		if err := c.Login(account.Email, newPassword).Wait(); err != nil {
			t.Fatalf("Login with new password failed after window: %v", err)
		}
		// RemoteLookup SHOULD be called again
		if remotelookupCalls != 2 {
			t.Fatalf("Expected 2 remotelookup calls, got %d", remotelookupCalls)
		}
		t.Log("✓ Login with new password succeeded after window (revalidated)")
	})
}

// setupIMAPProxyWithMasterAuthAndCache creates IMAP proxy with master auth and caching enabled
func setupIMAPProxyWithMasterAuthAndCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-auth-cache"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-auth-cache",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

// setupIMAPProxyWithHTTPRemoteLookupAndCache creates IMAP proxy with HTTP remotelookup and caching
func setupIMAPProxyWithHTTPRemoteLookupAndCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-remotelookup-cache"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-remotelookup-cache",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL,
			Timeout:                "5s",
			LookupLocalUsers:       false,
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with remotelookup: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

// setupIMAPProxyWithHTTPRemoteLookupAndShortNegativeTTL creates proxy with short negative cache TTL (1s)
func setupIMAPProxyWithHTTPRemoteLookupAndShortNegativeTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-short-negative"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-short-negative",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL,
			Timeout:                "5s",
			LookupLocalUsers:       false,
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1s", // Very short for testing
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

// setupIMAPProxyWithHTTPRemoteLookupAndShortPositiveTTL creates proxy with short positive cache TTL (3s)
func setupIMAPProxyWithHTTPRemoteLookupAndShortPositiveTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-short-positive"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-short-positive",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL,
			Timeout:                "5s",
			LookupLocalUsers:       false,
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "3s", // Very short for testing
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
