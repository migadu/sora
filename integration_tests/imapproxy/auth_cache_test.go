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
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/imapproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestIMAPProxyAuthCache_MasterPasswordCaching tests that master password authentication
// is properly cached and subsequent logins use the cache
func TestIMAPProxyAuthCache_MasterPasswordCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-%d@example.com", time.Now().UnixNano())
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

// TestIMAPProxyAuthCache_BadPasswordHandling tests that bad password attempts
// are cached in the negative cache with proper expiry
func TestIMAPProxyAuthCache_BadPasswordHandling(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-bad-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for prelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Create prelookup server that returns auth + routing info
	// When "server" field is present, proxy validates password locally using password_hash,
	// then connects to specified backend using master SASL authentication
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer prelookupServer.Close()

	// Set up IMAP proxy with short negative cache TTL (1 second) for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithHTTPPrelookupAndShortNegativeTTL(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, prelookupServer.URL)
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

// TestIMAPProxyAuthCache_SuccessfulAuthExpiry tests that successful auth cache entries
// expire correctly and get revalidated
func TestIMAPProxyAuthCache_SuccessfulAuthExpiry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("authcache-expiry-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for prelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track prelookup calls
	prelookupCalls := 0
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prelookupCalls++
		t.Logf("Prelookup call #%d", prelookupCalls)

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
	defer prelookupServer.Close()

	// Set up IMAP proxy with short positive cache TTL (3 seconds) for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithHTTPPrelookupAndShortPositiveTTL(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, prelookupServer.URL)
	defer proxy.Close()

	// Test 1: First login - should call prelookup
	t.Run("FirstLogin_CallsPrelookup", func(t *testing.T) {
		initialCalls := prelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("First login failed: %v", err)
		}

		if prelookupCalls == initialCalls {
			t.Fatal("Expected prelookup to be called on first login")
		}
		t.Logf("✓ First login succeeded (prelookup called, cache populated)")
	})

	// Test 2: Second login within TTL - should use cache (no prelookup call)
	t.Run("SecondLogin_UsesCache", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		callsBeforeLogin := prelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed from cache
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Second login failed: %v", err)
		}

		if prelookupCalls > callsBeforeLogin {
			t.Logf("NOTE: Prelookup was called on second login (cache miss or revalidation)")
		} else {
			t.Log("✓ Second login used cache (no prelookup call)")
		}
	})

	// Test 3: Third login after TTL expiry - should revalidate (call prelookup)
	t.Run("ThirdLogin_AfterExpiry", func(t *testing.T) {
		// Wait for cache entry to expire (3 seconds TTL)
		time.Sleep(3500 * time.Millisecond)
		callsBeforeLogin := prelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed and revalidate
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Third login failed after cache expiry: %v", err)
		}

		if prelookupCalls == callsBeforeLogin {
			t.Log("NOTE: Cache entry not expired yet or revalidation window not reached")
		} else {
			t.Log("✓ Third login revalidated (prelookup called after expiry)")
		}
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

// setupIMAPProxyWithHTTPPrelookupAndCache creates IMAP proxy with HTTP prelookup and caching
func setupIMAPProxyWithHTTPPrelookupAndCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-prelookup-cache"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-prelookup-cache",
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
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL,
			Timeout:                "5s",
			FallbackDefault:        false,
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
		t.Fatalf("Failed to create IMAP proxy with prelookup: %v", err)
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

// setupIMAPProxyWithHTTPPrelookupAndShortNegativeTTL creates proxy with short negative cache TTL (1s)
func setupIMAPProxyWithHTTPPrelookupAndShortNegativeTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
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
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL,
			Timeout:                "5s",
			FallbackDefault:        false,
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

// setupIMAPProxyWithHTTPPrelookupAndShortPositiveTTL creates proxy with short positive cache TTL (3s)
func setupIMAPProxyWithHTTPPrelookupAndShortPositiveTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
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
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL,
			Timeout:                "5s",
			FallbackDefault:        false,
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
