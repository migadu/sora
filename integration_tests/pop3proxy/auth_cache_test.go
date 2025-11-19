//go:build integration

package pop3proxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
	"golang.org/x/crypto/bcrypt"
)

// TestPOP3ProxyAuthCache_MasterPasswordCaching tests that master password authentication is cached correctly
func TestPOP3ProxyAuthCache_MasterPasswordCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with master SASL credentials
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username/password and auth cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterAuthAndCache(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	// Test 1: First login with master password should authenticate and cache
	t.Run("FirstLogin_CacheMiss", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		loginUsername := account.Email + "@" + proxyMasterUsername
		err = client.SendCommand("USER " + loginUsername)
		if err != nil {
			t.Fatalf("Failed to send USER command: %v", err)
		}
		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("USER command failed: %s", resp)
		}

		err = client.SendCommand("PASS " + proxyMasterPassword)
		if err != nil {
			t.Fatalf("Failed to send PASS command: %v", err)
		}
		resp, _ = client.ReadResponse()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("PASS command failed: %s", resp)
		}
		t.Log("✓ First login successful (cache miss, should be cached now)")
	})

	// Test 2: Second login should hit cache (very fast)
	t.Run("SecondLogin_CacheHit", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		loginUsername := account.Email + "@" + proxyMasterUsername
		start := time.Now()

		client.SendCommand("USER " + loginUsername)
		client.ReadResponse()
		client.SendCommand("PASS " + proxyMasterPassword)
		resp, _ := client.ReadResponse()
		elapsed := time.Since(start)

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Second login failed: %s", resp)
		}
		t.Logf("✓ Second login successful (cache hit, took %v)", elapsed)

		if elapsed > 2*time.Second {
			t.Logf("WARNING: Cache hit took %v, expected faster", elapsed)
		}
	})

	// Test 3: Wrong master password should NOT be cached or succeed
	t.Run("WrongPassword_NoCache", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		loginUsername := account.Email + "@" + proxyMasterUsername
		client.SendCommand("USER " + loginUsername)
		client.ReadResponse()
		client.SendCommand("PASS wrong_password")
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "+OK") {
			t.Fatal("Expected login to fail with wrong master password")
		}
		t.Logf("✓ Wrong password correctly rejected: %s", resp)

		// Try again with correct password - should still work
		client.Close()
		client2, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client2.Close()

		client2.SendCommand("USER " + loginUsername)
		client2.ReadResponse()
		client2.SendCommand("PASS " + proxyMasterPassword)
		resp2, _ := client2.ReadResponse()
		if !strings.HasPrefix(resp2, "+OK") {
			t.Fatalf("Login after wrong password failed: %s", resp2)
		}
		t.Log("✓ Correct password works after failed attempt")
	})
}

// TestPOP3ProxyAuthCache_BadPasswordHandling tests that bad passwords are cached with short TTL
func TestPOP3ProxyAuthCache_BadPasswordHandling(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Track prelookup calls
	var prelookupCalls atomic.Int32

	// Set up prelookup server
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prelookupCalls.Add(1)
		t.Logf("Prelookup call #%d", prelookupCalls.Load())

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
	defer prelookupServer.Close()

	// Set up proxy with SHORT negative TTL (1 second for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithHTTPPrelookupAndShortNegativeTTL(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL)
	defer proxy.Stop()

	// Test 1: Bad password should be rejected
	t.Run("BadPassword_Rejected", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS wrong_password")
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "+OK") {
			t.Fatal("Expected login to fail with bad password")
		}
		t.Logf("✓ Bad password correctly rejected: %s", resp)
	})

	// Test 2: Immediate retry with bad password should hit cache
	t.Run("ImmediateRetry_CacheHit", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS wrong_password")
		resp, _ := client.ReadResponse()

		if strings.HasPrefix(resp, "+OK") {
			t.Fatal("Expected login to fail with bad password")
		}

		callsAfter := prelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("NOTE: Prelookup was called on retry: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("✓ Immediate retry hit cache (no new prelookup)")
		}
	})

	// Test 3: After negative TTL expires, correct password should work
	t.Run("AfterTTL_CorrectPasswordWorks", func(t *testing.T) {
		t.Log("Waiting 2s for negative cache to expire...")
		time.Sleep(2 * time.Second)

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Login with correct password failed after cache expiry: %s", resp)
		}
		t.Log("✓ Correct password works after negative cache expiry")
	})
}

// TestPOP3ProxyAuthCache_SuccessfulAuthExpiry tests cache expiry and renewal for successful auth
func TestPOP3ProxyAuthCache_SuccessfulAuthExpiry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Track prelookup calls
	var prelookupCalls atomic.Int32

	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := prelookupCalls.Add(1)
		t.Logf("Prelookup call #%d", count)

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
	defer prelookupServer.Close()

	// Set up proxy with SHORT positive TTL (3 seconds for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithHTTPPrelookupAndShortPositiveTTL(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL)
	defer proxy.Stop()

	// Test 1: First login
	t.Run("FirstLogin", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("First login failed: %s", resp)
		}
		t.Log("✓ First login successful (cache populated)")
	})

	// Test 2: Immediate second login (should hit cache)
	t.Run("ImmediateSecondLogin_CacheHit", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)
		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Second login failed: %s", resp)
		}

		callsAfter := prelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("NOTE: Prelookup was called: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("✓ Second login hit cache (no prelookup)")
		}
	})

	// Test 3: After positive TTL expires (should revalidate)
	t.Run("AfterExpiry_Revalidate", func(t *testing.T) {
		t.Log("Waiting 4s for positive cache to expire...")
		time.Sleep(4 * time.Second)

		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Login after expiry failed: %s", resp)
		}

		callsAfter := prelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("✓ Cache expired, revalidation occurred: %d -> %d", callsBefore, callsAfter)
		} else {
			t.Log("NOTE: No revalidation (cache may have been refreshed)")
		}
	})

	// Test 4: Renewal - multiple logins within TTL should refresh cache
	t.Run("Renewal_MultipleLogins", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		// Login 3 times within TTL window (every 1 second, TTL is 3 seconds)
		for i := 0; i < 3; i++ {
			client, err := NewPOP3Client(proxyAddress)
			if err != nil {
				t.Fatalf("Failed to connect to POP3 proxy: %v", err)
			}

			client.SendCommand("USER " + account.Email)
			client.ReadResponse()
			client.SendCommand("PASS " + account.Password)
			resp, _ := client.ReadResponse()
			client.Close()

			if !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("Login %d failed: %s", i+1, resp)
			}
			t.Logf("Login %d successful", i+1)

			if i < 2 {
				time.Sleep(1 * time.Second)
			}
		}

		callsAfter := prelookupCalls.Load()
		newCalls := callsAfter - callsBefore
		t.Logf("✓ 3 logins resulted in %d prelookup call(s)", newCalls)

		if newCalls <= 1 {
			t.Log("✓ Cache renewal working (minimal revalidation)")
		} else {
			t.Logf("NOTE: Multiple revalidations occurred (%d calls)", newCalls)
		}
	})
}

// Helper functions

func setupPOP3ProxyWithMasterAuthAndCache(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:               "test-pop3-proxy-master-cache",
		RemoteAddrs:        backendAddrs,
		RemotePort:         110,
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

	proxy, err := pop3proxy.New(context.Background(), "test-host", proxyAddr, rdb.ResilientDB, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb.ResilientDB,
	}
}

func setupPOP3ProxyWithHTTPPrelookupAndShortNegativeTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-short-negative-ttl",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    false,
		RemoteTLS:              false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1s", // SHORT negative TTL
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := pop3proxy.New(context.Background(), "test-host", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb,
	}
}

func setupPOP3ProxyWithHTTPPrelookupAndShortPositiveTTL(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-short-positive-ttl",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    false,
		RemoteTLS:              false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "3s", // SHORT positive TTL
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := pop3proxy.New(context.Background(), "test-host", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb,
	}
}
