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

// TestPOP3ProxyActualEmailCaching tests that when prelookup returns an "address" field
// (ActualEmail) that differs from the submitted username (e.g., token-based auth),
// the cache stores ActualEmail so cache hits can use the resolved address.
//
// Bug: Cache wasn't storing ActualEmail, so cache hits used submitted username for backend
//
// Expected behavior:
// 1. Login with user@example.com@TOKEN → prelookup returns address="user@example.com"
// 2. Cache key: "user@example.com@TOKEN", Cache value includes ActualEmail="user@example.com"
// 3. Subsequent login with same TOKEN → cache hit, uses stored ActualEmail for backend
func TestPOP3ProxyActualEmailCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Generate password hash for prelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track prelookup calls
	var prelookupCalls atomic.Int32

	// Create prelookup server that returns a resolved address different from the queried username
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := prelookupCalls.Add(1)
		t.Logf("Prelookup call #%d: %s", count, r.URL.Path)

		// Return resolved address (without TOKEN suffix) in the response
		response := map[string]interface{}{
			"address":       account.Email, // This is the resolved/actual email
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		t.Logf("Prelookup returned address=%s", account.Email)
	}))
	defer prelookupServer.Close()

	// Set up POP3 proxy with prelookup
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPrelookupForActualEmailTest(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, prelookupServer.URL)
	defer proxy.Stop()

	// Test 1: Login with token - should populate cache with TOKEN as key, ActualEmail in value
	t.Run("LoginWithToken_PopulatesCache", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Login with username@TOKEN
		usernameWithToken := account.Email + "@TOKEN"
		err = client.SendCommand("USER " + usernameWithToken)
		if err != nil {
			t.Fatalf("Failed to send USER command: %v", err)
		}
		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("USER command failed: %s", resp)
		}

		err = client.SendCommand("PASS " + account.Password)
		if err != nil {
			t.Fatalf("Failed to send PASS command: %v", err)
		}
		resp, _ = client.ReadResponse()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Login with token failed: %s", resp)
		}
		t.Logf("✓ Login with token succeeded (username=%s@TOKEN, resolved=%s)", account.Email, account.Email)

		callsAfter := prelookupCalls.Load()
		if callsAfter <= callsBefore {
			t.Fatalf("Expected prelookup to be called, but it wasn't")
		}
	})

	time.Sleep(200 * time.Millisecond)

	// Test 2: Login with same token - should hit cache and use stored ActualEmail
	t.Run("LoginWithTokenAgain_ShouldHitCache", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Login with same username@TOKEN
		usernameWithToken := account.Email + "@TOKEN"
		client.SendCommand("USER " + usernameWithToken)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Second login with token failed: %s", resp)
		}
		t.Log("✓ Login with token (second time) succeeded")

		callsAfter := prelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Errorf("Prelookup was called %d time(s) - cache MISS (expected cache HIT)",
				callsAfter-callsBefore)
		} else {
			t.Log("✓ Cache hit with token - using stored ActualEmail")
		}
	})

	// Test 3: Login with resolved email (without token) - will call prelookup (different cache key)
	t.Run("LoginWithResolvedEmail_CallsPrelookup", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Login without TOKEN - this is a different cache key
		client.SendCommand("USER " + account.Email)
		client.ReadResponse()
		client.SendCommand("PASS " + account.Password)
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("Login with resolved email failed: %s", resp)
		}
		t.Log("✓ Login with resolved email succeeded")

		callsAfter := prelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Logf("NOTE: Prelookup was called (expected - different cache key: '%s' vs '%s@TOKEN')",
				account.Email, account.Email)
		}
	})
}

// setupPOP3ProxyWithPrelookupForActualEmailTest sets up a POP3 proxy with prelookup enabled
func setupPOP3ProxyWithPrelookupForActualEmailTest(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-actual-email",
		Debug:                  true,
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
