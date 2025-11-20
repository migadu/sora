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
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestManageSieveProxyActualEmailCaching tests that when prelookup returns an "address" field
// (ActualEmail) that differs from the submitted username (e.g., token-based auth),
// the cache stores ActualEmail so cache hits can use the resolved address.
//
// Bug: Cache wasn't storing ActualEmail, so cache hits used submitted username for backend
//
// Expected behavior:
// 1. Login with user@example.com@TOKEN → prelookup returns address="user@example.com"
// 2. Cache key: "user@example.com@TOKEN", Cache value includes ActualEmail="user@example.com"
// 3. Subsequent login with same TOKEN → cache hit, uses stored ActualEmail for backend
func TestManageSieveProxyActualEmailCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with PROXY protocol support
	backendServer, account := common.SetupManageSieveServerWithPROXY(t)
	defer backendServer.Close()

	// Generate password hash for prelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track prelookup calls
	var prelookupCalls atomic.Int32

	// Create prelookup server
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := prelookupCalls.Add(1)
		t.Logf("Prelookup call #%d: %s", count, r.URL.Path)

		response := map[string]interface{}{
			"address":       account.Email, // Resolved email (without token)
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		t.Logf("Prelookup returned address=%s", account.Email)
	}))
	defer prelookupServer.Close()

	// Set up ManageSieve proxy with prelookup
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithPrelookupForActualEmailTest(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, prelookupServer.URL)
	defer proxy.Close()

	// Test 1: Login with token - should populate cache with TOKEN as key, ActualEmail in value
	t.Run("LoginWithToken_PopulatesCache", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// AUTHENTICATE using PLAIN SASL with token
		usernameWithToken := account.Email + "@TOKEN"
		authString := fmt.Sprintf("\x00%s\x00%s", usernameWithToken, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		err = client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		if err != nil {
			t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
		}

		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Login with token failed: %s", resp)
		}
		t.Logf("✓ Login with token succeeded (username=%s@TOKEN, resolved=%s)", account.Email, account.Email)

		callsAfter := prelookupCalls.Load()
		if callsAfter <= callsBefore {
			t.Fatalf("Expected prelookup to be called")
		}
	})

	time.Sleep(200 * time.Millisecond)

	// Test 2: Login with same token - should hit cache and use stored ActualEmail
	t.Run("LoginWithTokenAgain_ShouldHitCache", func(t *testing.T) {
		callsBefore := prelookupCalls.Load()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Login with same username@TOKEN
		usernameWithToken := account.Email + "@TOKEN"
		authString := fmt.Sprintf("\x00%s\x00%s", usernameWithToken, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
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

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Login without TOKEN - this is a different cache key
		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authB64))
		resp, _ := client.ReadResponse()

		if !strings.HasPrefix(resp, "OK") {
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

// setupManageSieveProxyWithPrelookupForActualEmailTest sets up a ManageSieve proxy with prelookup enabled
func setupManageSieveProxyWithPrelookupForActualEmailTest(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-actual-email",
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
