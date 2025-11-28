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

// TestIMAPProxyActualEmailCaching tests that when remotelookup returns an "address" field
// (ActualEmail) that differs from the submitted username (e.g., token-based auth),
// the cache stores ActualEmail so cache hits can use the resolved address.
//
// Bug: Cache wasn't storing ActualEmail, so cache hits used submitted username for backend
//
// Expected behavior:
// 1. Login with user@example.com@TOKEN → remotelookup returns address="user@example.com"
// 2. Cache key: "user@example.com@TOKEN", Cache value includes ActualEmail="user@example.com"
// 3. Subsequent login with same TOKEN → cache hit, uses stored ActualEmail for backend
func TestIMAPProxyActualEmailCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("actualcache-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for remotelookup response
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track remotelookup calls
	var remotelookupCalls int

	// Create remotelookup server that:
	// - Accepts "user@example.com@TOKEN" as username
	// - Returns "user@example.com" as address (ActualEmail)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls++
		t.Logf("RemoteLookup request #%d: %s", remotelookupCalls, r.URL.Path)

		// Return response with different address than queried username
		// This simulates token-based auth where:
		// - Client sends: user@example.com@TOKEN
		// - RemoteLookup resolves to: user@example.com
		response := map[string]interface{}{
			"address":       account.Email, // Resolved email (without token)
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode remotelookup response: %v", err)
		}
		t.Logf("RemoteLookup returned address=%s for token-based auth", account.Email)
	}))
	defer remotelookupServer.Close()

	// Set up IMAP proxy with remotelookup
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithRemoteLookup(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Test 1: Login with token - should populate cache with TOKEN as key, ActualEmail in value
	t.Run("LoginWithToken_PopulatesCache", func(t *testing.T) {
		remotelookupCallsBefore := remotelookupCalls

		// Login with username@TOKEN
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		usernameWithToken := account.Email + "@TOKEN"
		if err := c.Login(usernameWithToken, account.Password).Wait(); err != nil {
			t.Fatalf("Login with token failed: %v", err)
		}
		t.Logf("✓ Login with token succeeded (username=%s, resolved=%s)", usernameWithToken, account.Email)

		// Verify remotelookup was called (first time, cache miss)
		if remotelookupCalls <= remotelookupCallsBefore {
			t.Fatalf("Expected remotelookup to be called, but got %d calls", remotelookupCalls-remotelookupCallsBefore)
		}
	})

	// Wait for cache to settle
	time.Sleep(200 * time.Millisecond)

	// Test 2: Login with TOKEN again - should hit cache, use stored ActualEmail
	t.Run("LoginWithTokenAgain_ShouldHitCache", func(t *testing.T) {
		remotelookupCallsBefore := remotelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		usernameWithToken := account.Email + "@TOKEN"
		if err := c.Login(usernameWithToken, account.Password).Wait(); err != nil {
			t.Fatalf("Login with token (second time) failed: %v", err)
		}
		t.Log("✓ Login with token (second time) succeeded")

		// This SHOULD hit cache (same token as first login)
		remotelookupCallsAfter := remotelookupCalls
		if remotelookupCallsAfter > remotelookupCallsBefore {
			t.Errorf("RemoteLookup was called %d time(s) - cache MISS (expected cache HIT)",
				remotelookupCallsAfter-remotelookupCallsBefore)
			t.Error("Cache should hit for same token")
		} else {
			t.Log("✓ Cache hit with token - using stored ActualEmail")
		}
	})

	// Test 3: Login with resolved email (without token) - WILL call remotelookup (different cache key)
	// This is EXPECTED because cache key is "user@TOKEN", not "user"
	t.Run("LoginWithResolvedEmail_CallsRemoteLookup", func(t *testing.T) {
		remotelookupCallsBefore := remotelookupCalls

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login with resolved email (no token) - this is a DIFFERENT cache key
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login with resolved email failed: %v", err)
		}
		t.Log("✓ Login with resolved email succeeded")

		// This WILL call remotelookup because it's a different cache key
		// This is EXPECTED behavior - each unique username gets its own cache entry
		remotelookupCallsAfter := remotelookupCalls
		if remotelookupCallsAfter > remotelookupCallsBefore {
			t.Logf("NOTE: RemoteLookup was called (expected - different cache key: '%s' vs '%s@TOKEN')",
				account.Email, account.Email)
		}
	})
}

// setupIMAPProxyWithRemoteLookup sets up an IMAP proxy with remotelookup enabled
func setupIMAPProxyWithRemoteLookup(t *testing.T, rdb *resilient.ResilientDatabase, addr string, remoteAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-actual-email",
		Addr:                   addr,
		RemoteAddrs:            remoteAddrs,
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    remotelookupURL + "/$email",
			Timeout:                "10s",
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

	proxy, err := imapproxy.New(context.Background(), rdb, "test-proxy-actual-email", opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy stopped: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     addr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
