//go:build integration

package imapproxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyFallbackToDefaultEnabled tests that when lookup_local_users=true,
// proxy rejects auth when remotelookup has service failures (5xx errors)
// This is NOT a failover mechanism - transient errors always reject
func TestIMAPProxyFallbackToDefaultEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that always returns 500 (simulating service failure)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer remotelookupServer.Close()

	// Set up IMAP proxy with remotelookup enabled and lookup_local_users=true
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
	defer proxy.Close()

	// Test that authentication FAILS (service unavailable, no fallback for 5xx)
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should FAIL because 5xx errors always reject (not a failover mechanism)
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with 5xx error (service unavailable), but it succeeded")
	}
	t.Logf("✓ Login correctly failed with 5xx error (service unavailable): %v", err)
}

// TestIMAPProxyFallbackToDefaultDisabled tests that when lookup_local_users=false,
// proxy still rejects auth when remotelookup has service failures (5xx errors)
// The setting has no effect on transient errors - they always reject
func TestIMAPProxyFallbackToDefaultDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that always returns 500 (simulating service failure)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer remotelookupServer.Close()

	// Set up IMAP proxy with remotelookup enabled and lookup_local_users=false
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, false)
	defer proxy.Close()

	// Test that authentication FAILS (service unavailable, regardless of setting)
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because 5xx errors always reject (setting doesn't matter)
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with 5xx error (service unavailable), but it succeeded")
	}
	t.Logf("✓ Login correctly failed with 5xx error (service unavailable): %v", err)
}

// TestIMAPProxyFallbackUserNotFound tests user-not-found (404) behavior based on lookup_local_users setting
func TestIMAPProxyFallbackUserNotFound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that returns 404 (user not found)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
	}))
	defer remotelookupServer.Close()

	t.Run("FallbackEnabled", func(t *testing.T) {
		// Set up proxy with lookup_local_users=true
		// User-not-found (404) should fall back to main DB
		proxyAddress := common.GetRandomAddress(t)
		proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
		defer proxy.Close()

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed by falling back to main DB
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed when user not found with lookup_local_users=true: %v", err)
		}
		t.Log("✓ Login succeeded when user not found (404) with lookup_local_users=true")
	})

	t.Run("FallbackDisabled", func(t *testing.T) {
		// Set up proxy with lookup_local_users=false
		// User-not-found (404) should reject (remotelookup is authoritative)
		proxyAddress := common.GetRandomAddress(t)
		proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, false)
		defer proxy.Close()

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should fail because lookup is disabled and user not found in remotelookup
		err = c.Login(account.Email, account.Password).Wait()
		if err == nil {
			t.Fatal("Expected login to fail with lookup_local_users=false when user not found (404), but it succeeded")
		}
		t.Logf("✓ Login correctly failed when user not found (404) with lookup_local_users=false: %v", err)
	})
}

// TestIMAPProxyFallback403Forbidden tests that HTTP 403 returns AuthFailed (no fallback)
func TestIMAPProxyFallback403Forbidden(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that returns 403 Forbidden
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
	}))
	defer remotelookupServer.Close()

	// Set up proxy with lookup_local_users=true (shouldn't matter for 403)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
	defer proxy.Close()

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because 403 means AuthFailed (no fallback regardless of setting)
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with HTTP 403 Forbidden, but it succeeded")
	}
	t.Logf("✓ Login correctly failed with HTTP 403 Forbidden (AuthFailed): %v", err)
}

// TestIMAPProxyFallback401Unauthorized tests that HTTP 401 returns AuthFailed (no fallback)
func TestIMAPProxyFallback401Unauthorized(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a remotelookup server that returns 401 Unauthorized
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer remotelookupServer.Close()

	// Set up proxy with lookup_local_users=true (shouldn't matter for 401)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
	defer proxy.Close()

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because 401 means AuthFailed (no fallback regardless of setting)
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with HTTP 401 Unauthorized, but it succeeded")
	}
	t.Logf("✓ Login correctly failed with HTTP 401 Unauthorized (AuthFailed): %v", err)
}

// setupIMAPProxyWithFallback creates IMAP proxy with remotelookup and configurable fallback
func setupIMAPProxyWithFallback(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string, fallbackToDefault bool) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-fallback"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-fallback",
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
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupURL,
			Timeout:          "5s",
			LookupLocalUsers: fallbackToDefault,
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with fallback=%v: %v", fallbackToDefault, err)
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
