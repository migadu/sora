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

// TestIMAPProxyFallbackToDefaultEnabled tests that when fallback_to_default=true,
// proxy falls back to regular backend routing when prelookup fails
func TestIMAPProxyFallbackToDefaultEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up IMAP proxy with prelookup enabled and fallback_to_default=true
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, true)
	defer proxy.Close()

	// Test that authentication works (falls back to default routing)
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should succeed because fallback is enabled
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed through proxy with fallback enabled: %v", err)
	}
	t.Log("✓ Login succeeded with fallback_to_default=true (prelookup failed)")

	// Verify we can perform IMAP operations
	selectCmd := c.Select("INBOX", nil)
	_, err = selectCmd.Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	t.Log("✓ IMAP operations work after fallback")
}

// TestIMAPProxyFallbackToDefaultDisabled tests that when fallback_to_default=false,
// proxy rejects authentication when prelookup fails
func TestIMAPProxyFallbackToDefaultDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up IMAP proxy with prelookup enabled and fallback_to_default=false
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
	defer proxy.Close()

	// Test that authentication fails (no fallback allowed)
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because fallback is disabled and prelookup is failing
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with fallback_to_default=false when prelookup fails, but it succeeded")
	}
	t.Logf("✓ Login correctly failed with fallback_to_default=false: %v", err)
}

// TestIMAPProxyFallbackUserNotFound tests that user-not-found (404) ALWAYS allows fallback
// regardless of fallback_to_default setting (this supports partitioning scenarios)
func TestIMAPProxyFallbackUserNotFound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that returns 404 (user not found)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
	}))
	defer prelookupServer.Close()

	t.Run("AlwaysFallbackEvenWhenDisabled", func(t *testing.T) {
		// Set up proxy with fallback_to_default=false
		// User-not-found should STILL allow fallback (partitioning use case)
		proxyAddress := common.GetRandomAddress(t)
		proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
		defer proxy.Close()

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed by falling back to default backend
		// even though fallback_to_default=false (404 always allows fallback)
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed when user not found (should always fallback for partitioning): %v", err)
		}
		t.Log("✓ Login succeeded when user not found (404 always allows fallback for partitioning)")
	})
}

// TestIMAPProxyFallback403Forbidden tests that HTTP 403 returns AuthFailed (no fallback)
func TestIMAPProxyFallback403Forbidden(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that returns 403 Forbidden
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
	}))
	defer prelookupServer.Close()

	// Set up proxy with fallback_to_default=true (shouldn't matter for 403)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, true)
	defer proxy.Close()

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because 403 means AuthFailed (not user not found)
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

	// Create a prelookup server that returns 401 Unauthorized
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer prelookupServer.Close()

	// Set up proxy with fallback_to_default=true (shouldn't matter for 401)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, true)
	defer proxy.Close()

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Login should fail because 401 means AuthFailed (not user not found)
	err = c.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("Expected login to fail with HTTP 401 Unauthorized, but it succeeded")
	}
	t.Logf("✓ Login correctly failed with HTTP 401 Unauthorized (AuthFailed): %v", err)
}

// setupIMAPProxyWithFallback creates IMAP proxy with prelookup and configurable fallback
func setupIMAPProxyWithFallback(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string, fallbackToDefault bool) *common.TestServer {
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
		PreLookup: &config.PreLookupConfig{
			Enabled:         true,
			URL:             prelookupURL,
			Timeout:         "5s",
			FallbackDefault: fallbackToDefault,
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
