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
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// TestManageSieveProxyFallbackToDefaultEnabled tests that when fallback_to_default=true,
// proxy falls back to regular backend routing when prelookup fails
func TestManageSieveProxyFallbackToDefaultEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up ManageSieve proxy with prelookup enabled and fallback_to_default=true
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, true)
	defer proxy.Close()

	// Test that authentication works (falls back to default routing)
	client, err := NewManageSieveClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
	}
	defer client.Close()

	// Authenticate using PLAIN mechanism
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	authBase64 := base64.StdEncoding.EncodeToString([]byte(authString))

	err = client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authBase64))
	if err != nil {
		t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
	}

	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}

	if !strings.HasPrefix(response, "OK") {
		t.Fatalf("Authentication failed through proxy with fallback enabled: %s", response)
	}
	t.Log("✓ Authentication succeeded with fallback_to_default=true (prelookup failed)")

	// Verify we can perform ManageSieve operations
	err = client.SendCommand("LISTSCRIPTS")
	if err != nil {
		t.Fatalf("Failed to send LISTSCRIPTS command: %v", err)
	}

	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read LISTSCRIPTS response: %v", err)
	}

	if !strings.HasPrefix(response, "OK") {
		t.Fatalf("LISTSCRIPTS command failed: %s", response)
	}
	t.Log("✓ ManageSieve operations work after fallback")
}

// TestManageSieveProxyFallbackToDefaultDisabled tests that when fallback_to_default=false,
// proxy rejects authentication when prelookup fails
func TestManageSieveProxyFallbackToDefaultDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up ManageSieve proxy with prelookup enabled and fallback_to_default=false
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
	defer proxy.Close()

	// Test that authentication fails (no fallback allowed)
	client, err := NewManageSieveClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
	}
	defer client.Close()

	// Authenticate using PLAIN mechanism
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	authBase64 := base64.StdEncoding.EncodeToString([]byte(authString))

	err = client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authBase64))
	if err != nil {
		t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
	}

	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}

	if !strings.HasPrefix(response, "NO") && !strings.HasPrefix(response, "BYE") {
		t.Fatalf("Expected authentication to fail with fallback_to_default=false, but got: %s", response)
	}
	t.Logf("✓ Authentication correctly failed with fallback_to_default=false: %s", response)
}

// TestManageSieveProxyFallbackUserNotFound tests that user-not-found (404) ALWAYS allows fallback
// regardless of fallback_to_default setting (this supports partitioning scenarios)
func TestManageSieveProxyFallbackUserNotFound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
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
		proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
		defer proxy.Close()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Authentication should succeed by falling back to default backend
		// even though fallback_to_default=false (404 always allows fallback)
		authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		authBase64 := base64.StdEncoding.EncodeToString([]byte(authString))

		err = client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authBase64))
		if err != nil {
			t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
		}

		response, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
		}

		if !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed when user not found (should always fallback for partitioning): %s", response)
		}
		t.Log("✓ Authentication succeeded when user not found (404 always allows fallback for partitioning)")
	})
}

// setupManageSieveProxyWithFallback creates ManageSieve proxy with prelookup and configurable fallback
func setupManageSieveProxyWithFallback(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string, fallbackToDefault bool) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-fallback"
	// These MUST match what the backend server expects (from common.SetupManageSieveServerWithMaster)
	masterSASLUsername := "master_sasl"
	masterSASLPassword := "master_sasl_secret"

	opts := managesieveproxy.ServerOptions{
		Name:               "test-proxy-fallback",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		MasterSASLUsername: masterSASLUsername,
		MasterSASLPassword: masterSASLPassword,
		TLS:                false,
		TLSVerify:          false,
		RemoteTLS:          false,
		RemoteTLSVerify:    false,
		InsecureAuth:       true, // Allow authentication over non-TLS for testing
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		EnableAffinity:     true,
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

	proxy, err := managesieveproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy with fallback=%v: %v", fallbackToDefault, err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
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
