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

// TestManageSieveProxyFallbackToDefaultEnabled tests that when lookup_local_users=true,
// proxy still rejects auth when remotelookup has service failures (5xx errors)
// This is NOT a failover mechanism - transient errors always reject
func TestManageSieveProxyFallbackToDefaultEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create a remotelookup server that always returns 500 (simulating service failure)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer remotelookupServer.Close()

	// Set up ManageSieve proxy with remotelookup enabled and lookup_local_users=true
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
	defer proxy.Close()

	// Test that authentication FAILS (service unavailable, no fallback for 5xx)
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

	if strings.HasPrefix(response, "OK") {
		t.Fatalf("Expected authentication to fail with 5xx error (service unavailable), but it succeeded: %s", response)
	}
	t.Logf("✓ Authentication correctly failed with 5xx error (service unavailable): %s", response)
}

// TestManageSieveProxyFallbackToDefaultDisabled tests that when lookup_local_users=false,
// proxy still rejects auth when remotelookup has service failures (5xx errors)
// The setting has no effect on transient errors - they always reject
func TestManageSieveProxyFallbackToDefaultDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create a remotelookup server that always returns 500 (simulating failure)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer remotelookupServer.Close()

	// Set up ManageSieve proxy with remotelookup enabled and lookup_local_users=false
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, false)
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
		t.Fatalf("Expected authentication to fail with lookup_local_users=false, but got: %s", response)
	}
	t.Logf("✓ Authentication correctly failed with lookup_local_users=false: %s", response)
}

// TestManageSieveProxyFallbackUserNotFound tests user-not-found (404) behavior based on lookup_local_users setting
func TestManageSieveProxyFallbackUserNotFound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create a remotelookup server that returns 404 (user not found)
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
	}))
	defer remotelookupServer.Close()

	t.Run("FallbackEnabled", func(t *testing.T) {
		// Set up proxy with lookup_local_users=true
		proxyAddress := common.GetRandomAddress(t)
		proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, true)
		defer proxy.Close()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Authentication should succeed by falling back to main DB
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
			t.Fatalf("Authentication failed when user not found with fallback enabled: %s", response)
		}
		t.Log("✓ Authentication succeeded when user not found with lookup_local_users=true")
	})

	t.Run("FallbackDisabled", func(t *testing.T) {
		// Set up proxy with lookup_local_users=false
		proxyAddress := common.GetRandomAddress(t)
		proxy := setupManageSieveProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL, false)
		defer proxy.Close()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Authentication should fail because fallback is disabled
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

		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail with lookup_local_users=false when user not found, but it succeeded")
		}
		t.Logf("✓ Authentication correctly failed when user not found with lookup_local_users=false: %s", response)
	})
}

// setupManageSieveProxyWithFallback creates ManageSieve proxy with remotelookup and configurable fallback
func setupManageSieveProxyWithFallback(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string, fallbackToDefault bool) *common.TestServer {
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
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupURL,
			Timeout:          "5s",
			LookupLocalUsers: fallbackToDefault,
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
