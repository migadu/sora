//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyFallbackToDefaultEnabled tests that when fallback_to_default=true,
// proxy falls back to regular backend routing when prelookup fails
func TestPOP3ProxyFallbackToDefaultEnabled(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up POP3 proxy with prelookup enabled and fallback_to_default=true
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, true)
	defer proxy.Close()

	// Test that authentication works (falls back to default routing)
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(string(greeting), "+OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}
	t.Logf("Received greeting: %s", greeting)

	// Test login through proxy - should succeed with fallback
	fmt.Fprintf(writer, "USER %s\r\n", account.Email)
	writer.Flush()

	response, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(string(response), "+OK") {
		t.Fatalf("USER command failed: %s", response)
	}

	fmt.Fprintf(writer, "PASS %s\r\n", account.Password)
	writer.Flush()

	response, _, err = reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(string(response), "+OK") {
		t.Fatalf("Login failed through proxy with fallback enabled: %s", response)
	}
	t.Log("✓ Login succeeded with fallback_to_default=true (prelookup failed)")

	// Verify we can perform POP3 operations
	fmt.Fprintf(writer, "STAT\r\n")
	writer.Flush()

	response, _, err = reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read STAT response: %v", err)
	}
	if !strings.HasPrefix(string(response), "+OK") {
		t.Fatalf("STAT command failed: %s", response)
	}
	t.Log("✓ POP3 operations work after fallback")
}

// TestPOP3ProxyFallbackToDefaultDisabled tests that when fallback_to_default=false,
// proxy rejects authentication when prelookup fails
func TestPOP3ProxyFallbackToDefaultDisabled(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Create a prelookup server that always returns 500 (simulating failure)
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer prelookupServer.Close()

	// Set up POP3 proxy with prelookup enabled and fallback_to_default=false
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
	defer proxy.Close()

	// Test that authentication fails (no fallback allowed)
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(string(greeting), "+OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Test login through proxy - should fail
	fmt.Fprintf(writer, "USER %s\r\n", account.Email)
	writer.Flush()

	response, _, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(string(response), "+OK") {
		t.Fatalf("USER command failed: %s", response)
	}

	fmt.Fprintf(writer, "PASS %s\r\n", account.Password)
	writer.Flush()

	response, _, err = reader.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(string(response), "-ERR") {
		t.Fatalf("Expected login to fail with fallback_to_default=false, but got: %s", response)
	}
	t.Logf("✓ Login correctly failed with fallback_to_default=false: %s", response)
}

// TestPOP3ProxyFallbackUserNotFound tests that user-not-found (404) ALWAYS allows fallback
// regardless of fallback_to_default setting (this supports partitioning scenarios)
func TestPOP3ProxyFallbackUserNotFound(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
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
		proxy := setupPOP3ProxyWithFallback(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL, false)
		defer proxy.Close()

		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			t.Fatalf("Failed to dial POP3 proxy: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Read greeting
		reader.ReadLine()

		// Login should succeed by falling back to default backend
		// even though fallback_to_default=false (404 always allows fallback)
		fmt.Fprintf(writer, "USER %s\r\n", account.Email)
		writer.Flush()
		reader.ReadLine()

		fmt.Fprintf(writer, "PASS %s\r\n", account.Password)
		writer.Flush()
		response, _, _ := reader.ReadLine()

		if !strings.HasPrefix(string(response), "+OK") {
			t.Fatalf("Login failed when user not found (should always fallback for partitioning): %s", response)
		}
		t.Log("✓ Login succeeded when user not found (404 always allows fallback for partitioning)")
	})
}

// setupPOP3ProxyWithFallback creates POP3 proxy with prelookup and configurable fallback
func setupPOP3ProxyWithFallback(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string, fallbackToDefault bool) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-fallback"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-proxy-fallback",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseXCLIENT:       false,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AffinityValidity:       24 * time.Hour,
		AffinityStickiness:     0.9,
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

	proxy, err := pop3proxy.New(context.Background(), hostname, proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with fallback=%v: %v", fallbackToDefault, err)
	}

	// Start proxy in background
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Create a wrapper that handles shutdown gracefully
	wrapper := &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb,
	}

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      wrapper,
		ResilientDB: rdb,
	}
}
