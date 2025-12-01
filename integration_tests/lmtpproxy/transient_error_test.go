//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxyRemoteLookupTransientError verifies that transient errors from remotelookup
// result in temporary failure (451) instead of permanent failure (550)
func TestLMTPProxyRemoteLookupTransientError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lmtpcache-transient-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Track remotelookup state - first returns success, then fails with transient error
	var remotelookupCalls int32
	shouldFail := atomic.Bool{}
	shouldFail.Store(false) // Start with success

	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&remotelookupCalls, 1)

		if shouldFail.Load() {
			// Simulate transient error (network failure, timeout, 5xx, etc.)
			// Return 500 Internal Server Error
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}

		// Return success
		response := map[string]interface{}{
			"address": account.Email,
			"server":  backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up LMTP proxy with remotelookup and cache (short TTL for testing)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithRemoteLookupAndShortCache(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Helper to check RCPT TO response
	checkRCPT := func() (string, error) {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			return "", fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send LHLO
		fmt.Fprintf(conn, "LHLO localhost\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		// Send MAIL FROM
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		reader.ReadString('\n')

		// Send RCPT TO and capture response
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", uniqueEmail)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read RCPT TO response failed: %w", err)
		}
		return strings.TrimSpace(line), nil
	}

	// Test 1: First delivery - remotelookup succeeds, caches result
	response, err := checkRCPT()
	if err != nil {
		t.Fatalf("First delivery failed: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("First delivery should succeed, got: %s", response)
	}
	if atomic.LoadInt32(&remotelookupCalls) != 1 {
		t.Fatalf("Expected 1 remotelookup call, got %d", atomic.LoadInt32(&remotelookupCalls))
	}
	t.Log("✓ First delivery succeeded (remotelookup succeeded, result cached)")

	// Test 2: Second delivery within cache TTL - uses cache (no remotelookup call)
	response, err = checkRCPT()
	if err != nil {
		t.Fatalf("Second delivery failed: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Second delivery should succeed from cache, got: %s", response)
	}
	if atomic.LoadInt32(&remotelookupCalls) != 1 {
		t.Fatalf("Expected remotelookup calls to remain 1 (cache hit), got %d", atomic.LoadInt32(&remotelookupCalls))
	}
	t.Log("✓ Second delivery succeeded (cache hit, no remotelookup)")

	// Wait for cache to expire (TTL is 2 seconds in setupLMTPProxyWithRemoteLookupAndShortCache)
	t.Log("Waiting for cache to expire...")
	time.Sleep(3 * time.Second)

	// Test 3: Enable transient error in remotelookup
	shouldFail.Store(true)

	// Third delivery after cache expiration - remotelookup fails with transient error
	response, err = checkRCPT()
	if err != nil {
		t.Fatalf("Third delivery failed to connect: %v", err)
	}

	// Verify the response code
	if strings.HasPrefix(response, "550") {
		t.Errorf("BUG CONFIRMED: Transient remotelookup error returned permanent failure 550")
		t.Errorf("Response: %s", response)
		t.Errorf("Expected: 451 4.x.x (temporary failure)")
		t.Errorf("Got: %s (permanent failure)", response)
		t.Log("This is the bug we're testing for - transient errors should return 451, not 550")
	} else if strings.HasPrefix(response, "451") || strings.HasPrefix(response, "4") {
		t.Log("✓ Third delivery correctly returned temporary failure (451)")
	} else {
		t.Errorf("Unexpected response: %s (expected 451 or 550)", response)
	}

	// Verify remotelookup was called again after cache expiration
	if atomic.LoadInt32(&remotelookupCalls) != 2 {
		t.Errorf("Expected 2 remotelookup calls (initial + after cache expiry), got %d", atomic.LoadInt32(&remotelookupCalls))
	}
}

// TestLMTPProxyCacheExpirationWithTransientError tests the race condition where:
// 1. User is cached successfully
// 2. Cache expires
// 3. Next lookup triggers remotelookup
// 4. Remotelookup has transient error
// 5. Should return 451, but currently returns 550
func TestLMTPProxyCacheExpirationWithTransientError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("cache-expiry-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Track remotelookup state
	var callCount int32
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)

		if count == 1 {
			// First call: Success - cache will be populated
			response := map[string]interface{}{
				"address": account.Email,
				"server":  backendServer.Address,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		} else {
			// Subsequent calls after cache expiry: Transient error
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service Unavailable"))
		}
	}))
	defer remotelookupServer.Close()

	// Set up LMTP proxy with very short cache TTL (2 seconds)
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithRemoteLookupAndShortCache(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Helper to check RCPT TO response code
	checkRCPTCode := func() (string, error) {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			return "", fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)

		reader.ReadString('\n') // greeting
		fmt.Fprintf(conn, "LHLO localhost\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		reader.ReadString('\n')
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", uniqueEmail)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	// Phase 1: Initial successful lookup (populates cache)
	response, err := checkRCPTCode()
	if err != nil {
		t.Fatalf("Phase 1 failed: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Phase 1: Expected 250, got: %s", response)
	}
	t.Logf("✓ Phase 1: User lookup succeeded (remotelookup called, cached)")

	// Phase 2: Lookup within cache TTL (should use cache, no remotelookup)
	response, err = checkRCPTCode()
	if err != nil {
		t.Fatalf("Phase 2 failed: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Phase 2: Expected 250 from cache, got: %s", response)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("Phase 2: Expected 1 remotelookup call (cache hit), got %d", atomic.LoadInt32(&callCount))
	}
	t.Logf("✓ Phase 2: User lookup succeeded from cache (no remotelookup)")

	// Phase 3: Wait for cache expiration
	t.Log("Waiting for cache to expire (3 seconds)...")
	time.Sleep(3 * time.Second)

	// Phase 4: Lookup after cache expiration with transient remotelookup error
	response, err = checkRCPTCode()
	if err != nil {
		t.Fatalf("Phase 4 failed: %v", err)
	}

	// This is the critical test: What response code do we get?
	if strings.HasPrefix(response, "550") {
		t.Errorf("❌ BUG CONFIRMED: Cache expiration + transient error = 550 (permanent failure)")
		t.Errorf("   Response: %s", response)
		t.Errorf("   Expected: 451 4.x.x Service temporarily unavailable")
		t.Errorf("   Problem: User exists and was previously cached, but cache expired.")
		t.Errorf("            Remotelookup has transient error (503), but proxy returns 550.")
		t.Errorf("            This causes senders to give up instead of retrying.")
	} else if strings.HasPrefix(response, "451") || strings.HasPrefix(response, "4") {
		t.Logf("✓ Phase 4: Correctly returned temporary failure: %s", response)
	} else {
		t.Errorf("Phase 4: Unexpected response: %s", response)
	}

	// Verify remotelookup was called again
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("Expected 2 remotelookup calls, got %d", atomic.LoadInt32(&callCount))
	}
}

// setupLMTPProxyWithRemoteLookupAndShortCache creates LMTP proxy with remotelookup and very short cache TTL
func setupLMTPProxyWithRemoteLookupAndShortCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-lmtp-short-cache"
	opts := lmtpproxy.ServerOptions{
		Name:           hostname,
		Addr:           proxyAddr,
		RemoteAddrs:    backendAddrs,
		RemotePort:     0,
		ConnectTimeout: 10 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupURL,
			Timeout:          "5s",
			LookupLocalUsers: false, // Don't fallback to DB on remotelookup failure
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "2s", // Very short TTL for testing cache expiration
			NegativeTTL:     "1s",
			MaxSize:         10000,
			CleanupInterval: "1s",
		},
	}

	proxy, err := lmtpproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
