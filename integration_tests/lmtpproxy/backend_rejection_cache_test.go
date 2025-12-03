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
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxyBackendRejectionCacheInvalidation tests the critical bug fix for remotelookup routing:
//
// BUG #1: IsRemoteLookupAccount not set from cache
// - When cache returns remotelookup routing info, IsRemoteLookupAccount was not set in UserRoutingInfo
// - This caused the connection manager to allow fallback to consistent hash/round-robin
// - Result: Cached remotelookup routes could randomly route to different backends
//
// BUG #2: No cache invalidation on backend rejection
// - When remotelookup returns backend A, but backend A rejects with "550 User doesn't exist"
// - The stale cache entry pointing to backend A remained
// - Result: Repeated delivery attempts kept routing to the wrong backend until cache expired
//
// This test verifies both fixes work correctly.
func TestLMTPProxyBackendRejectionCacheInvalidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create TWO backend LMTP servers
	backend1, _ := common.SetupLMTPServer(t)
	defer backend1.Close()

	backend2, _ := common.SetupLMTPServer(t)
	defer backend2.Close()

	// Create test account ONLY on backend2
	testEmail := fmt.Sprintf("test-routing-fix-%d@example.com", time.Now().UnixNano())
	_ = common.CreateTestAccountWithEmail(t, backend2.ResilientDB, testEmail, "password123")

	// Track which backend remotelookup returns
	var remoteLookupCalls atomic.Int32
	currentBackend := backend1.Address // Initially return backend1 (WRONG backend - user not there)

	// Mock remotelookup server
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteLookupCalls.Add(1)
		callNum := remoteLookupCalls.Load()

		backend := currentBackend
		t.Logf("RemoteLookup HTTP call #%d: URL=%s, returning backend %s", callNum, r.URL.Path, backend)

		// Return routing response in expected format
		response := map[string]interface{}{
			"address":    testEmail,
			"account_id": 99999, // Dummy account ID
			"server":     backend,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Logf("Failed to encode JSON response: %v", err)
		}
		t.Logf("RemoteLookup response sent: %+v", response)
	}))
	defer remotelookupServer.Close()

	t.Logf("RemoteLookup server URL: %s", remotelookupServer.URL)

	// Create LMTP proxy with BOTH backends available and remotelookup cache
	proxyAddress := common.GetRandomAddress(t)

	opts := lmtpproxy.ServerOptions{
		Name:           "test-routing-proxy",
		Addr:           proxyAddress,
		RemoteAddrs:    []string{backend1.Address, backend2.Address}, // Both backends available
		RemotePort:     0,
		ConnectTimeout: 5 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"}, // Trust localhost
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupServer.URL,
			Timeout:          "5s",
			LookupLocalUsers: false,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "30s",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyServer, err := lmtpproxy.New(ctx, backend1.ResilientDB, "localhost", opts)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go func() {
		if err := proxyServer.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	time.Sleep(500 * time.Millisecond) // Give proxy more time to start

	// Verify proxy is listening
	testConn, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("Proxy not listening on %s after startup: %v", proxyAddress, err)
	}
	testConn.Close()
	t.Logf("Proxy confirmed listening on %s", proxyAddress)

	// Helper to send RCPT TO and get response
	sendRCPT := func(attemptNum int) (string, error) {
		conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
		if err != nil {
			return "", fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()

		// Set read deadline for all operations
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		reader := bufio.NewReader(conn)

		// Read greeting
		greeting, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read greeting failed: %w", err)
		}
		t.Logf("Attempt #%d: Greeting: %s", attemptNum, strings.TrimSpace(greeting))

		// LHLO
		if _, err := fmt.Fprintf(conn, "LHLO localhost\r\n"); err != nil {
			return "", fmt.Errorf("send LHLO failed: %w", err)
		}

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("read LHLO response failed: %w", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		// MAIL FROM
		if _, err := fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n"); err != nil {
			return "", fmt.Errorf("send MAIL FROM failed: %w", err)
		}
		mailResp, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read MAIL FROM response failed: %w", err)
		}
		t.Logf("Attempt #%d: MAIL FROM response: %s", attemptNum, strings.TrimSpace(mailResp))

		// RCPT TO
		if _, err := fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", testEmail); err != nil {
			return "", fmt.Errorf("send RCPT TO failed: %w", err)
		}
		response, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read RCPT TO response failed: %w", err)
		}

		trimmed := strings.TrimSpace(response)
		t.Logf("Attempt #%d: RCPT TO response: %s", attemptNum, trimmed)
		return trimmed, nil
	}

	// ===== TEST SCENARIO =====

	// Attempt 1: RemoteLookup returns backend1, delivery succeeds (user exists in shared DB)
	t.Log("=== Attempt 1: Initial delivery (remotelookup returns backend1) ===")
	resp1, err := sendRCPT(1)
	if err != nil {
		t.Fatalf("Attempt 1 failed: %v", err)
	}

	// Both backends share same database, so delivery succeeds
	if !strings.HasPrefix(resp1, "250") {
		t.Fatalf("Attempt 1 should succeed, got: %s", resp1)
	}
	t.Logf("✓ Attempt 1: Succeeded as expected (user exists in database)")

	// Verify remotelookup was called
	if remoteLookupCalls.Load() != 1 {
		t.Fatalf("Expected 1 remotelookup call, got %d", remoteLookupCalls.Load())
	}

	// NOW delete the user from database to simulate data inconsistency
	t.Log("=== Deleting user from database to simulate data inconsistency ===")
	if err := backend2.ResilientDB.DeleteAccountWithRetry(context.Background(), testEmail); err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}
	t.Logf("✓ User deleted from database")

	// Attempt 2: Cache hit, routes to backend1, but backend rejects (user deleted)
	// With the fix: Proxy detects inconsistency, returns 451, invalidates cache
	t.Log("=== Attempt 2: Delivery with stale cache (backend will reject) ===")
	resp2, err := sendRCPT(2)
	if err != nil {
		t.Fatalf("Attempt 2 failed: %v", err)
	}

	// With the fix, backend rejection triggers cache invalidation and 451 response
	if !strings.HasPrefix(resp2, "451") {
		t.Errorf("Expected 451 (data inconsistency detected), got: %s", resp2)
	} else {
		t.Logf("✓ Attempt 2: Got 451 as expected (data inconsistency detected)")
	}

	// Verify remotelookup was NOT called (cache hit)
	if remoteLookupCalls.Load() != 1 {
		t.Errorf("Expected still 1 remotelookup call (cache hit), got %d", remoteLookupCalls.Load())
	}

	// Change remotelookup to return backend2 (where user was originally created)
	// We don't recreate the user because of deletion grace period
	t.Log("=== Updating remotelookup to return backend2 ===")
	currentBackend = backend2.Address
	t.Logf("RemoteLookup now returns: %s", currentBackend)

	// Attempt 3: With FIX #2, cache was invalidated, should call remotelookup again
	// Backend2 will also reject (user deleted), proving cache was invalidated and fresh remotelookup called
	t.Log("=== Attempt 3: Delivery after cache invalidation (should trigger fresh remotelookup) ===")
	resp3, err := sendRCPT(3)
	if err != nil {
		t.Fatalf("Attempt 3 failed: %v", err)
	}

	// Verify remotelookup was called again (cache was invalidated)
	finalCalls := remoteLookupCalls.Load()
	if finalCalls != 2 {
		t.Errorf("Expected 2 remotelookup calls total (cache invalidation worked), got %d", finalCalls)
		t.Error("BUG: Cache was NOT invalidated - no fresh remotelookup call!")
	} else {
		t.Logf("✓ Verified: Cache invalidated, remotelookup called again")
	}

	// Attempt 3 should also get 451 (backend2 also rejects because user deleted)
	// This proves the fresh remotelookup was called and routed to the NEW backend
	if !strings.HasPrefix(resp3, "451") {
		t.Errorf("Expected 451 (backend2 also rejects), got: %s", resp3)
	} else {
		t.Logf("✓ Attempt 3: Got 451 as expected (routed to backend2 via fresh remotelookup)")
	}

	// Cleanup
	proxyServer.Stop()
	t.Logf("✓ Test passed: Both bug fixes verified!")
}

// TestLMTPProxyRemoteLookupNoFallbackOnCacheHit verifies that BUG #1 is fixed:
// When cache returns a remotelookup entry with ServerAddress, IsRemoteLookupAccount
// must be set to prevent fallback to consistent hash/round-robin.
func TestLMTPProxyRemoteLookupNoFallbackOnCacheHit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create ONE real backend
	realBackend, _ := common.SetupLMTPServer(t)
	defer realBackend.Close()

	testEmail := fmt.Sprintf("test-no-fallback-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, realBackend.ResilientDB, testEmail, "password123")

	// RemoteLookup returns a NON-EXISTENT backend (should fail, no fallback)
	fakeBackend := "192.0.2.1:9999" // TEST-NET-1, unreachable

	var remoteLookupCalls atomic.Int32
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteLookupCalls.Add(1)
		t.Logf("RemoteLookup call #%d: returning FAKE backend %s", remoteLookupCalls.Load(), fakeBackend)

		response := map[string]interface{}{
			"address": account.Email,
			"server":  fakeBackend, // Point to non-existent backend
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Proxy has access to the REAL backend, but remotelookup returns FAKE backend
	proxyAddress := common.GetRandomAddress(t)

	opts := lmtpproxy.ServerOptions{
		Name:           "test-no-fallback-proxy",
		Addr:           proxyAddress,
		RemoteAddrs:    []string{realBackend.Address, fakeBackend}, // Real backend + fake
		RemotePort:     0,
		ConnectTimeout: 2 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"}, // Trust localhost
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupServer.URL,
			Timeout:          "3s",
			LookupLocalUsers: false,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "30s",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyServer, err := lmtpproxy.New(ctx, realBackend.ResilientDB, "localhost", opts)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go proxyServer.Start()
	time.Sleep(200 * time.Millisecond)

	sendRCPT := func(attemptNum int) (string, error) {
		conn, err := net.DialTimeout("tcp", proxyAddress, 3*time.Second)
		if err != nil {
			return "", err
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reader.ReadString('\n')

		fmt.Fprintf(conn, "LHLO localhost\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		reader.ReadString('\n')

		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", testEmail)
		response, _ := reader.ReadString('\n')
		trimmed := strings.TrimSpace(response)
		t.Logf("Attempt #%d: %s", attemptNum, trimmed)
		return trimmed, nil
	}

	// Attempt 1: RemoteLookup returns fake backend, should FAIL (no fallback to real backend)
	resp1, _ := sendRCPT(1)
	if !strings.HasPrefix(resp1, "451") || !strings.Contains(resp1, "Backend connection failed") {
		t.Errorf("Expected 451 backend connection failed (no fallback), got: %s", resp1)
		t.Error("BUG: Proxy fell back to real backend instead of enforcing remotelookup route!")
	} else {
		t.Logf("✓ Attempt 1: Correctly rejected (no fallback to real backend)")
	}

	// Attempt 2: Cache hit should ALSO enforce remotelookup route (verify IsRemoteLookupAccount set)
	resp2, _ := sendRCPT(2)
	if !strings.HasPrefix(resp2, "451") {
		t.Errorf("Expected 451 on cache hit too, got: %s", resp2)
		t.Error("BUG: IsRemoteLookupAccount NOT set from cache - fallback occurred!")
	} else {
		t.Logf("✓ Attempt 2: Cache hit also enforced remotelookup route")
	}

	// Verify only 1 remotelookup call (second was cache hit)
	if remoteLookupCalls.Load() != 1 {
		t.Errorf("Expected 1 remotelookup call, got %d", remoteLookupCalls.Load())
	} else {
		t.Logf("✓ Cache hit confirmed (only 1 remotelookup call)")
	}

	proxyServer.Stop()
	t.Logf("✓ Test passed: IsRemoteLookupAccount preserved from cache!")
}
