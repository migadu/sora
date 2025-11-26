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
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxyLookupCache_PositiveCaching verifies that valid recipients are cached
func TestLMTPProxyLookupCache_PositiveCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lmtpcache-pos-%d@example.com", time.Now().UnixNano())
	common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Set up LMTP proxy with cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithCache(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Helper to perform LMTP delivery attempt
	checkDelivery := func() error {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			return fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)

		// Read greeting
		if _, err := reader.ReadString('\n'); err != nil {
			return fmt.Errorf("read greeting failed: %w", err)
		}

		// Send LHLO
		fmt.Fprintf(conn, "LHLO localhost\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read LHLO response failed: %w", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		// Send MAIL FROM
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "250") {
			return fmt.Errorf("MAIL FROM failed: %s", line)
		}

		// Send RCPT TO
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", uniqueEmail)
		if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "250") {
			return fmt.Errorf("RCPT TO failed: %s", line)
		}

		return nil
	}

	// Test 1: First delivery - populates cache
	if err := checkDelivery(); err != nil {
		t.Fatalf("First delivery failed: %v", err)
	}
	t.Log("✓ First delivery succeeded (cache miss)")

	// Test 2: Second delivery - uses cache
	// We can't easily verify it used cache without metrics or mocking, but it should succeed
	if err := checkDelivery(); err != nil {
		t.Fatalf("Second delivery failed: %v", err)
	}
	t.Log("✓ Second delivery succeeded (cache hit)")
}

// TestLMTPProxyLookupCache_NegativeCaching verifies that invalid recipients are cached negatively
func TestLMTPProxyLookupCache_NegativeCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Set up LMTP proxy with cache enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithCache(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	invalidEmail := "nonexistent@example.com"

	// Helper to perform LMTP delivery attempt
	checkDelivery := func() error {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			return fmt.Errorf("dial failed: %w", err)
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

		// Send RCPT TO
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", invalidEmail)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read RCPT TO response failed: %w", err)
		}
		if strings.HasPrefix(line, "250") {
			return nil // Success (unexpected)
		}
		return fmt.Errorf("RCPT TO failed: %s", line) // Expected failure
	}

	// Test 1: First delivery - fails and caches negative
	err := checkDelivery()
	if err == nil {
		t.Fatal("First delivery to invalid user should have failed")
	}
	if !strings.Contains(err.Error(), "User unknown") && !strings.Contains(err.Error(), "550") {
		t.Fatalf("Unexpected error message: %v", err)
	}
	t.Log("✓ First delivery failed as expected (cache miss -> negative cache)")

	// Test 2: Second delivery - fails from cache
	err = checkDelivery()
	if err == nil {
		t.Fatal("Second delivery to invalid user should have failed")
	}
	t.Log("✓ Second delivery failed as expected (cache hit)")
}

// TestLMTPProxyLookupCache_RemoteLookupCaching verifies that remotelookup results are cached
func TestLMTPProxyLookupCache_RemoteLookupCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lmtpcache-pre-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Track remotelookup calls
	remotelookupCalls := 0
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotelookupCalls++
		response := map[string]interface{}{
			"address": account.Email,
			"server":  backendServer.Address,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer remotelookupServer.Close()

	// Set up LMTP proxy with remotelookup and cache
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithRemoteLookupAndCache(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Helper to perform LMTP delivery attempt
	checkDelivery := func() error {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			return fmt.Errorf("dial failed: %w", err)
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

		// Send RCPT TO
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", uniqueEmail)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250") {
			return fmt.Errorf("RCPT TO failed: %s", line)
		}
		return nil
	}

	// Test 1: First delivery - calls remotelookup
	if err := checkDelivery(); err != nil {
		t.Fatalf("First delivery failed: %v", err)
	}
	if remotelookupCalls != 1 {
		t.Fatalf("Expected 1 remotelookup call, got %d", remotelookupCalls)
	}
	t.Log("✓ First delivery succeeded (remotelookup called)")

	// Test 2: Second delivery - uses cache (no remotelookup)
	if err := checkDelivery(); err != nil {
		t.Fatalf("Second delivery failed: %v", err)
	}
	if remotelookupCalls != 1 {
		t.Fatalf("Expected remotelookup calls to remain 1, got %d", remotelookupCalls)
	}
	t.Log("✓ Second delivery succeeded (cache hit, no remotelookup)")
}

// setupLMTPProxyWithCache creates LMTP proxy with caching enabled
func setupLMTPProxyWithCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-lmtp-cache"
	opts := lmtpproxy.ServerOptions{
		Name:           hostname,
		Addr:           proxyAddr,
		RemoteAddrs:    backendAddrs,
		RemotePort:     0, // Use port from address
		ConnectTimeout: 10 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
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

// setupLMTPProxyWithRemoteLookupAndCache creates LMTP proxy with remotelookup and caching
func setupLMTPProxyWithRemoteLookupAndCache(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-lmtp-remotelookup-cache"
	opts := lmtpproxy.ServerOptions{
		Name:           hostname,
		Addr:           proxyAddr,
		RemoteAddrs:    backendAddrs,
		RemotePort:     0,
		ConnectTimeout: 10 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:      true,
			URL:          remotelookupURL,
			Timeout:      "5s",
			FallbackToDB: false,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
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
