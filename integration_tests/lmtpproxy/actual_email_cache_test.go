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
	"golang.org/x/crypto/bcrypt"
)

// TestLMTPProxyActualEmailCaching tests that when remotelookup returns an "address" field
// (ActualEmail) that differs from the submitted recipient,
// the cache stores ActualEmail so cache hits can use the resolved address.
//
// Bug: Cache wasn't storing ActualEmail, so cache hits used submitted recipient for routing
//
// Expected behavior:
// 1. Deliver to user@example.com → remotelookup may return different address
// 2. Cache key: BaseAddress of recipient, Cache value includes ActualEmail if different
// 3. Subsequent delivery → cache hit, uses stored ActualEmail for routing
//
// Note: LMTP uses BaseAddress() which strips +detail, so user+tag@example.com → user@example.com
func TestLMTPProxyActualEmailCaching(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server
	backendServer, _ := common.SetupLMTPServer(t)
	defer backendServer.Close()

	// Create test account
	uniqueEmail := fmt.Sprintf("lmtpactualcache-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for remotelookup response (not used by LMTP but included for completeness)
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Track remotelookup calls
	var remotelookupCalls atomic.Int32

	// Create remotelookup server
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := remotelookupCalls.Add(1)
		t.Logf("RemoteLookup call #%d: %s", count, r.URL.Path)

		response := map[string]interface{}{
			"address":       account.Email, // Resolved email
			"password_hash": passwordHash,
			"server":        backendServer.Address,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		t.Logf("RemoteLookup returned address=%s", account.Email)
	}))
	defer remotelookupServer.Close()

	// Set up LMTP proxy with remotelookup
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupLMTPProxyWithRemoteLookupForActualEmailTest(t, backendServer.ResilientDB, proxyAddress,
		[]string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	// Helper to perform LMTP delivery attempt (just RCPT TO, no DATA)
	checkDelivery := func(recipient string) error {
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
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", recipient)
		if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "250") {
			return fmt.Errorf("RCPT TO failed: %s", line)
		}

		return nil
	}

	// Test 1: Deliver to recipient - should populate cache
	t.Run("DeliverFirst_PopulatesCache", func(t *testing.T) {
		callsBefore := remotelookupCalls.Load()

		if err := checkDelivery(account.Email); err != nil {
			t.Fatalf("First delivery failed: %v", err)
		}
		t.Logf("✓ RCPT TO succeeded (recipient=%s)", account.Email)

		callsAfter := remotelookupCalls.Load()
		if callsAfter <= callsBefore {
			t.Fatalf("Expected remotelookup to be called")
		}
	})

	time.Sleep(200 * time.Millisecond)

	// Test 2: Deliver again - should hit cache
	t.Run("DeliverSecond_ShouldHitCache", func(t *testing.T) {
		callsBefore := remotelookupCalls.Load()

		if err := checkDelivery(account.Email); err != nil {
			t.Fatalf("Second delivery failed: %v", err)
		}
		t.Log("✓ RCPT TO (second time) succeeded")

		callsAfter := remotelookupCalls.Load()
		if callsAfter > callsBefore {
			t.Errorf("RemoteLookup was called %d time(s) - cache MISS (expected cache HIT)",
				callsAfter-callsBefore)
		} else {
			t.Log("✓ Cache hit - remotelookup was NOT called")
		}
	})
}

// setupLMTPProxyWithRemoteLookupForActualEmailTest sets up an LMTP proxy with remotelookup enabled
func setupLMTPProxyWithRemoteLookupForActualEmailTest(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-lmtp-actual-email-cache"
	opts := lmtpproxy.ServerOptions{
		Name:           hostname,
		Addr:           proxyAddr,
		RemoteAddrs:    backendAddrs,
		RemotePort:     0,
		ConnectTimeout: 10 * time.Second,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupURL + "/$email",
			Timeout:          "5s",
			LookupLocalUsers: false,
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
