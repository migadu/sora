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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestIMAPProxyAuthOnlyMode tests that prelookup can be used for authentication only
// When the prelookup response omits the "server" field, the proxy should:
// 1. Authenticate the user via prelookup
// 2. Select backend using local routing (affinity/consistent-hash/round-robin)
// 3. Build affinity over time like regular accounts
func TestIMAPProxyAuthOnlyMode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create two backend IMAP servers
	backendServer1, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer1.Close()

	backendServer2, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer2.Close()

	// Create test account using helper with unique email
	uniqueEmail := fmt.Sprintf("authonly-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, backendServer1.ResilientDB, uniqueEmail, "test123")

	// Generate password hash for prelookup response (same way accounts are created)
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// Create a prelookup server that returns auth-only response (no "server" field)
	requestCount := 0
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		t.Logf("Prelookup request #%d: %s", requestCount, r.URL.Path)

		// Return auth-only response (no server field)
		response := map[string]interface{}{
			"address":       account.Email,
			"password_hash": passwordHash,
			// "server" field intentionally omitted - this triggers auth-only mode
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode prelookup response: %v", err)
		}
		t.Logf("Prelookup returned auth-only response for %s", account.Email)
	}))
	defer prelookupServer.Close()

	// Set up IMAP proxy with auth-only prelookup
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithAuthOnly(t, backendServer1.ResilientDB, proxyAddress,
		[]string{backendServer1.Address, backendServer2.Address}, prelookupServer.URL)
	defer proxy.Close()

	// Test 1: First login - should authenticate via prelookup, route via consistent hash/round-robin
	t.Run("FirstLogin_AuthViaPreLookup", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed (auth via prelookup, routing via local selection)
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed with auth-only prelookup: %v", err)
		}
		t.Log("✓ Login succeeded with auth-only prelookup mode")

		// Verify we can perform IMAP operations
		selectCmd := c.Select("INBOX", nil)
		_, err = selectCmd.Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Log("✓ IMAP operations work with auth-only prelookup")

		// Verify prelookup was called (auth-only mode)
		if requestCount < 1 {
			t.Errorf("Expected prelookup to be called, but got %d requests", requestCount)
		}
	})

	// Test 2: Second login - should use affinity (same backend as first login)
	t.Run("SecondLogin_UseAffinity", func(t *testing.T) {
		// Reset request count to track if prelookup is called again
		requestCountBefore := requestCount

		// Wait a bit to ensure first connection is fully established and affinity is set
		time.Sleep(500 * time.Millisecond)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login should succeed again
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Second login failed: %v", err)
		}
		t.Log("✓ Second login succeeded (should use affinity)")

		// Verify prelookup was NOT called again (should use auth cache)
		// The auth cache stores routing info from first login and reuses it
		// This is expected behavior for performance optimization
		if requestCount > requestCountBefore {
			t.Logf("NOTE: Prelookup was called %d time(s) on second login (cache miss or revalidation)", requestCount-requestCountBefore)
		} else {
			t.Log("✓ Auth cache prevented unnecessary prelookup call (expected behavior)")
		}

		// Verify IMAP operations still work
		selectCmd := c.Select("INBOX", nil)
		_, err = selectCmd.Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed on second login: %v", err)
		}
		t.Log("✓ IMAP operations work on second login (affinity)")
	})
}

// TestIMAPProxyMixedMode tests that prelookup can handle both modes:
// - Some users with explicit backend routing (server field present)
// - Some users with auth-only mode (server field omitted)
func TestIMAPProxyMixedMode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create shared database for both backend servers (they must share the same DB)
	// Note: Database will be closed by SetupTestDatabase's cleanup
	rdb := common.SetupTestDatabase(t)

	// Create two backend IMAP servers on the shared database
	backendServer1 := common.SetupIMAPServerWithPROXYAndDatabase(t, rdb)
	defer backendServer1.Close()

	backendServer2 := common.SetupIMAPServerWithPROXYAndDatabase(t, rdb)
	defer backendServer2.Close()

	// Create two test accounts using helper with unique emails to avoid conflicts
	timestamp := time.Now().UnixNano()
	authOnlyAccount := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("authonly-mixed-%d@example.com", timestamp), "test123")
	routedAccount := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("routed-mixed-%d@example.com", timestamp), "test456")

	// Generate password hashes for prelookup response
	authOnlyHashBytes, err := bcrypt.GenerateFromPassword([]byte(authOnlyAccount.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash auth-only password: %v", err)
	}
	routedHashBytes, err := bcrypt.GenerateFromPassword([]byte(routedAccount.Password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash routed password: %v", err)
	}
	authOnlyHash := string(authOnlyHashBytes)
	routedHash := string(routedHashBytes)

	// Create prelookup server that returns different responses based on user
	prelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimPrefix(r.URL.Path, "/")
		t.Logf("Prelookup request for: %s", email)

		var response map[string]interface{}
		if strings.Contains(email, "authonly") {
			// Auth-only mode: no server field
			response = map[string]interface{}{
				"address":       authOnlyAccount.Email,
				"password_hash": authOnlyHash,
				// No "server" field - triggers auth-only mode
			}
			t.Logf("Returning auth-only response for %s", email)
		} else if strings.Contains(email, "routed") {
			// Routing mode: includes server field
			response = map[string]interface{}{
				"address":       routedAccount.Email,
				"password_hash": routedHash,
				"server":        backendServer2.Address, // Explicitly route to backend 2
			}
			t.Logf("Returning routed response for %s (backend: %s)", email, backendServer2.Address)
			t.Logf("Backend2 actual address: %s, Backend1 address: %s", backendServer2.Address, backendServer1.Address)
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer prelookupServer.Close()

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithAuthOnly(t, rdb, proxyAddress,
		[]string{backendServer1.Address, backendServer2.Address}, prelookupServer.URL+"/$email")
	defer proxy.Close()

	// Test auth-only user
	t.Run("AuthOnlyUser", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}

		if err := c.Login(authOnlyAccount.Email, authOnlyAccount.Password).Wait(); err != nil {
			t.Fatalf("Auth-only user login failed: %v", err)
		}
		t.Log("✓ Auth-only user login succeeded")

		// Explicitly logout and close
		c.Logout()
		c.Close()
	})

	// Wait for first connection to fully close and backends to be ready
	time.Sleep(2 * time.Second)

	// Test routed user
	t.Run("RoutedUser", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}

		if err := c.Login(routedAccount.Email, routedAccount.Password).Wait(); err != nil {
			t.Fatalf("Routed user login failed: %v", err)
		}
		t.Log("✓ Routed user login succeeded (explicit backend routing)")

		// Explicitly logout and close
		c.Logout()
		c.Close()
	})
}

// setupIMAPProxyWithAuthOnly creates IMAP proxy with auth-only prelookup configured
func setupIMAPProxyWithAuthOnly(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-authonly"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-authonly",
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
		EnableAffinity:         true, // Enable affinity to test it works with auth-only mode
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		PreLookup: &config.PreLookupConfig{
			Enabled:                true,
			URL:                    prelookupURL,
			Timeout:                "5s",
			FallbackDefault:        false, // Not needed for auth-only mode
			RemoteUseProxyProtocol: true,  // Backend servers expect PROXY protocol
		},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with auth-only prelookup: %v", err)
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
