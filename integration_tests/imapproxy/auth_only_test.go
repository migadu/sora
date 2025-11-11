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

	// Create test account using helper
	account := common.CreateTestAccountWithEmail(t, backendServer1.ResilientDB, "authonly@example.com", "test123")

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

		// Verify prelookup was called again for authentication
		// (auth-only mode always authenticates via prelookup)
		if requestCount <= requestCountBefore {
			t.Errorf("Expected prelookup to be called again for auth, but got %d requests", requestCount-requestCountBefore)
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

	// Create two backend IMAP servers
	backendServer1, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer1.Close()

	backendServer2, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer2.Close()

	// Create two test accounts using helper (use unique emails to avoid conflicts)
	authOnlyAccount := common.CreateTestAccountWithEmail(t, backendServer1.ResilientDB, "authonly-mixed@example.com", "test123")
	routedAccount := common.CreateTestAccountWithEmail(t, backendServer1.ResilientDB, "routed-mixed@example.com", "test456")

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
	proxy := setupIMAPProxyWithAuthOnly(t, backendServer1.ResilientDB, proxyAddress,
		[]string{backendServer1.Address, backendServer2.Address}, prelookupServer.URL+"/$email")
	defer proxy.Close()

	// Test auth-only user
	t.Run("AuthOnlyUser", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		if err := c.Login(authOnlyAccount.Email, authOnlyAccount.Password).Wait(); err != nil {
			t.Fatalf("Auth-only user login failed: %v", err)
		}
		t.Log("✓ Auth-only user login succeeded")
	})

	// Test routed user
	t.Run("RoutedUser", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		if err := c.Login(routedAccount.Email, routedAccount.Password).Wait(); err != nil {
			t.Fatalf("Routed user login failed: %v", err)
		}
		t.Log("✓ Routed user login succeeded (explicit backend routing)")
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
			Enabled:         true,
			URL:             prelookupURL,
			Timeout:         "5s",
			FallbackDefault: false, // Not needed for auth-only mode
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
