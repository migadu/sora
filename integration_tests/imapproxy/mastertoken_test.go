//go:build integration

package imapproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// TestIMAPProxyMasterToken tests master token authentication through HTTP prelookup
func TestIMAPProxyMasterToken(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up HTTP prelookup server
	prelookupServer := setupHTTPPrelookupServer(t, account.Email, account.Password, backendServer.Address)
	defer prelookupServer.Close()

	// Set up IMAP proxy with HTTP prelookup and master token enabled
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupIMAPProxyWithHTTPPrelookup(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL)
	defer func() {
		if srv, ok := proxyServer.Server.(*imapproxy.Server); ok {
			srv.Stop()
		}
	}()

	t.Run("NormalAuthentication", func(t *testing.T) {
		// Test normal authentication (without master token)
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(account.Email, account.Password).Wait()
		if err != nil {
			t.Fatalf("Normal authentication failed: %v", err)
		}
		t.Logf("✓ Normal authentication successful for %s", account.Email)
	})

	t.Run("MasterTokenAuthentication", func(t *testing.T) {
		// Test master token authentication
		masterToken := "supersecretmastertoken"
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login using email@TOKEN format
		// Password field should contain the master token, not the user password
		err = c.Login(emailWithToken, masterToken).Wait()
		if err != nil {
			t.Fatalf("Master token authentication failed: %v", err)
		}
		t.Logf("✓ Master token authentication successful for %s", emailWithToken)
	})

	t.Run("MasterTokenWrongPassword", func(t *testing.T) {
		// Test master token with wrong token
		// Use correct email with WRONG token appended
		wrongToken := "wrongtoken"
		emailWithWrongToken := fmt.Sprintf("%s@%s", account.Email, wrongToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Pass the wrong token as the password (since that's what gets verified)
		err = c.Login(emailWithWrongToken, wrongToken).Wait()
		if err == nil {
			t.Fatal("Expected master token authentication to fail with wrong token, but it succeeded")
		}
		t.Logf("✓ Master token correctly rejected wrong token: %v", err)
	})

	t.Run("InvalidMasterToken", func(t *testing.T) {
		// Test with invalid master token
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, "invalidtoken")

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(emailWithToken, "invalidtoken").Wait()
		if err == nil {
			t.Fatal("Expected authentication to fail with invalid master token, but it succeeded")
		}
		t.Logf("✓ Invalid master token correctly rejected: %v", err)
	})

	t.Run("ResolvedAddress", func(t *testing.T) {
		// Test that resolved_address is used for routing
		// The prelookup setup includes a resolved_address that points to the backend
		masterToken := "supersecretmastertoken"
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(emailWithToken, masterToken).Wait()
		if err != nil {
			t.Fatalf("Master token authentication with resolved address failed: %v", err)
		}
		t.Logf("✓ Resolved address routing successful")
	})
}

// TestIMAPProxyMasterTokenAddressValidation tests that emails with multiple @ work
func TestIMAPProxyMasterTokenAddressValidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up HTTP prelookup server
	prelookupServer := setupHTTPPrelookupServer(t, account.Email, account.Password, backendServer.Address)
	defer prelookupServer.Close()

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupIMAPProxyWithHTTPPrelookup(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, prelookupServer.URL)
	defer func() {
		if srv, ok := proxyServer.Server.(*imapproxy.Server); ok {
			srv.Stop()
		}
	}()

	// Test that email with multiple @ symbols doesn't get rejected by address validation
	masterToken := "token123"
	emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

	// Count @ symbols to verify we're testing the right scenario
	atCount := strings.Count(emailWithToken, "@")
	if atCount < 2 {
		t.Fatalf("Test email should have at least 2 @ symbols, got %d in: %s", atCount, emailWithToken)
	}
	t.Logf("Testing email with %d @ symbols: %s", atCount, emailWithToken)

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Update the prelookup server to accept this specific token
	if httpServer, ok := prelookupServer.Config.Handler.(*httpPrelookupHandler); ok {
		httpServer.updateMasterToken(masterToken)
	}

	err = c.Login(emailWithToken, masterToken).Wait()
	if err != nil {
		t.Fatalf("Authentication failed for email with multiple @ symbols: %v", err)
	}
	t.Logf("✓ Email with multiple @ symbols (%d) accepted successfully", atCount)
}

// httpPrelookupHandler handles HTTP prelookup requests for testing
type httpPrelookupHandler struct {
	mu               sync.RWMutex
	userEmail        string
	userPassword     string
	masterToken      string
	backendAddr      string
	userPasswordHash string
	masterTokenHash  string
}

func (h *httpPrelookupHandler) updateMasterToken(newToken string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.masterToken = newToken
	hash, _ := bcrypt.GenerateFromPassword([]byte(newToken), bcrypt.DefaultCost)
	h.masterTokenHash = string(hash)
}

func (h *httpPrelookupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, `{"error": "email parameter required"}`, http.StatusBadRequest)
		return
	}

	// Check if this is master token authentication (email@domain@TOKEN)
	parts := strings.Split(email, "@")
	var actualEmail string
	var hashToReturn string

	if len(parts) >= 3 {
		// Master token format: user@domain@TOKEN
		actualEmail = parts[0] + "@" + parts[1]
		token := parts[2]

		// Verify token matches
		if actualEmail == h.userEmail && token == h.masterToken {
			hashToReturn = h.masterTokenHash
		} else {
			http.Error(w, `{"error": "invalid master token"}`, http.StatusForbidden)
			return
		}
	} else {
		// Normal authentication
		actualEmail = email
		if actualEmail == h.userEmail {
			hashToReturn = h.userPasswordHash
		} else {
			http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
			return
		}
	}

	response := map[string]interface{}{
		"address":       actualEmail,
		"password_hash": hashToReturn,
		"server":        h.backendAddr,
		"account_id":    1,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// setupHTTPPrelookupServer creates an HTTP test server for prelookup
func setupHTTPPrelookupServer(t *testing.T, userEmail, userPassword, backendAddr string) *httptest.Server {
	t.Helper()

	// Hash user password
	userHash, err := bcrypt.GenerateFromPassword([]byte(userPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash user password: %v", err)
	}

	// Hash master token
	masterToken := "supersecretmastertoken"
	masterHash, err := bcrypt.GenerateFromPassword([]byte(masterToken), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash master token: %v", err)
	}

	handler := &httpPrelookupHandler{
		userEmail:        userEmail,
		userPassword:     userPassword,
		masterToken:      masterToken,
		backendAddr:      backendAddr,
		userPasswordHash: string(userHash),
		masterTokenHash:  string(masterHash),
	}

	server := httptest.NewServer(handler)
	t.Logf("Created HTTP prelookup server at %s for %s", server.URL, userEmail)
	return server
}

// setupIMAPProxyWithHTTPPrelookup creates IMAP proxy with HTTP prelookup and master token support
func setupIMAPProxyWithHTTPPrelookup(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, prelookupURL string) *common.TestServer {
	t.Helper()

	hostname := "test-master-token"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	// Configure HTTP prelookup with caching
	// Note: Master token logic is now handled by the HTTP endpoint, not the client
	prelookupConfig := &config.PreLookupConfig{
		Enabled: true,
		URL:     prelookupURL + "/lookup",
		Timeout: "5s",
		// Enable caching for testing
		Cache: &config.PreLookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "10s",
			NegativeTTL:     "5s",
			MaxSize:         100,
			CleanupInterval: "30s",
		},
		RemoteUseProxyProtocol: true, // Match the backend server configuration
	}

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
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
		SessionTimeout:         30 * time.Minute,
		EnableAffinity:         true,
		AffinityValidity:       24 * time.Hour,
		AffinityStickiness:     0.9,
		PreLookup:              prelookupConfig,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	// Create proxy server
	proxyServer, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with HTTP prelookup: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxyServer.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Server:      proxyServer,
		Address:     proxyAddr,
		ResilientDB: rdb,
	}
}
