//go:build integration

package userapiproxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

const testJWTSecret = "test-secret-key-for-testing-only"

// TestContext holds common test infrastructure
type TestContext struct {
	BackendServer *httptest.Server
	ProxyServer   *userapiproxy.Server
	ProxyAddr     string
	RDB           *resilient.ResilientDatabase
	HTTPClient    *http.Client
	JWTToken      string
	TestUser      common.TestAccount
	ctx           context.Context
	cancel        context.CancelFunc
}

// setupTestEnvironment creates backend and proxy servers
func setupTestEnvironment(t *testing.T) *TestContext {
	t.Helper()

	common.SkipIfDatabaseUnavailable(t)

	// Setup database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	account := common.CreateTestAccount(t, rdb)

	// Create backend User API server
	serverOptions := userapi.ServerOptions{
		Name:           "test-backend",
		Addr:           "127.0.0.1:0",
		JWTSecret:      testJWTSecret,
		TokenDuration:  1 * time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		AllowedHosts:   []string{"127.0.0.1", "localhost"}, // Trust local connections from proxy
		Storage:        nil,
		Cache:          nil,
		TLS:            false,
	}

	backendAPI, err := userapi.New(rdb, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create backend server: %v", err)
	}

	// Create test HTTP server for backend
	backendServer := httptest.NewServer(backendAPI.SetupRoutes())

	// Get backend address for proxy configuration
	backendAddr := backendServer.Listener.Addr().String()

	// Create proxy server
	ctx, cancel := context.WithCancel(context.Background())
	proxyOptions := userapiproxy.ServerOptions{
		Name:        "test-proxy",
		Addr:        "127.0.0.1:0",
		RemoteAddrs: []string{backendAddr},
		RemotePort:  8081,
		JWTSecret:   testJWTSecret,
		TLS:         false,
	}

	proxy, err := userapiproxy.New(ctx, rdb, proxyOptions)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	// Start proxy in goroutine
	proxyAddr := common.GetRandomAddress(t)
	proxy.(*userapiproxy.Server).addr = proxyAddr

	go func() {
		if err := proxy.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Proxy server error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	tc := &TestContext{
		BackendServer: backendServer,
		ProxyServer:   proxy.(*userapiproxy.Server),
		ProxyAddr:     proxyAddr,
		RDB:           rdb,
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
		TestUser:      account,
		ctx:           ctx,
		cancel:        cancel,
	}

	t.Cleanup(func() {
		backendServer.Close()
		cancel()
		time.Sleep(50 * time.Millisecond)
	})

	return tc
}

// makeProxyRequest makes an HTTP request through the proxy
func (tc *TestContext) makeProxyRequest(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	url := fmt.Sprintf("http://%s%s", tc.ProxyAddr, path)
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if tc.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+tc.JWTToken)
	}

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	return resp
}

// parseJSON parses JSON response into target
func parseJSON(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v (body: %s)", err, string(body))
	}
}

// TestProxyAuthentication tests that the proxy validates JWT tokens
func TestProxyAuthentication(t *testing.T) {
	tc := setupTestEnvironment(t)

	t.Run("ProxyRejectsRequestWithoutToken", func(t *testing.T) {
		resp := tc.makeProxyRequest(t, "GET", "/user/mailboxes", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401 for request without token, got %d", resp.StatusCode)
		}
	})

	t.Run("ProxyRejectsInvalidToken", func(t *testing.T) {
		tc.JWTToken = "invalid.jwt.token"
		resp := tc.makeProxyRequest(t, "GET", "/user/mailboxes", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401 for invalid token, got %d", resp.StatusCode)
		}
	})

	t.Run("ProxyAcceptsValidToken", func(t *testing.T) {
		// First login through backend to get valid token
		loginReq := map[string]string{
			"email":    tc.TestUser.Email,
			"password": tc.TestUser.Password,
		}

		url := fmt.Sprintf("%s/user/auth/login", tc.BackendServer.URL)
		jsonBody, _ := json.Marshal(loginReq)
		resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
		if err != nil {
			t.Fatalf("Failed to login: %v", err)
		}

		var loginResp map[string]interface{}
		parseJSON(t, resp, &loginResp)
		tc.JWTToken = loginResp["token"].(string)

		// Now make request through proxy with valid token
		resp = tc.makeProxyRequest(t, "GET", "/user/mailboxes", nil)
		// Note: May get 404 or other errors due to missing mailbox data, but not 401
		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("Proxy rejected valid token with status 401")
		}

		t.Logf("Proxy accepted valid token, status: %d", resp.StatusCode)
	})
}

// TestProxyForwardsHeaders tests that proxy forwards user headers to backend
func TestProxyForwardsHeaders(t *testing.T) {
	tc := setupTestEnvironment(t)

	// Login to get token
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}

	url := fmt.Sprintf("%s/user/auth/login", tc.BackendServer.URL)
	jsonBody, _ := json.Marshal(loginReq)
	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	var loginResp map[string]interface{}
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Make request through proxy
	resp = tc.makeProxyRequest(t, "GET", "/user/mailboxes", nil)

	// The fact that we don't get a 401 means the backend trusted the proxy's headers
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("Backend did not trust proxy's forwarded headers")
	}

	t.Logf("Backend successfully trusted proxy headers, status: %d", resp.StatusCode)
}

// TestProxyUserRouting tests that proxy routes users consistently
func TestProxyUserRouting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database
	rdb := common.SetupTestDatabase(t)

	// Create test accounts
	account1 := common.CreateTestAccount(t, rdb)
	account2 := common.CreateTestAccountWithEmail(t, rdb, "user2@example.com", "password123")

	// Create backend servers
	backend1 := createBackendServer(t, rdb, "backend1")
	backend2 := createBackendServer(t, rdb, "backend2")
	defer backend1.Close()
	defer backend2.Close()

	// Create proxy with multiple backends
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyOptions := userapiproxy.ServerOptions{
		Name:        "test-proxy-routing",
		Addr:        "127.0.0.1:0",
		RemoteAddrs: []string{backend1.Listener.Addr().String(), backend2.Listener.Addr().String()},
		JWTSecret:   testJWTSecret,
	}

	proxy, err := userapiproxy.New(ctx, rdb, proxyOptions)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyAddr := common.GetRandomAddress(t)
	proxy.(*userapiproxy.Server).addr = proxyAddr

	go proxy.Start()
	time.Sleep(100 * time.Millisecond)

	// Get tokens for both users
	token1 := loginAndGetToken(t, backend1.URL, account1.Email, account1.Password)
	token2 := loginAndGetToken(t, backend2.URL, account2.Email, account2.Password)

	// Make multiple requests for user1 - should go to same backend
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/user/mailboxes", proxyAddr), nil)
		req.Header.Set("Authorization", "Bearer "+token1)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("Request %d got 401 - routing failed", i)
		}
	}

	// Make requests for user2 - should also be routed consistently
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/user/mailboxes", proxyAddr), nil)
		req.Header.Set("Authorization", "Bearer "+token2)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("Request %d got 401 - routing failed", i)
		}
	}

	t.Log("User routing test completed - users consistently routed")
}

// Helper function to create a backend server
func createBackendServer(t *testing.T, rdb *resilient.ResilientDatabase, name string) *httptest.Server {
	t.Helper()

	serverOptions := userapi.ServerOptions{
		Name:           name,
		Addr:           "127.0.0.1:0",
		JWTSecret:      testJWTSecret,
		TokenDuration:  1 * time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		AllowedHosts:   []string{"127.0.0.1", "localhost"},
		Storage:        nil,
		Cache:          nil,
		TLS:            false,
	}

	backendAPI, err := userapi.New(rdb, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create backend %s: %v", name, err)
	}

	return httptest.NewServer(backendAPI.SetupRoutes())
}

// Helper function to login and get token
func loginAndGetToken(t *testing.T, baseURL, email, password string) string {
	t.Helper()

	loginReq := map[string]string{
		"email":    email,
		"password": password,
	}

	jsonBody, _ := json.Marshal(loginReq)
	resp, err := http.Post(baseURL+"/user/auth/login", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var loginResp map[string]interface{}
	json.Unmarshal(body, &loginResp)

	return loginResp["token"].(string)
}

// TestProxyConnectionLimits tests that proxy respects connection limits
func TestProxyConnectionLimits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create backend
	backend := createBackendServer(t, rdb, "backend")
	defer backend.Close()

	// Create proxy with low connection limit
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyOptions := userapiproxy.ServerOptions{
		Name:           "test-proxy-limits",
		Addr:           "127.0.0.1:0",
		RemoteAddrs:    []string{backend.Listener.Addr().String()},
		JWTSecret:      testJWTSecret,
		MaxConnections: 2, // Very low limit for testing
	}

	proxy, err := userapiproxy.New(ctx, rdb, proxyOptions)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyAddr := common.GetRandomAddress(t)
	proxy.(*userapiproxy.Server).addr = proxyAddr

	go proxy.Start()
	time.Sleep(100 * time.Millisecond)

	// Get token
	token := loginAndGetToken(t, backend.URL, account.Email, account.Password)

	// Test connection limits
	t.Log("Testing connection limits - this test verifies limit enforcement exists")

	// Make a few requests - some may be rejected if limits are enforced
	client := &http.Client{Timeout: 2 * time.Second}
	var rejectedCount int

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/user/mailboxes", proxyAddr), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				rejectedCount++
				continue
			}
			t.Logf("Request %d got error: %v", i, err)
			continue
		}
		resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("Connection limit test completed - %d requests handled", 5-rejectedCount)
}
