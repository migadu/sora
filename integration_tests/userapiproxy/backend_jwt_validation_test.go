//go:build integration

package userapiproxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

// TestBackendValidatesJWT verifies that the backend actually validates JWT tokens
// when requests come from the proxy (after removing X-Forwarded-User trust)
func TestBackendValidatesJWT(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create backend server
	backendOptions := userapi.ServerOptions{
		Name:           "test-backend",
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

	backendAPI, err := userapi.New(rdb, backendOptions)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backendServer := httptest.NewServer(backendAPI.SetupRoutes())
	defer backendServer.Close()

	// Create proxy
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr := common.GetRandomAddress(t)
	proxyOptions := userapiproxy.ServerOptions{
		Name:        "test-proxy",
		Addr:        proxyAddr,
		RemoteAddrs: []string{backendServer.Listener.Addr().String()},
		JWTSecret:   testJWTSecret,
		TLS:         false,
	}

	proxy, err := userapiproxy.New(ctx, rdb, proxyOptions)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go proxy.Start()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	// Login to get valid JWT
	loginReq := map[string]string{
		"email":    account.Email,
		"password": account.Password,
	}
	loginBody, _ := json.Marshal(loginReq)
	loginResp, err := http.Post(backendServer.URL+"/user/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	defer loginResp.Body.Close()

	var loginData map[string]any
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	validToken := loginData["token"].(string)

	t.Run("Backend_AcceptsValidJWT_FromProxy", func(t *testing.T) {
		// Make request through proxy with valid JWT
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/user/mailboxes", proxyAddr), nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK with valid JWT, got %d", resp.StatusCode)
		}

		t.Log("✓ Backend validated JWT correctly (valid token accepted)")
	})

	t.Run("Backend_RejectsInvalidJWT_FromProxy", func(t *testing.T) {
		// Make request through proxy with INVALID JWT
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/user/mailboxes", proxyAddr), nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token.here")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Proxy should reject invalid JWT before forwarding
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized with invalid JWT, got %d", resp.StatusCode)
		}

		t.Log("✓ Proxy rejected invalid JWT (correct)")
	})

	t.Run("Backend_RejectsRequest_WithoutJWT_EvenFromProxy", func(t *testing.T) {
		// Try to bypass by sending request directly to backend without JWT
		// (simulating if someone bypassed the proxy)
		req, _ := http.NewRequest("GET", backendServer.URL+"/user/mailboxes", nil)

		// Try to spoof X-Forwarded-User (should be ignored after our fix)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Forwarded-User", account.Email)
		req.Header.Set("X-Forwarded-User-ID", "999")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized without JWT (backend must validate), got %d", resp.StatusCode)
		}

		t.Log("✓ Backend rejected request without JWT (ignoring X-Forwarded-User)")
	})

	t.Run("Backend_ValidatesJWT_NotTrustingHeaders", func(t *testing.T) {
		// Make request directly to backend with valid JWT + spoofed headers
		req, _ := http.NewRequest("GET", backendServer.URL+"/user/mailboxes", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		// These should be completely ignored
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Forwarded-User", "attacker@example.com")
		req.Header.Set("X-Forwarded-User-ID", "999")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK (JWT validated), got %d", resp.StatusCode)
		}

		// Parse response to verify it's the CORRECT user (from JWT, not X-Forwarded-User)
		var mailboxResp map[string]any
		json.NewDecoder(resp.Body).Decode(&mailboxResp)

		// Should see default mailboxes (INBOX, Sent, etc.) for the authenticated user
		// Not an error or "attacker@example.com" data
		if mailboxResp["error"] != nil {
			t.Errorf("Backend should have accepted valid JWT, got error: %v", mailboxResp["error"])
		}

		t.Log("✓ Backend validated JWT and ignored spoofed X-Forwarded-User headers")
	})
}
