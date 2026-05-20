//go:build integration

package userapi

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAuthBypassPrevention verifies that X-Forwarded-User headers cannot be used
// to bypass JWT authentication (CVE-2026-XXXXX fix verification)
func TestAuthBypassPrevention(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	tc := setupTestServer(t)

	t.Run("RejectRequest_WithForwardedUserButNoJWT", func(t *testing.T) {
		// Attempt to bypass authentication using X-Forwarded-User header
		req, err := http.NewRequest("GET", tc.Server.URL+"/user/mailboxes", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Attacker-controlled headers
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Forwarded-User", tc.TestUser.Email)
		req.Header.Set("X-Forwarded-User-ID", "999")

		resp, err := tc.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Should be rejected with 401 Unauthorized
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("RejectRequest_WithForwardedUserAndInvalidJWT", func(t *testing.T) {
		// Attempt to use spoofed headers with invalid JWT
		req, err := http.NewRequest("GET", tc.Server.URL+"/user/mailboxes", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Attacker-controlled headers
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Forwarded-User", "victim@example.com")
		req.Header.Set("X-Forwarded-User-ID", "999")
		req.Header.Set("Authorization", "Bearer invalid-token")

		resp, err := tc.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Should be rejected with 401 Unauthorized
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("AcceptRequest_WithValidJWT_IgnoreForwardedHeaders", func(t *testing.T) {
		// Login to get valid JWT
		loginReq := map[string]string{
			"email":    tc.TestUser.Email,
			"password": tc.TestUser.Password,
		}
		loginResp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		defer loginResp.Body.Close()

		if loginResp.StatusCode != http.StatusOK {
			t.Fatalf("Login failed with status %d", loginResp.StatusCode)
		}

		var loginData struct {
			Token string `json:"token"`
		}
		body, _ := io.ReadAll(loginResp.Body)
		if err := json.Unmarshal(body, &loginData); err != nil {
			t.Fatalf("Failed to parse login response: %v", err)
		}

		// Make request with valid JWT but spoofed forwarded headers
		req, err := http.NewRequest("GET", tc.Server.URL+"/user/mailboxes", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+loginData.Token)
		// These should be ignored
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Forwarded-User", "attacker@example.com")
		req.Header.Set("X-Forwarded-User-ID", "999")

		resp, err := tc.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Should succeed and use JWT identity, not X-Forwarded-User
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK with valid JWT, got %d", resp.StatusCode)
		}
	})
}
