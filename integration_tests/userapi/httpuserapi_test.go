//go:build integration

package userapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/userapi"
)

// TestContext holds common test infrastructure
type TestContext struct {
	Server     *httptest.Server
	RDB        *resilient.ResilientDatabase
	HTTPClient *http.Client
	JWTToken   string
	TestUser   common.TestAccount
}

// setupTestServer creates a test HTTP server with all dependencies
func setupTestServer(t *testing.T) *TestContext {
	t.Helper()

	// Skip if database unavailable
	common.SkipIfDatabaseUnavailable(t)

	// Setup database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	account := common.CreateTestAccount(t, rdb)

	// Create server
	serverOptions := userapi.ServerOptions{
		Name:           "test-server",
		Addr:           "127.0.0.1:0", // Random port
		JWTSecret:      "test-secret-key-for-testing-only",
		TokenDuration:  1 * time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		Storage:        nil, // Can be nil for metadata-only tests
		Cache:          nil, // Can be nil for tests
		TLS:            false,
	}

	server, err := userapi.New(rdb, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Get the router from setupRoutes
	router := server.SetupRoutes()

	// Create test HTTP server with the router
	testServer := httptest.NewServer(router)

	tc := &TestContext{
		Server:     testServer,
		RDB:        rdb,
		HTTPClient: testServer.Client(),
		TestUser:   account,
	}

	t.Cleanup(func() {
		testServer.Close()
	})

	return tc
}

// makeRequest makes an HTTP request and returns the response
func (tc *TestContext) makeRequest(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, tc.Server.URL+path, reqBody)
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
func parseJSON(t *testing.T, resp *http.Response, target any) {
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

// TestAuthentication tests the authentication endpoints
func TestAuthentication(t *testing.T) {
	tc := setupTestServer(t)

	t.Run("Login_Success", func(t *testing.T) {
		loginReq := map[string]string{
			"email":    tc.TestUser.Email,
			"password": tc.TestUser.Password,
		}

		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var loginResp map[string]any
		parseJSON(t, resp, &loginResp)

		token, ok := loginResp["token"].(string)
		if !ok || token == "" {
			t.Fatal("Expected token in response")
		}

		tc.JWTToken = token
		t.Logf("Successfully obtained JWT token")
	})

	t.Run("Login_InvalidPassword", func(t *testing.T) {
		loginReq := map[string]string{
			"email":    tc.TestUser.Email,
			"password": "wrongpassword",
		}

		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("Login_NonexistentUser", func(t *testing.T) {
		loginReq := map[string]string{
			"email":    "nonexistent@example.com",
			"password": "password",
		}

		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("RefreshToken_Success", func(t *testing.T) {
		// First login to get a token
		loginReq := map[string]string{
			"email":    tc.TestUser.Email,
			"password": tc.TestUser.Password,
		}

		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		var loginResp map[string]any
		parseJSON(t, resp, &loginResp)
		oldToken := loginResp["token"].(string)

		// Small delay to ensure token timestamps differ
		time.Sleep(1 * time.Second)

		// Refresh the token
		refreshReq := map[string]string{
			"token": oldToken,
		}

		resp = tc.makeRequest(t, "POST", "/user/auth/refresh", refreshReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var refreshResp map[string]any
		parseJSON(t, resp, &refreshResp)

		newToken, ok := refreshResp["token"].(string)
		if !ok || newToken == "" {
			t.Fatal("Expected new token in response")
		}

		if newToken == oldToken {
			t.Fatal("Expected new token to be different from old token")
		}

		t.Logf("Successfully refreshed JWT token")
	})
}

// TestMailboxOperations tests mailbox CRUD operations
func TestMailboxOperations(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	t.Run("ListMailboxes_Default", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		mailboxes, ok := result["mailboxes"].([]any)
		if !ok {
			t.Fatal("Expected mailboxes array in response")
		}

		// New accounts may have no mailboxes initially - that's OK
		t.Logf("Found %d mailboxes", len(mailboxes))
	})

	t.Run("CreateMailbox_Success", func(t *testing.T) {
		createReq := map[string]string{
			"name": fmt.Sprintf("TestFolder-%d", time.Now().Unix()),
		}

		resp := tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
		if resp.StatusCode != http.StatusCreated {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		if result["name"] != createReq["name"] {
			t.Fatalf("Expected name '%s', got %v", createReq["name"], result["name"])
		}

		t.Log("Successfully created mailbox")
	})

	t.Run("DeleteMailbox_ProtectINBOX", func(t *testing.T) {
		resp := tc.makeRequest(t, "DELETE", "/user/mailboxes/INBOX", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected status 403 for INBOX deletion, got %d", resp.StatusCode)
		}
	})

	t.Run("Unauthorized_WithoutToken", func(t *testing.T) {
		oldToken := tc.JWTToken
		tc.JWTToken = ""

		resp := tc.makeRequest(t, "GET", "/user/mailboxes", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got %d", resp.StatusCode)
		}

		tc.JWTToken = oldToken
	})
}

// TestMessageOperations tests message listing and operations
func TestMessageOperations(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Create INBOX for message tests
	createReq := map[string]string{"name": "INBOX"}
	tc.makeRequest(t, "POST", "/user/mailboxes", createReq)

	t.Run("ListMessages_EmptyMailbox", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/messages", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		// messages can be nil (null in JSON) for empty mailboxes
		var messages []any
		if result["messages"] != nil {
			var ok bool
			messages, ok = result["messages"].([]any)
			if !ok {
				t.Fatalf("Expected messages to be array or null, got %T", result["messages"])
			}
		}

		total := int(result["total"].(float64))
		t.Logf("Found %d messages in mailbox", total)

		// Empty or not, the response structure should be correct
		if len(messages) > 0 {
			t.Logf("Mailbox contains %d messages", len(messages))
		}

		t.Log("Successfully listed messages")
	})

	t.Run("ListMessages_WithPagination", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/messages?limit=10&offset=0", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		if result["limit"].(float64) != 10 {
			t.Fatalf("Expected limit 10, got %v", result["limit"])
		}

		if result["offset"].(float64) != 0 {
			t.Fatalf("Expected offset 0, got %v", result["offset"])
		}

		t.Log("Successfully tested pagination parameters")
	})

	t.Run("SearchMessages", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q=test", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		if result["query"] != "test" {
			t.Fatalf("Expected query 'test', got %v", result["query"])
		}

		t.Log("Successfully performed search")
	})

	t.Run("SearchMessages_MissingQuery", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}
	})
}

// TestMailboxSubscriptions tests mailbox subscription operations
func TestMailboxSubscriptions(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Create a test mailbox first
	mailboxName := fmt.Sprintf("TestSubscribe-%d", time.Now().Unix())
	createReq := map[string]string{
		"name": mailboxName,
	}
	resp = tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test mailbox: status %d", resp.StatusCode)
	}

	t.Run("SubscribeToMailbox", func(t *testing.T) {
		resp := tc.makeRequest(t, "POST", fmt.Sprintf("/user/mailboxes/%s/subscribe", mailboxName), nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully subscribed to mailbox")
	})

	t.Run("UnsubscribeFromMailbox", func(t *testing.T) {
		resp := tc.makeRequest(t, "POST", fmt.Sprintf("/user/mailboxes/%s/unsubscribe", mailboxName), nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully unsubscribed from mailbox")
	})

	t.Run("ListSubscribedMailboxes", func(t *testing.T) {
		// Subscribe first
		tc.makeRequest(t, "POST", fmt.Sprintf("/user/mailboxes/%s/subscribe", mailboxName), nil)

		resp := tc.makeRequest(t, "GET", "/user/mailboxes?subscribed=true", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		mailboxes, ok := result["mailboxes"].([]any)
		if !ok {
			t.Fatal("Expected mailboxes array in response")
		}

		t.Logf("Found %d subscribed mailboxes", len(mailboxes))
	})
}

// TestAuthenticationEdgeCases tests edge cases in authentication
func TestAuthenticationEdgeCases(t *testing.T) {
	tc := setupTestServer(t)

	t.Run("Login_MissingEmail", func(t *testing.T) {
		loginReq := map[string]string{
			"password": "password",
		}
		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("Login_MissingPassword", func(t *testing.T) {
		loginReq := map[string]string{
			"email": tc.TestUser.Email,
		}
		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("Login_EmptyCredentials", func(t *testing.T) {
		loginReq := map[string]string{
			"email":    "",
			"password": "",
		}
		resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
		// Either 400 or 401 is acceptable
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 400 or 401, got %d", resp.StatusCode)
		}
	})

	t.Run("RefreshToken_InvalidToken", func(t *testing.T) {
		refreshReq := map[string]string{
			"token": "invalid.jwt.token",
		}
		resp := tc.makeRequest(t, "POST", "/user/auth/refresh", refreshReq)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("RefreshToken_MissingToken", func(t *testing.T) {
		refreshReq := map[string]string{}
		resp := tc.makeRequest(t, "POST", "/user/auth/refresh", refreshReq)
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 400 or 401, got %d", resp.StatusCode)
		}
	})
}

// TestMailboxEdgeCases tests edge cases in mailbox operations
func TestMailboxEdgeCases(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	t.Run("CreateMailbox_DuplicateName", func(t *testing.T) {
		mailboxName := fmt.Sprintf("TestDuplicate-%d", time.Now().Unix())
		createReq := map[string]string{
			"name": mailboxName,
		}

		// Create first time
		resp := tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to create mailbox first time: status %d", resp.StatusCode)
		}

		// Try to create again - should fail
		resp = tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
		if resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 409 or 400 for duplicate, got %d", resp.StatusCode)
		}
	})

	t.Run("CreateMailbox_EmptyName", func(t *testing.T) {
		createReq := map[string]string{
			"name": "",
		}
		resp := tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("DeleteMailbox_Nonexistent", func(t *testing.T) {
		resp := tc.makeRequest(t, "DELETE", "/user/mailboxes/NonexistentFolder123", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d", resp.StatusCode)
		}
	})

	t.Run("CreateMailbox_HierarchicalName", func(t *testing.T) {
		mailboxName := fmt.Sprintf("Parent/Child-%d", time.Now().Unix())
		createReq := map[string]string{
			"name": mailboxName,
		}
		resp := tc.makeRequest(t, "POST", "/user/mailboxes", createReq)
		// Should succeed or fail based on implementation
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusBadRequest {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Hierarchical mailbox creation: status %d: %s", resp.StatusCode, string(body))
		}
	})
}

// TestMessageRetrieval tests message body and raw retrieval
func TestMessageRetrieval(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Note: These tests will return 404 if no messages exist, which is expected
	// In a real test, you'd want to create test messages first

	t.Run("GetMessage_Details", func(t *testing.T) {
		// Try to get message with ID 1 (may not exist)
		resp := tc.makeRequest(t, "GET", "/user/messages/1", nil)
		// Either 200 (exists) or 404 (doesn't exist) is acceptable
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusOK {
			var result map[string]any
			parseJSON(t, resp, &result)
			if result["id"] == nil {
				t.Fatal("Expected id in response")
			}
			t.Logf("Successfully retrieved message details")
		}
	})

	t.Run("GetMessage_Body", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/messages/1/body", nil)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusOK {
			t.Logf("Successfully retrieved message body")
		}
	})

	t.Run("GetMessage_BodyHTML", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/messages/1/body?format=html", nil)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GetMessage_BodyText", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/messages/1/body?format=text", nil)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GetMessage_Raw", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/messages/1/raw", nil)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusOK {
			// Check content type
			contentType := resp.Header.Get("Content-Type")
			if contentType != "message/rfc822" && contentType != "text/plain" {
				t.Logf("Warning: unexpected content type: %s", contentType)
			}
		}
	})
}

// TestMessageFlags tests message flag operations
func TestMessageFlags(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Note: These tests need actual messages to work properly
	// Testing against non-existent messages to verify error handling

	t.Run("UpdateFlags_AddFlags", func(t *testing.T) {
		updateReq := map[string]any{
			"add_flags": []string{"Seen", "Flagged"},
		}
		resp := tc.makeRequest(t, "PATCH", "/user/messages/1", updateReq)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})

	t.Run("UpdateFlags_RemoveFlags", func(t *testing.T) {
		updateReq := map[string]any{
			"remove_flags": []string{"Draft"},
		}
		resp := tc.makeRequest(t, "PATCH", "/user/messages/1", updateReq)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})

	t.Run("UpdateFlags_BothAddAndRemove", func(t *testing.T) {
		updateReq := map[string]any{
			"add_flags":    []string{"Seen"},
			"remove_flags": []string{"Draft"},
		}
		resp := tc.makeRequest(t, "PATCH", "/user/messages/1", updateReq)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})

	t.Run("DeleteMessage", func(t *testing.T) {
		resp := tc.makeRequest(t, "DELETE", "/user/messages/1", nil)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 200 or 404, got %d", resp.StatusCode)
		}
	})
}

// TestSieveFilters tests Sieve filter operations
func TestSieveFilters(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	filterName := fmt.Sprintf("test-filter-%d", time.Now().Unix())
	filterContent := `require ["fileinto"];
if header :contains "Subject" "[SPAM]" {
  fileinto "Junk";
}`

	t.Run("ListFilters_Empty", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/filters", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		scripts, ok := result["scripts"].([]any)
		if !ok {
			t.Fatal("Expected scripts array in response")
		}

		t.Logf("Found %d filters", len(scripts))
	})

	t.Run("CreateFilter", func(t *testing.T) {
		createReq := map[string]string{
			"script": filterContent,
		}
		resp := tc.makeRequest(t, "PUT", fmt.Sprintf("/user/filters/%s", filterName), createReq)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200 or 201, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully created filter")
	})

	t.Run("GetFilter", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", fmt.Sprintf("/user/filters/%s", filterName), nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		if result["name"] != filterName {
			t.Fatalf("Expected name '%s', got %v", filterName, result["name"])
		}

		if result["script"] != filterContent {
			t.Fatalf("Expected script to match")
		}

		t.Logf("Successfully retrieved filter")
	})

	t.Run("UpdateFilter", func(t *testing.T) {
		updatedContent := `require ["fileinto", "vacation"];
if header :contains "Subject" "[SPAM]" {
  fileinto "Junk";
}`
		updateReq := map[string]string{
			"script": updatedContent,
		}
		resp := tc.makeRequest(t, "PUT", fmt.Sprintf("/user/filters/%s", filterName), updateReq)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully updated filter")
	})

	t.Run("ActivateFilter", func(t *testing.T) {
		resp := tc.makeRequest(t, "POST", fmt.Sprintf("/user/filters/%s/activate", filterName), nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully activated filter")
	})

	t.Run("GetCapabilities", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/filters/capabilities", nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		extensions, ok := result["extensions"].([]any)
		if !ok {
			t.Fatal("Expected extensions array in response")
		}

		t.Logf("Sieve supports %d extensions", len(extensions))
	})

	t.Run("DeleteFilter", func(t *testing.T) {
		resp := tc.makeRequest(t, "DELETE", fmt.Sprintf("/user/filters/%s", filterName), nil)
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("Successfully deleted filter")
	})

	t.Run("GetFilter_AfterDelete", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", fmt.Sprintf("/user/filters/%s", filterName), nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 404 after deletion, got %d", resp.StatusCode)
		}
	})
}

// TestSearchFunctionality tests search operations
func TestSearchFunctionality(t *testing.T) {
	tc := setupTestServer(t)

	// Login first
	loginReq := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	resp := tc.makeRequest(t, "POST", "/user/auth/login", loginReq)
	var loginResp map[string]any
	parseJSON(t, resp, &loginResp)
	tc.JWTToken = loginResp["token"].(string)

	// Create INBOX for search tests
	createReq := map[string]string{"name": "INBOX"}
	tc.makeRequest(t, "POST", "/user/mailboxes", createReq)

	t.Run("Search_BasicQuery", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q=test", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)

		if result["query"] != "test" {
			t.Fatalf("Expected query 'test', got %v", result["query"])
		}
	})

	t.Run("Search_WithFromFilter", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q=test&from=sender@example.com", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)
		t.Logf("Search with from filter returned %v results", result["total"])
	})

	t.Run("Search_WithSubjectFilter", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q=test&subject=important", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)
		t.Logf("Search with subject filter returned %v results", result["total"])
	})

	t.Run("Search_UnseenOnly", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/INBOX/search?q=test&unseen=true", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		parseJSON(t, resp, &result)
		t.Logf("Search for unseen messages returned %v results", result["total"])
	})

	t.Run("Search_NonexistentMailbox", func(t *testing.T) {
		resp := tc.makeRequest(t, "GET", "/user/mailboxes/NonexistentFolder/search?q=test", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d", resp.StatusCode)
		}
	})
}

// TLS Tests
// =============================================================================

// setupTestServerWithTLS creates a test HTTP User API server with actual TLS
func setupTestServerWithTLS(t *testing.T, tlsConfig *tls.Config, useTLSConfig bool) (*TestContext, string) {
	t.Helper()

	// Skip if database unavailable
	common.SkipIfDatabaseUnavailable(t)

	// Setup database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	account := common.CreateTestAccount(t, rdb)

	// Get random port
	addr := common.GetRandomAddress(t)

	// Create server options with TLS
	serverOptions := userapi.ServerOptions{
		Name:           "test-server-tls",
		Addr:           addr,
		JWTSecret:      "test-secret-key-for-testing-only",
		TokenDuration:  1 * time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		Storage:        nil, // Can be nil for metadata-only tests
		Cache:          nil, // Can be nil for tests
		TLS:            true,
	}

	if useTLSConfig {
		// Use TLS config from manager
		serverOptions.TLSConfig = tlsConfig
	} else {
		// Use static certificate files
		serverOptions.TLSCertFile = "../../testdata/sora.crt"
		serverOptions.TLSKeyFile = "../../testdata/sora.key"
	}

	_, err := userapi.New(rdb, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go userapi.Start(ctx, rdb, serverOptions, errChan)

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Check if server started successfully
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP User API server: %v", err)
	default:
		// Server started successfully
	}

	baseURL := fmt.Sprintf("https://%s", addr)

	// Create HTTPS client
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip verification for self-signed test cert
			},
		},
	}

	tc := &TestContext{
		Server:     nil, // Not using httptest.Server for TLS tests
		RDB:        rdb,
		HTTPClient: client,
		TestUser:   account,
	}

	t.Cleanup(func() {
		cancel()
	})

	return tc, baseURL
}

func TestHTTPUserAPI_TLS_StaticCertificates(t *testing.T) {
	tc, baseURL := setupTestServerWithTLS(t, nil, false)

	// Test login endpoint over HTTPS
	loginBody := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	body, _ := json.Marshal(loginBody)

	resp, err := tc.HTTPClient.Post(baseURL+"/user/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to make HTTPS login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to get token
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	if loginResp.Token == "" {
		t.Fatal("Expected token in response")
	}

	t.Log("✓ HTTP User API works correctly with static TLS certificates")
}

func TestHTTPUserAPI_TLS_TLSManager(t *testing.T) {
	// Load test certificate for TLS manager simulation
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	// Create TLS config simulating what the TLS manager would provide
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	tc, baseURL := setupTestServerWithTLS(t, tlsConfig, true)

	// Test login endpoint over HTTPS
	loginBody := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	body, _ := json.Marshal(loginBody)

	resp, err := tc.HTTPClient.Post(baseURL+"/user/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to make HTTPS login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to get token
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	if loginResp.Token == "" {
		t.Fatal("Expected token in response")
	}

	t.Log("✓ HTTP User API works correctly with TLS config from manager")
}

func TestHTTPUserAPI_TLS_WithoutInsecureSkipVerify(t *testing.T) {
	tc, baseURL := setupTestServerWithTLS(t, nil, false)

	// Create HTTPS client WITHOUT InsecureSkipVerify
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Don't skip verification
			},
		},
	}

	// Test login endpoint - should fail with certificate error
	loginBody := map[string]string{
		"email":    tc.TestUser.Email,
		"password": tc.TestUser.Password,
	}
	body, _ := json.Marshal(loginBody)

	resp, err := client.Post(baseURL+"/user/auth/login", "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected TLS verification error, but request succeeded")
	}

	// Verify the error is certificate-related
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("Expected certificate error, got: %v", err)
	}

	t.Logf("✓ TLS certificate verification correctly fails for self-signed cert: %v", err)
}

// TestAuthRateLimiting tests authentication rate limiting on the User API
func TestAuthRateLimiting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("IP_Blocking_After_Failed_Attempts", func(t *testing.T) {
		// Setup database and account
		rdb := common.SetupTestDatabase(t)
		account := common.CreateTestAccount(t, rdb)

		// Create server with aggressive rate limiting
		serverOptions := userapi.ServerOptions{
			Name:          "test-server-rate-limit-1",
			Addr:          "127.0.0.1:0",
			JWTSecret:     "test-secret-key",
			TokenDuration: 1 * time.Hour,
			TokenIssuer:   "test-issuer",
			Storage:       nil,
			Cache:         nil,
			TLS:           false,
			AuthRateLimit: server.AuthRateLimiterConfig{
				Enabled:          true,
				MaxAttemptsPerIP: 3, // Block after 3 failures
				IPBlockDuration:  1 * time.Minute,
				IPWindowDuration: 5 * time.Minute,
			},
		}

		srv, err := userapi.New(rdb, serverOptions)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		router := srv.SetupRoutes()
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		client := testServer.Client()
		// Make 3 failed login attempts
		for i := 0; i < 3; i++ {
			loginBody := map[string]string{
				"email":    account.Email,
				"password": fmt.Sprintf("wrongpassword%d", i),
			}
			body, _ := json.Marshal(loginBody)

			resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("Request %d failed: %v", i+1, err)
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Attempt %d: Expected 401, got %d", i+1, resp.StatusCode)
			}
			resp.Body.Close()
			t.Logf("Failed attempt %d: Got expected 401 Unauthorized", i+1)
		}

		// 4th attempt should be blocked with 429
		loginBody := map[string]string{
			"email":    account.Email,
			"password": account.Password, // Even with correct password!
		}
		body, _ := json.Marshal(loginBody)

		resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("4th request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusTooManyRequests {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected 429 Too Many Requests, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
		}

		t.Logf("✓ IP successfully blocked after 3 failed attempts (got 429)")
	})

	t.Run("Success_Resets_Failure_Count", func(t *testing.T) {
		// Setup database and account
		rdb := common.SetupTestDatabase(t)
		account := common.CreateTestAccount(t, rdb)

		// Create server with aggressive rate limiting
		serverOptions := userapi.ServerOptions{
			Name:          "test-server-rate-limit-2",
			Addr:          "127.0.0.1:0",
			JWTSecret:     "test-secret-key",
			TokenDuration: 1 * time.Hour,
			TokenIssuer:   "test-issuer",
			Storage:       nil,
			Cache:         nil,
			TLS:           false,
			AuthRateLimit: server.AuthRateLimiterConfig{
				Enabled:          true,
				MaxAttemptsPerIP: 3, // Block after 3 failures
				IPBlockDuration:  1 * time.Minute,
				IPWindowDuration: 5 * time.Minute,
			},
		}

		srv, err := userapi.New(rdb, serverOptions)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		router := srv.SetupRoutes()
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		client := testServer.Client()

		// Make 2 failed attempts
		for i := 0; i < 2; i++ {
			loginBody := map[string]string{
				"email":    account.Email,
				"password": "wrongpassword",
			}
			body, _ := json.Marshal(loginBody)

			resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("Failed request: %v", err)
			}
			resp.Body.Close()
		}

		// Successful login should reset counter
		loginBody := map[string]string{
			"email":    account.Email,
			"password": account.Password,
		}
		body, _ := json.Marshal(loginBody)

		resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("Success login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
		}

		// Now we should be able to make 2 more failed attempts without blocking
		for i := 0; i < 2; i++ {
			loginBody := map[string]string{
				"email":    account.Email,
				"password": "wrongpassword",
			}
			body, _ := json.Marshal(loginBody)

			resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected 401, got %d", resp.StatusCode)
			}
			resp.Body.Close()
		}

		// Should still be able to login successfully (not blocked)
		loginBody = map[string]string{
			"email":    account.Email,
			"password": account.Password,
		}
		body, _ = json.Marshal(loginBody)

		resp, err = client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("Final login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK after reset, got %d", resp.StatusCode)
		}

		t.Logf("✓ Successful authentication resets failure count")
	})
}
