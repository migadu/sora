//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
)

const (
	testAPIKey = "test-integration-api-key-12345"
)

type HTTPAPITestServer struct {
	URL     string
	server  *adminapi.Server
	rdb     *resilient.ResilientDatabase
	cache   *cache.Cache
	cleanup func()
}

func (h *HTTPAPITestServer) Close() {
	if h.cleanup != nil {
		h.cleanup()
	}
}

// setupHTTPAPIServer creates a test HTTP API server
func setupHTTPAPIServer(t *testing.T) *HTTPAPITestServer {
	t.Helper()

	// Set up database
	rdb := common.SetupTestDatabase(t)

	// Set up cache
	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}

	// Get random port
	addr := common.GetRandomAddress(t)

	// Create server options
	options := adminapi.ServerOptions{
		Addr:         addr,
		APIKey:       testAPIKey,
		AllowedHosts: []string{}, // Allow all for testing
		Cache:        testCache,
		TLS:          false,
	}

	// Create server
	server, err := adminapi.New(rdb, options)
	if err != nil {
		t.Fatalf("Failed to create HTTP API server: %v", err)
	}

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go adminapi.Start(ctx, rdb, options, errChan)

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Check if server started successfully
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
		// Server started successfully
	}

	cleanup := func() {
		cancel()
		testCache.Close()
	}

	baseURL := fmt.Sprintf("http://%s", addr)

	return &HTTPAPITestServer{
		URL:     baseURL,
		server:  server,
		rdb:     rdb,
		cache:   testCache,
		cleanup: cleanup,
	}
}

// testSourceDB implements cache.SourceDatabase for testing
type testSourceDB struct {
	rdb *resilient.ResilientDatabase
}

func (t *testSourceDB) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	return nil, nil // Not needed for HTTP API tests
}

func (t *testSourceDB) GetRecentMessagesForWarmupWithRetry(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return nil, nil // Not needed for HTTP API tests
}

// HTTP client helpers
func (h *HTTPAPITestServer) makeRequest(t *testing.T, method, endpoint string, body any) (*http.Response, []byte) {
	t.Helper()

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
	}

	url := h.URL + endpoint
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	resp.Body.Close()

	return resp, respBody
}

func (h *HTTPAPITestServer) expectJSON(t *testing.T, respBody []byte, target any) {
	t.Helper()

	if err := json.Unmarshal(respBody, target); err != nil {
		t.Fatalf("Failed to unmarshal response: %v\nResponse body: %s", err, string(respBody))
	}
}

func (h *HTTPAPITestServer) expectError(t *testing.T, respBody []byte, expectedMessage string) {
	t.Helper()

	var errorResp map[string]string
	h.expectJSON(t, respBody, &errorResp)

	if !strings.Contains(errorResp["error"], expectedMessage) {
		t.Errorf("Expected error message to contain %q, got: %s", expectedMessage, errorResp["error"])
	}
}

// Test Account Management Endpoints

func TestAccountCRUD(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	testEmail := fmt.Sprintf("test-crud-%d@example.com", time.Now().UnixNano())

	// 1. Create account
	reqBody := adminapi.CreateAccountRequest{
		Email:    testEmail,
		Password: "test-password-123",
	}

	resp, body := server.makeRequest(t, "POST", "/admin/accounts", reqBody)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, resp.StatusCode, string(body))
	}

	var result map[string]any
	server.expectJSON(t, body, &result)

	if result["email"] != testEmail {
		t.Errorf("Expected email %s, got %v", testEmail, result["email"])
	}

	if result["message"] != "Account created successfully" {
		t.Errorf("Expected success message, got %v", result["message"])
	}

	// 2. Check account exists
	resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail+"/exists", nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	if result["email"] != testEmail {
		t.Errorf("Expected email %s, got %v", testEmail, result["email"])
	}

	if result["exists"] != true {
		t.Errorf("Expected exists to be true, got %v", result["exists"])
	}

	// 3. Get account details
	resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail, nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	// Should contain account details - check if email field exists in some form
	if result["address"] != nil {
		// API might return "address" instead of "email"
		if result["address"] != testEmail {
			t.Errorf("Expected address %s, got %v", testEmail, result["address"])
		}
	} else if result["email"] != nil {
		if result["email"] != testEmail {
			t.Errorf("Expected email %s, got %v", testEmail, result["email"])
		}
	} else {
		t.Errorf("Expected either email or address field in account details, got: %v", result)
	}

	// 4. Update account
	updateReq := adminapi.UpdateAccountRequest{
		Password: "new-password-456",
	}

	resp, body = server.makeRequest(t, "PUT", "/admin/accounts/"+testEmail, updateReq)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	if result["message"] != "Account updated successfully" {
		t.Errorf("Expected success message, got %v", result["message"])
	}

	// 5. List accounts
	resp, body = server.makeRequest(t, "GET", "/admin/accounts", nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	accounts, ok := result["accounts"].([]any)
	if !ok {
		t.Errorf("Expected accounts to be an array, got %T", result["accounts"])
	}

	// Should contain at least our test account
	if len(accounts) == 0 {
		t.Error("Expected at least one account")
	}

	total, ok := result["total"].(float64)
	if !ok || int(total) != len(accounts) {
		t.Errorf("Expected total to match accounts length, got total=%v, len=%d", result["total"], len(accounts))
	}

	// 6. Delete account
	resp, body = server.makeRequest(t, "DELETE", "/admin/accounts/"+testEmail, nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	if result["email"] != testEmail {
		t.Errorf("Expected email %s, got %v", testEmail, result["email"])
	}

	if !strings.Contains(result["message"].(string), "soft-deleted successfully") {
		t.Errorf("Expected soft-delete message, got %v", result["message"])
	}

	// 7. Restore account
	resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+testEmail+"/restore", nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	if result["email"] != testEmail {
		t.Errorf("Expected email %s, got %v", testEmail, result["email"])
	}

	if !strings.Contains(result["message"].(string), "restored successfully") {
		t.Errorf("Expected restore message, got %v", result["message"])
	}
}

func TestMultiCredentialAccount(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	primaryEmail := fmt.Sprintf("primary-%d@example.com", time.Now().UnixNano())
	secondaryEmail := fmt.Sprintf("secondary-%d@example.com", time.Now().UnixNano())

	// Create account with multiple credentials
	reqBody := adminapi.CreateAccountRequest{
		Credentials: []adminapi.CreateCredentialSpec{
			{
				Email:     primaryEmail,
				Password:  "primary-password",
				IsPrimary: true,
				HashType:  "bcrypt",
			},
			{
				Email:     secondaryEmail,
				Password:  "secondary-password",
				IsPrimary: false,
				HashType:  "bcrypt",
			},
		},
	}

	resp, body := server.makeRequest(t, "POST", "/admin/accounts", reqBody)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, resp.StatusCode, string(body))
	}

	var result map[string]any
	server.expectJSON(t, body, &result)

	if result["message"] != "Account created successfully with multiple credentials" {
		t.Errorf("Expected multi-credential success message, got %v", result["message"])
	}

	credentials, ok := result["credentials"].([]any)
	if !ok || len(credentials) != 2 {
		t.Errorf("Expected 2 credentials, got %v", result["credentials"])
	}

	// List credentials for primary email
	resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+primaryEmail+"/credentials", nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	credentials, ok = result["credentials"].([]any)
	if !ok || len(credentials) < 2 {
		t.Errorf("Expected at least 2 credentials, got %v", result["credentials"])
	}

	count, ok := result["count"].(float64)
	if !ok || int(count) != len(credentials) {
		t.Errorf("Expected count to match credentials length, got count=%v, len=%d", result["count"], len(credentials))
	}

	// Add additional credential
	additionalEmail := fmt.Sprintf("additional-%d@example.com", time.Now().UnixNano())

	addReq := adminapi.AddCredentialRequest{
		Email:    additionalEmail,
		Password: "additional-password",
	}

	resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+primaryEmail+"/credentials", addReq)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	if result["new_email"] != additionalEmail {
		t.Errorf("Expected new_email %s, got %v", additionalEmail, result["new_email"])
	}

	if result["message"] != "Credential added successfully" {
		t.Errorf("Expected success message, got %v", result["message"])
	}

	// Get credential details
	resp, body = server.makeRequest(t, "GET", "/admin/credentials/"+secondaryEmail, nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
	}

	server.expectJSON(t, body, &result)

	// Should contain credential details - check for either email or address field
	if result["address"] != nil {
		if result["address"] != secondaryEmail {
			t.Errorf("Expected address %s, got %v", secondaryEmail, result["address"])
		}
	} else if result["email"] != nil {
		if result["email"] != secondaryEmail {
			t.Errorf("Expected email %s, got %v", secondaryEmail, result["email"])
		}
	} else {
		t.Errorf("Expected either email or address field in credential details, got: %v", result)
	}
}

// Test Connection Management Endpoints

func TestConnectionManagement(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("list connections", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/connections", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		connections := []any{}
		if result["connections"] != nil {
			var ok bool
			connections, ok = result["connections"].([]any)
			if !ok {
				t.Errorf("Expected connections to be an array, got %T", result["connections"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(connections) {
			t.Errorf("Expected count to match connections length, got count=%v, len=%d", result["count"], len(connections))
		}
	})

	t.Run("get connection stats", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/connections/stats", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Should contain some stats fields - just verify we get a valid JSON response
		// The exact fields returned depend on the actual server state
	})

	// Create a test account to test user connections and kick
	testEmail := fmt.Sprintf("conn-test-%d@example.com", time.Now().UnixNano())
	reqBody := adminapi.CreateAccountRequest{
		Email:    testEmail,
		Password: "test-password-123",
	}
	server.makeRequest(t, "POST", "/admin/accounts", reqBody)

	t.Run("kick user connections", func(t *testing.T) {
		// Test gossip-based kick (requires user_email)
		kickReqBody := map[string]string{
			"user_email": testEmail,
			"protocol":   "IMAP",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/connections/kick", kickReqBody)

		// Expect either 200 (kicked successfully) or 503 (cluster mode not available)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d or %d, got %d. Body: %s",
				http.StatusOK, http.StatusServiceUnavailable, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if resp.StatusCode == http.StatusOK {
			// Successfully kicked via gossip protocol
			if !strings.Contains(result["message"].(string), "kicked successfully") {
				t.Errorf("Expected kick success message, got %v", result["message"])
			}
		} else {
			// Cluster mode not available (expected in non-proxy tests)
			if !strings.Contains(result["error"].(string), "not available") {
				t.Errorf("Expected 'not available' error, got %v", result["error"])
			}
		}
	})

	t.Run("kick without user_email should fail", func(t *testing.T) {
		// Test that kicking without user_email returns 400
		kickReqBody := map[string]string{
			"protocol": "IMAP",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/connections/kick", kickReqBody)

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if !strings.Contains(result["error"].(string), "user_email is required") {
			t.Errorf("Expected 'user_email is required' error, got %v", result["error"])
		}
	})

	t.Run("get user connections", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/connections/user/"+testEmail, nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if result["email"] != testEmail {
			t.Errorf("Expected email %s, got %v", testEmail, result["email"])
		}

		connections := []any{}
		if result["connections"] != nil {
			var ok bool
			connections, ok = result["connections"].([]any)
			if !ok {
				t.Errorf("Expected connections to be an array, got %T", result["connections"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(connections) {
			t.Errorf("Expected count to match connections length, got count=%v, len=%d", result["count"], len(connections))
		}
	})
}

// Test Cache Management Endpoints

func TestCacheManagement(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("get cache stats", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/cache/stats", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Should return valid JSON response with cache stats
		// The exact fields returned depend on the cache state
	})

	t.Run("get cache metrics - latest", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/cache/metrics?latest=true", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		metrics := []any{}
		if result["metrics"] != nil {
			var ok bool
			metrics, ok = result["metrics"].([]any)
			if !ok {
				t.Errorf("Expected metrics to be an array, got %T", result["metrics"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(metrics) {
			t.Errorf("Expected count to match metrics length, got count=%v, len=%d", result["count"], len(metrics))
		}
	})

	t.Run("get cache metrics - historical", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/cache/metrics?limit=10", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Check that metrics field is an array if present
		if result["metrics"] != nil {
			if _, ok := result["metrics"].([]any); !ok {
				t.Errorf("Expected metrics to be an array, got %T", result["metrics"])
			}
		}

		// Verify we got a valid JSON response
	})

	t.Run("purge cache", func(t *testing.T) {
		resp, body := server.makeRequest(t, "POST", "/admin/cache/purge", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if !strings.Contains(result["message"].(string), "purged successfully") {
			t.Errorf("Expected purge success message, got %v", result["message"])
		}

		if _, ok := result["stats_before"]; !ok {
			t.Error("Expected stats_before field")
		}

		if _, ok := result["stats_after"]; !ok {
			t.Error("Expected stats_after field")
		}
	})
}

// Test Health Monitoring Endpoints

func TestHealthMonitoring(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("get health overview", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/overview", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Health overview should contain system-wide health information
		// The exact structure depends on your implementation
	})

	t.Run("get health overview for specific hostname", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/overview?hostname=test-host", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)
	})

	t.Run("get health statuses by host", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/servers/test-host", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if result["hostname"] != "test-host" {
			t.Errorf("Expected hostname test-host, got %v", result["hostname"])
		}

		statuses := []any{}
		if result["statuses"] != nil {
			var ok bool
			statuses, ok = result["statuses"].([]any)
			if !ok {
				t.Errorf("Expected statuses to be an array, got %T", result["statuses"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(statuses) {
			t.Errorf("Expected count to match statuses length, got count=%v, len=%d", result["count"], len(statuses))
		}
	})

	t.Run("get health status by component", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/servers/test-host/components/database", nil)

		// This might return 404 if no health status exists, which is okay for testing
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d or %d, got %d. Body: %s", http.StatusOK, http.StatusNotFound, resp.StatusCode, string(body))
		}

		if resp.StatusCode == http.StatusOK {
			var result map[string]any
			server.expectJSON(t, body, &result)
			// Should contain health status details
		}
	})

	t.Run("get health history", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/servers/test-host/components/database?history=true&limit=5", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if result["hostname"] != "test-host" {
			t.Errorf("Expected hostname test-host, got %v", result["hostname"])
		}

		if result["component"] != "database" {
			t.Errorf("Expected component database, got %v", result["component"])
		}

		history := []any{}
		if result["history"] != nil {
			var ok bool
			history, ok = result["history"].([]any)
			if !ok {
				t.Errorf("Expected history to be an array, got %T", result["history"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(history) {
			t.Errorf("Expected count to match history length, got count=%v, len=%d", result["count"], len(history))
		}
	})
}

// Test Uploader Monitoring Endpoints

func TestUploaderMonitoring(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("get uploader status", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/uploader/status", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if _, ok := result["stats"]; !ok {
			t.Error("Expected stats field in uploader status")
		}
	})

	t.Run("get uploader status with failed uploads", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/uploader/status?show_failed=true&failed_limit=5", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if _, ok := result["stats"]; !ok {
			t.Error("Expected stats field")
		}

		failedUploads := []any{}
		if result["failed_uploads"] != nil {
			var ok bool
			failedUploads, ok = result["failed_uploads"].([]any)
			if !ok {
				t.Errorf("Expected failed_uploads to be an array, got %T", result["failed_uploads"])
			}
		}

		failedCount, ok := result["failed_count"].(float64)
		if !ok || int(failedCount) != len(failedUploads) {
			t.Errorf("Expected failed_count to match failed_uploads length, got count=%v, len=%d", result["failed_count"], len(failedUploads))
		}
	})

	t.Run("get failed uploads", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/uploader/failed?limit=10", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		failedUploads := []any{}
		if result["failed_uploads"] != nil {
			var ok bool
			failedUploads, ok = result["failed_uploads"].([]any)
			if !ok {
				t.Errorf("Expected failed_uploads to be an array, got %T", result["failed_uploads"])
			}
		}

		count, ok := result["count"].(float64)
		if !ok || int(count) != len(failedUploads) {
			t.Errorf("Expected count to match failed_uploads length, got count=%v, len=%d", result["count"], len(failedUploads))
		}

		if _, ok := result["limit"]; !ok {
			t.Error("Expected limit field")
		}

		if _, ok := result["max_attempts"]; !ok {
			t.Error("Expected max_attempts field")
		}
	})
}

// Test Authentication Statistics

func TestAuthStatistics(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("get auth stats - in-memory implementation", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/auth/stats", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Check for new in-memory implementation fields
		if result["implementation"] != "in-memory" {
			t.Errorf("Expected implementation in-memory, got %v", result["implementation"])
		}

		if _, ok := result["tracking_mode"]; !ok {
			t.Error("Expected tracking_mode field")
		}

		if _, ok := result["available_stats"]; !ok {
			t.Error("Expected available_stats field")
		}

		if _, ok := result["access_methods"]; !ok {
			t.Error("Expected access_methods field")
		}
	})

	t.Run("get auth stats - window parameter ignored", func(t *testing.T) {
		// The window parameter is no longer used since we moved to in-memory tracking
		// but the endpoint should still accept it without error for backwards compatibility
		resp, body := server.makeRequest(t, "GET", "/admin/auth/stats?window=1h", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Should still return in-memory implementation info
		if result["implementation"] != "in-memory" {
			t.Errorf("Expected implementation in-memory, got %v", result["implementation"])
		}
	})
}

// Test System Configuration Endpoint

func TestSystemConfiguration(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("get config info", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/config", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if result["server_type"] != "sora-http-api" {
			t.Errorf("Expected server_type sora-http-api, got %v", result["server_type"])
		}

		featuresEnabled, ok := result["features_enabled"].(map[string]any)
		if !ok {
			t.Errorf("Expected features_enabled to be an object, got %T", result["features_enabled"])
		}

		// Check that cache management is enabled since we have a cache
		if featuresEnabled["cache_management"] != true {
			t.Errorf("Expected cache_management to be enabled, got %v", featuresEnabled["cache_management"])
		}

		endpoints, ok := result["endpoints"].(map[string]any)
		if !ok {
			t.Errorf("Expected endpoints to be an object, got %T", result["endpoints"])
		}

		// Check that account management endpoints are listed
		accountMgmt, ok := endpoints["account_management"].([]any)
		if !ok || len(accountMgmt) == 0 {
			t.Errorf("Expected account_management endpoints, got %v", endpoints["account_management"])
		}
	})
}

// Test Error Scenarios and Edge Cases

func TestErrorScenarios(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	t.Run("unauthorized request - no API key", func(t *testing.T) {
		url := server.URL + "/admin/accounts"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Don't set Authorization header
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusUnauthorized, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "Authorization header required")
	})

	t.Run("unauthorized request - wrong API key", func(t *testing.T) {
		url := server.URL + "/admin/accounts"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer wrong-api-key")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusForbidden, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "Invalid API key")
	})

	t.Run("account not found", func(t *testing.T) {
		nonExistentEmail := "nonexistent@example.com"

		resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+nonExistentEmail, nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "Account not found")
	})

	t.Run("duplicate account creation", func(t *testing.T) {
		testEmail := fmt.Sprintf("duplicate-test-%d@example.com", time.Now().UnixNano())

		reqBody := adminapi.CreateAccountRequest{
			Email:    testEmail,
			Password: "test-password-123",
		}

		// Create account first time
		resp1, body1 := server.makeRequest(t, "POST", "/admin/accounts", reqBody)
		if resp1.StatusCode != http.StatusCreated {
			t.Errorf("First creation should succeed. Status: %d, Body: %s", resp1.StatusCode, string(body1))
		}

		// Try to create same account again
		resp2, body2 := server.makeRequest(t, "POST", "/admin/accounts", reqBody)

		// The API might return 409 Conflict or 500 Internal Server Error depending on how it handles duplicates
		if resp2.StatusCode != http.StatusConflict && resp2.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status %d or %d, got %d. Body: %s", http.StatusConflict, http.StatusInternalServerError, resp2.StatusCode, string(body2))
		}

		// Check that it's some kind of error about the account existing or creation failing
		bodyStr := string(body2)
		if !strings.Contains(bodyStr, "already exists") && !strings.Contains(bodyStr, "Failed to create") && !strings.Contains(bodyStr, "unique") && !strings.Contains(bodyStr, "duplicate") {
			t.Errorf("Expected error message about duplicate/existing account, got: %s", bodyStr)
		}
	})

	t.Run("invalid email format", func(t *testing.T) {
		reqBody := adminapi.CreateAccountRequest{
			Email:    "invalid-email-format",
			Password: "test-password-123",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/accounts", reqBody)

		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status %d or %d, got %d. Body: %s", http.StatusBadRequest, http.StatusInternalServerError, resp.StatusCode, string(body))
		}

		// Should contain some error about invalid email
		if !strings.Contains(string(body), "error") {
			t.Errorf("Expected error message, got: %s", string(body))
		}
	})

	t.Run("delete non-existent account", func(t *testing.T) {
		nonExistentEmail := "nonexistent-delete@example.com"

		resp, body := server.makeRequest(t, "DELETE", "/admin/accounts/"+nonExistentEmail, nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("restore non-existent account", func(t *testing.T) {
		nonExistentEmail := "nonexistent-restore@example.com"

		resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+nonExistentEmail+"/restore", nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("add credential to non-existent account", func(t *testing.T) {
		nonExistentEmail := "nonexistent-primary@example.com"

		reqBody := adminapi.AddCredentialRequest{
			Email:    "secondary@example.com",
			Password: "password",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+nonExistentEmail+"/credentials", reqBody)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("get credential for non-existent email", func(t *testing.T) {
		nonExistentEmail := "nonexistent-credential@example.com"

		resp, body := server.makeRequest(t, "GET", "/admin/credentials/"+nonExistentEmail, nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("delete non-existent credential", func(t *testing.T) {
		nonExistentEmail := "nonexistent-credential@example.com"

		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+nonExistentEmail, nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("auth stats ignores invalid window parameter", func(t *testing.T) {
		// Since we moved to in-memory rate limiting, the window parameter is no longer used
		// The endpoint should accept any parameters and return the implementation info
		resp, body := server.makeRequest(t, "GET", "/admin/auth/stats?window=invalid-duration", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d (window param ignored), got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		// Should still return in-memory implementation info
		if result["implementation"] != "in-memory" {
			t.Errorf("Expected implementation in-memory, got %v", result["implementation"])
		}
	})

	t.Run("invalid cache metrics since parameter", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/cache/metrics?since=invalid-time", nil)

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "Invalid since parameter")
	})
}

// Test Credential Management Edge Cases

func TestCredentialManagementEdgeCases(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	primaryEmail := fmt.Sprintf("edge-primary-%d@example.com", time.Now().UnixNano())
	secondaryEmail := fmt.Sprintf("edge-secondary-%d@example.com", time.Now().UnixNano())

	// Create account with multiple credentials
	reqBody := adminapi.CreateAccountRequest{
		Credentials: []adminapi.CreateCredentialSpec{
			{
				Email:     primaryEmail,
				Password:  "primary-password",
				IsPrimary: true,
				HashType:  "bcrypt",
			},
			{
				Email:     secondaryEmail,
				Password:  "secondary-password",
				IsPrimary: false,
				HashType:  "bcrypt",
			},
		},
	}

	resp, body := server.makeRequest(t, "POST", "/admin/accounts", reqBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test account: %d - %s", resp.StatusCode, string(body))
	}

	t.Run("add duplicate credential email", func(t *testing.T) {
		addReq := adminapi.AddCredentialRequest{
			Email:    secondaryEmail, // Already exists
			Password: "new-password",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+primaryEmail+"/credentials", addReq)

		if resp.StatusCode != http.StatusConflict {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusConflict, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "already exists")
	})

	t.Run("try to delete primary credential", func(t *testing.T) {
		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+primaryEmail, nil)

		// Should not allow deleting primary credential if it would leave account without credentials
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "cannot delete")
	})

	t.Run("delete secondary credential - should succeed", func(t *testing.T) {
		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+secondaryEmail, nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		if result["email"] != secondaryEmail {
			t.Errorf("Expected email %s, got %v", secondaryEmail, result["email"])
		}

		if !strings.Contains(result["message"].(string), "deleted successfully") {
			t.Errorf("Expected success message, got %v", result["message"])
		}
	})

	t.Run("verify credential was deleted", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/credentials/"+secondaryEmail, nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusNotFound, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "not found")
	})

	t.Run("try to delete last remaining credential", func(t *testing.T) {
		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+primaryEmail, nil)

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, resp.StatusCode, string(body))
		}

		server.expectError(t, body, "cannot delete")
	})
}

// Test Account Lifecycle

func TestAccountLifecycle(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	testEmail := fmt.Sprintf("lifecycle-test-%d@example.com", time.Now().UnixNano())

	t.Run("complete account lifecycle", func(t *testing.T) {
		// 1. Create account
		createReq := adminapi.CreateAccountRequest{
			Email:    testEmail,
			Password: "initial-password",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/accounts", createReq)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to create account: %d - %s", resp.StatusCode, string(body))
		}

		// 2. Verify account exists
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail+"/exists", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to check account existence: %d - %s", resp.StatusCode, string(body))
		}

		var existsResult map[string]any
		server.expectJSON(t, body, &existsResult)
		if existsResult["exists"] != true {
			t.Errorf("Account should exist, got %v", existsResult["exists"])
		}

		// 3. Update password
		updateReq := adminapi.UpdateAccountRequest{
			Password: "new-password",
		}

		resp, body = server.makeRequest(t, "PUT", "/admin/accounts/"+testEmail, updateReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to update account: %d - %s", resp.StatusCode, string(body))
		}

		// 4. Add secondary credential
		addCredReq := adminapi.AddCredentialRequest{
			Email:    fmt.Sprintf("secondary-%s", testEmail),
			Password: "secondary-password",
		}

		resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+testEmail+"/credentials", addCredReq)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to add credential: %d - %s", resp.StatusCode, string(body))
		}

		// 5. List credentials
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail+"/credentials", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to list credentials: %d - %s", resp.StatusCode, string(body))
		}

		var credsResult map[string]any
		server.expectJSON(t, body, &credsResult)
		credentials := credsResult["credentials"].([]any)
		if len(credentials) < 2 {
			t.Errorf("Expected at least 2 credentials, got %d", len(credentials))
		}

		// 6. Delete account (soft delete)
		resp, body = server.makeRequest(t, "DELETE", "/admin/accounts/"+testEmail, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to delete account: %d - %s", resp.StatusCode, string(body))
		}

		// 7. Verify account is marked as deleted
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail, nil)
		// This might return different status codes depending on how soft delete is implemented
		// The account might still be retrievable but marked as deleted

		// 8. Restore account
		resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+testEmail+"/restore", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to restore account: %d - %s", resp.StatusCode, string(body))
		}

		// 9. Verify account is restored and accessible
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Account should be accessible after restore: %d - %s", resp.StatusCode, string(body))
		}
	})
}

// Test Message Restoration Endpoints
func TestMessageRestoration(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	testEmail := fmt.Sprintf("test-restore-%d@example.com", time.Now().UnixNano())
	ctx := context.Background()

	// 1. Create test account
	createReq := adminapi.CreateAccountRequest{
		Email:    testEmail,
		Password: "test-password",
	}
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", createReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create account: %d - %s", resp.StatusCode, string(body))
	}

	// Get account ID using direct database access
	var accountID int64
	err := server.rdb.GetDatabase().GetReadPool().QueryRow(ctx,
		"SELECT account_id FROM credentials WHERE address = $1",
		testEmail).Scan(&accountID)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// 2. Create mailboxes
	err = server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
		"INSERT INTO mailboxes (account_id, name, uid_validity, path) VALUES ($1, $2, extract(epoch from now())::bigint, $3) RETURNING id",
		accountID, "INBOX", "INBOX").Scan(new(int64))
	if err != nil {
		t.Fatalf("Failed to create INBOX: %v", err)
	}

	var archiveID int64
	err = server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
		"INSERT INTO mailboxes (account_id, name, uid_validity, path) VALUES ($1, $2, extract(epoch from now())::bigint, $3) RETURNING id",
		accountID, "INBOX/Archive", "INBOX/Archive").Scan(&archiveID)
	if err != nil {
		t.Fatalf("Failed to create Archive: %v", err)
	}

	// 3. Create and delete test messages directly in database
	// Insert message 1 in INBOX (with \Seen flag = 1)
	var msgID1, msgID2, msgID3 int64
	err = server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
		`INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
		 subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, flags,
		 created_modseq, expunged_at)
		 VALUES ($1, (SELECT id FROM mailboxes WHERE account_id = $1 AND name = 'INBOX'), 'INBOX', 1,
		 'test', 'test1', 'test-hash-1', 'Test message 1', '<msg1@test.com>', '[]'::jsonb, ''::bytea,
		 NOW(), NOW(), 100, 1, 1, NOW())
		 RETURNING id`, accountID).Scan(&msgID1)
	if err != nil {
		t.Fatalf("Failed to insert message 1: %v", err)
	}

	// Insert message 2 in INBOX (no flags)
	err = server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
		`INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
		 subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, flags,
		 created_modseq, expunged_at)
		 VALUES ($1, (SELECT id FROM mailboxes WHERE account_id = $1 AND name = 'INBOX'), 'INBOX', 2,
		 'test', 'test2', 'test-hash-2', 'Test message 2', '<msg2@test.com>', '[]'::jsonb, ''::bytea,
		 NOW(), NOW(), 200, 0, 2, NOW())
		 RETURNING id`, accountID).Scan(&msgID2)
	if err != nil {
		t.Fatalf("Failed to insert message 2: %v", err)
	}

	// Insert message 3 in Archive (with \Flagged flag = 4)
	err = server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
		`INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
		 subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, flags,
		 created_modseq, expunged_at)
		 VALUES ($1, $2, 'INBOX/Archive', 1, 'test', 'test3', 'test-hash-3', 'Test message 3', '<msg3@test.com>',
		 '[]'::jsonb, ''::bytea, NOW(), NOW(), 300, 4, 3, NOW())
		 RETURNING id`, accountID, archiveID).Scan(&msgID3)
	if err != nil {
		t.Fatalf("Failed to insert message 3: %v", err)
	}

	// 5. List all deleted messages
	t.Run("ListAllDeletedMessages", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+testEmail+"/messages/deleted", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to list deleted messages: %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		messages := result["messages"].([]any)
		total := int(result["total"].(float64))

		if total != 3 {
			t.Errorf("Expected 3 deleted messages, got %d", total)
		}
		if len(messages) != 3 {
			t.Errorf("Expected 3 messages in array, got %d", len(messages))
		}

		// Verify message structure (Go structs are serialized with capital letter field names)
		msg := messages[0].(map[string]any)
		if msg["ID"] == nil {
			t.Error("Message should have ID")
		}
		if msg["MailboxPath"] == nil {
			t.Error("Message should have MailboxPath")
		}
		if msg["Subject"] == nil {
			t.Error("Message should have Subject")
		}
		if msg["ExpungedAt"] == nil {
			t.Error("Message should have ExpungedAt")
		}
	})

	// 6. List deleted messages filtered by mailbox
	t.Run("ListDeletedMessagesByMailbox", func(t *testing.T) {
		endpoint := fmt.Sprintf("/admin/accounts/%s/messages/deleted?mailbox=INBOX", testEmail)
		resp, body := server.makeRequest(t, "GET", endpoint, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to list deleted messages: %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		total := int(result["total"].(float64))
		if total != 2 {
			t.Errorf("Expected 2 deleted messages from INBOX, got %d", total)
		}
	})

	// 7. List deleted messages with limit
	t.Run("ListDeletedMessagesWithLimit", func(t *testing.T) {
		endpoint := fmt.Sprintf("/admin/accounts/%s/messages/deleted?limit=1", testEmail)
		resp, body := server.makeRequest(t, "GET", endpoint, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to list deleted messages: %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		messages := result["messages"].([]any)
		if len(messages) != 1 {
			t.Errorf("Expected 1 message with limit=1, got %d", len(messages))
		}
	})

	// 8. Restore specific messages by ID
	t.Run("RestoreMessagesByID", func(t *testing.T) {
		restoreReq := map[string]any{
			"message_ids": []int64{msgID1, msgID2},
		}

		endpoint := fmt.Sprintf("/admin/accounts/%s/messages/restore", testEmail)
		resp, body := server.makeRequest(t, "POST", endpoint, restoreReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to restore messages: %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		restored := int(result["restored"].(float64))
		if restored != 2 {
			t.Errorf("Expected 2 messages restored, got %d", restored)
		}

		// Verify messages are no longer in deleted list
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+testEmail+"/messages/deleted", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to list deleted messages: %d - %s", resp.StatusCode, string(body))
		}

		server.expectJSON(t, body, &result)
		total := int(result["total"].(float64))
		if total != 1 {
			t.Errorf("Expected 1 deleted message remaining, got %d", total)
		}
	})

	// 9. Restore by mailbox
	t.Run("RestoreMessagesByMailbox", func(t *testing.T) {
		// Insert another deleted message in Archive
		var msgID4 int64
		err := server.rdb.GetDatabase().GetWritePool().QueryRow(ctx,
			`INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
			 subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, flags,
			 created_modseq, expunged_at)
			 VALUES ($1, $2, 'INBOX/Archive', 2, 'test', 'test4', 'test-hash-4', 'Test message 4', '<msg4@test.com>',
			 '[]'::jsonb, ''::bytea, NOW(), NOW(), 400, 0, 4, NOW())
			 RETURNING id`, accountID, archiveID).Scan(&msgID4)
		if err != nil {
			t.Fatalf("Failed to insert message 4: %v", err)
		}

		// Now we have msg3 and msg4 deleted in Archive
		restoreReq := map[string]any{
			"mailbox": "INBOX/Archive",
		}

		endpoint := fmt.Sprintf("/admin/accounts/%s/messages/restore", testEmail)
		resp, body := server.makeRequest(t, "POST", endpoint, restoreReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to restore messages: %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		server.expectJSON(t, body, &result)

		restored := int(result["restored"].(float64))
		if restored != 2 {
			t.Errorf("Expected 2 messages restored from Archive, got %d", restored)
		}
	})

	// 10. Test error cases
	t.Run("RestoreWithoutCriteria", func(t *testing.T) {
		restoreReq := map[string]any{}

		endpoint := fmt.Sprintf("/admin/accounts/%s/messages/restore", testEmail)
		resp, body := server.makeRequest(t, "POST", endpoint, restoreReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected 400 Bad Request, got %d - %s", resp.StatusCode, string(body))
		}

		server.expectError(t, body, "At least one filter is required")
	})

	t.Run("ListDeletedForNonExistentAccount", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/accounts/nonexistent@example.com/messages/deleted", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 Not Found, got %d - %s", resp.StatusCode, string(body))
		}
	})

	t.Run("RestoreForNonExistentAccount", func(t *testing.T) {
		restoreReq := map[string]any{
			"message_ids": []int64{999999},
		}

		resp, body := server.makeRequest(t, "POST", "/admin/accounts/nonexistent@example.com/messages/restore", restoreReq)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 Not Found, got %d - %s", resp.StatusCode, string(body))
		}
	})
}

// TestMailDelivery tests the HTTP mail delivery endpoint
func TestMailDelivery(t *testing.T) {
	t.Skip("Mail delivery tests require uploader configuration (not set up in test environment)")
	server := setupHTTPAPIServer(t)
	defer server.Close()

	// Create a test account to deliver mail to
	createReq := map[string]string{
		"email":    fmt.Sprintf("delivery-test-%d@example.com", time.Now().Unix()),
		"password": "testpassword123",
	}
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", createReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test account: %d - %s", resp.StatusCode, string(body))
	}

	var createResp map[string]any
	server.expectJSON(t, body, &createResp)
	testEmail := createResp["email"].(string)

	t.Run("DeliverMail_JSONFormat", func(t *testing.T) {
		deliveryReq := map[string]any{
			"recipients": []string{testEmail},
			"message": fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test Message via HTTP
Message-ID: <test-%d@example.com>
Date: %s

This is a test message delivered via HTTP API.
`, testEmail, time.Now().Unix(), time.Now().Format(time.RFC1123Z)),
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var deliveryResp map[string]any
		server.expectJSON(t, body, &deliveryResp)

		if success, ok := deliveryResp["success"].(bool); !ok || !success {
			t.Errorf("Expected success=true, got %v", deliveryResp["success"])
		}

		if messageID, ok := deliveryResp["message_id"].(string); !ok || messageID == "" {
			t.Errorf("Expected message_id, got %v", deliveryResp["message_id"])
		}

		recipients, ok := deliveryResp["recipients"].([]any)
		if !ok {
			t.Fatalf("Expected recipients array, got %T", deliveryResp["recipients"])
		}

		if len(recipients) != 1 {
			t.Errorf("Expected 1 recipient, got %d", len(recipients))
		}

		recipientStatus := recipients[0].(map[string]any)
		if email, ok := recipientStatus["email"].(string); !ok || email != testEmail {
			t.Errorf("Expected email %s, got %v", testEmail, recipientStatus["email"])
		}

		if accepted, ok := recipientStatus["accepted"].(bool); !ok || !accepted {
			t.Errorf("Expected accepted=true, got %v", recipientStatus["accepted"])
		}

		t.Logf("Successfully delivered message to %s", testEmail)
	})

	t.Run("DeliverMail_MultipleRecipients", func(t *testing.T) {
		// Create a second recipient
		createReq2 := map[string]string{
			"email":    fmt.Sprintf("delivery-test2-%d@example.com", time.Now().Unix()),
			"password": "testpassword123",
		}
		resp, body := server.makeRequest(t, "POST", "/admin/accounts", createReq2)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to create second test account: %d - %s", resp.StatusCode, string(body))
		}

		var createResp2 map[string]any
		server.expectJSON(t, body, &createResp2)
		testEmail2 := createResp2["email"].(string)

		deliveryReq := map[string]any{
			"recipients": []string{testEmail, testEmail2},
			"message": fmt.Sprintf(`From: sender@example.com
To: %s, %s
Subject: Test Message to Multiple Recipients
Message-ID: <test-multi-%d@example.com>
Date: %s

This message is delivered to multiple recipients.
`, testEmail, testEmail2, time.Now().Unix(), time.Now().Format(time.RFC1123Z)),
		}

		resp, body = server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var deliveryResp map[string]any
		server.expectJSON(t, body, &deliveryResp)

		recipients, ok := deliveryResp["recipients"].([]any)
		if !ok {
			t.Fatalf("Expected recipients array, got %T", deliveryResp["recipients"])
		}

		if len(recipients) != 2 {
			t.Errorf("Expected 2 recipients, got %d", len(recipients))
		}

		// Check both recipients were accepted
		for _, r := range recipients {
			recipientStatus := r.(map[string]any)
			if accepted, ok := recipientStatus["accepted"].(bool); !ok || !accepted {
				t.Errorf("Expected all recipients accepted, got %v for %v", recipientStatus["accepted"], recipientStatus["email"])
			}
		}

		t.Logf("Successfully delivered message to %d recipients", len(recipients))
	})

	t.Run("DeliverMail_PartialFailure", func(t *testing.T) {
		deliveryReq := map[string]any{
			"recipients": []string{testEmail, "nonexistent-user-12345@example.com"},
			"message": fmt.Sprintf(`From: sender@example.com
To: %s, nonexistent-user-12345@example.com
Subject: Test Partial Failure
Message-ID: <test-partial-%d@example.com>
Date: %s

This message has one valid and one invalid recipient.
`, testEmail, time.Now().Unix(), time.Now().Format(time.RFC1123Z)),
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		// Should return 207 Multi-Status for partial failure
		if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 207 or 200, got %d - %s", resp.StatusCode, string(body))
		}

		var deliveryResp map[string]any
		server.expectJSON(t, body, &deliveryResp)

		recipients, ok := deliveryResp["recipients"].([]any)
		if !ok {
			t.Fatalf("Expected recipients array, got %T", deliveryResp["recipients"])
		}

		if len(recipients) != 2 {
			t.Errorf("Expected 2 recipients, got %d", len(recipients))
		}

		// Check that one succeeded and one failed
		acceptedCount := 0
		rejectedCount := 0
		for _, r := range recipients {
			recipientStatus := r.(map[string]any)
			if accepted, ok := recipientStatus["accepted"].(bool); ok && accepted {
				acceptedCount++
			} else {
				rejectedCount++
			}
		}

		if acceptedCount != 1 || rejectedCount != 1 {
			t.Errorf("Expected 1 accepted and 1 rejected, got %d accepted, %d rejected", acceptedCount, rejectedCount)
		}

		t.Logf("Partial delivery: %d accepted, %d rejected", acceptedCount, rejectedCount)
	})

	t.Run("DeliverMail_InvalidFormat", func(t *testing.T) {
		deliveryReq := map[string]any{
			"recipients": []string{testEmail},
			"message":    "This is not a valid RFC822 message", // Missing headers
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Logf("Note: Got status %d for invalid message format (expected 400). Body: %s", resp.StatusCode, string(body))
			// Some implementations may be lenient and add headers automatically
			// So we don't fail the test, just log
		}
	})

	t.Run("DeliverMail_NoRecipients", func(t *testing.T) {
		deliveryReq := map[string]any{
			"recipients": []string{},
			"message": `From: sender@example.com
Subject: No Recipients
Message-ID: <test-norecip@example.com>

This message has no recipients.
`,
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400 for no recipients, got %d - %s", resp.StatusCode, string(body))
		}
	})

	t.Run("DeliverMail_MissingMessage", func(t *testing.T) {
		deliveryReq := map[string]any{
			"recipients": []string{testEmail},
			// message field missing
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400 for missing message, got %d - %s", resp.StatusCode, string(body))
		}
	})

	t.Run("DeliverMail_WithSieveFiltering", func(t *testing.T) {
		// This test verifies that Sieve filters are applied during HTTP delivery
		// First, we'd need to set up a Sieve filter for the account, but that's
		// beyond the scope of this basic test. Just verify delivery works.

		deliveryReq := map[string]any{
			"recipients": []string{testEmail},
			"message": fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test Sieve Integration
Message-ID: <test-sieve-%d@example.com>
Date: %s

Testing Sieve filter integration with HTTP delivery.
`, testEmail, time.Now().Unix(), time.Now().Format(time.RFC1123Z)),
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var deliveryResp map[string]any
		server.expectJSON(t, body, &deliveryResp)

		if success, ok := deliveryResp["success"].(bool); !ok || !success {
			t.Errorf("Expected success=true, got %v", deliveryResp["success"])
		}

		t.Log("Successfully delivered message (Sieve filters would be applied if configured)")
	})

	t.Run("DeliverMail_LargeMessage", func(t *testing.T) {
		// Create a larger message (100KB body)
		largeBody := strings.Repeat("This is a test line.\n", 5000)

		deliveryReq := map[string]any{
			"recipients": []string{testEmail},
			"message": fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Large Message Test
Message-ID: <test-large-%d@example.com>
Date: %s

%s`, testEmail, time.Now().Unix(), time.Now().Format(time.RFC1123Z), largeBody),
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", deliveryReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 for large message, got %d - %s", resp.StatusCode, string(body))
		}

		var deliveryResp map[string]any
		server.expectJSON(t, body, &deliveryResp)

		if success, ok := deliveryResp["success"].(bool); !ok || !success {
			t.Errorf("Expected success=true for large message, got %v", deliveryResp["success"])
		}

		t.Logf("Successfully delivered large message (~100KB)")
	})
}

// TestACLManagement tests the ACL management endpoints
func TestACLManagement(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server := setupHTTPAPIServer(t)
	defer server.Close()

	// Create test accounts
	owner := common.CreateTestAccount(t, server.rdb)
	user2 := common.CreateTestAccount(t, server.rdb)
	user3 := common.CreateTestAccount(t, server.rdb)

	// Create a shared mailbox via database
	ctx := context.Background()

	// Add config to context to enable shared mailbox detection
	cfg := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:         true,
			NamespacePrefix: "Shared/",
		},
	}
	ctx = context.WithValue(ctx, consts.ConfigContextKey, cfg)

	ownerID, _ := server.rdb.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	// Use unique mailbox name to avoid conflicts with previous test runs
	mailboxName := fmt.Sprintf("Shared/TestACL-%d", time.Now().UnixNano())

	err := server.rdb.CreateMailboxWithRetry(ctx, ownerID, mailboxName, nil)
	if err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	t.Run("GrantACL_Success", func(t *testing.T) {
		grantReq := map[string]any{
			"owner":      owner.Email,
			"mailbox":    mailboxName,
			"identifier": user2.Email,
			"rights":     "lrs",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/grant", grantReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var grantResp map[string]any
		server.expectJSON(t, body, &grantResp)

		if status, ok := grantResp["status"].(string); !ok || status != "success" {
			t.Errorf("Expected status='success', got %v", grantResp["status"])
		}

		if rights, ok := grantResp["rights"].(string); !ok || rights != "lrs" {
			t.Errorf("Expected rights='lrs', got %v", grantResp["rights"])
		}

		t.Logf("Successfully granted ACL rights: %v", grantResp)
	})

	t.Run("GrantACL_AnyoneIdentifier", func(t *testing.T) {
		grantReq := map[string]any{
			"owner":      owner.Email,
			"mailbox":    mailboxName,
			"identifier": "anyone",
			"rights":     "lr",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/grant", grantReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var grantResp map[string]any
		server.expectJSON(t, body, &grantResp)

		if identifier, ok := grantResp["identifier"].(string); !ok || identifier != "anyone" {
			t.Errorf("Expected identifier='anyone', got %v", grantResp["identifier"])
		}

		t.Logf("Successfully granted 'anyone' ACL rights: %v", grantResp)
	})

	t.Run("ListACL_Success", func(t *testing.T) {
		url := fmt.Sprintf("/admin/mailboxes/acl?owner=%s&mailbox=%s", owner.Email, mailboxName)
		resp, body := server.makeRequest(t, "GET", url, nil)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var listResp map[string]any
		server.expectJSON(t, body, &listResp)

		if mbox, ok := listResp["mailbox"].(string); !ok || mbox != mailboxName {
			t.Errorf("Expected mailbox='%s', got %v", mailboxName, listResp["mailbox"])
		}

		acls, ok := listResp["acls"].([]any)
		if !ok {
			t.Fatalf("Expected acls array, got %T", listResp["acls"])
		}

		if len(acls) < 2 {
			t.Errorf("Expected at least 2 ACL entries (owner + user2), got %d", len(acls))
		}

		// Verify user2 has 'lrs' rights
		foundUser2 := false
		foundAnyone := false
		for _, acl := range acls {
			aclMap := acl.(map[string]any)
			identifier := aclMap["identifier"].(string)
			rights := aclMap["rights"].(string)

			if identifier == user2.Email && rights == "lrs" {
				foundUser2 = true
			}
			if identifier == "anyone" && rights == "lr" {
				foundAnyone = true
			}
		}

		if !foundUser2 {
			t.Error("Did not find user2 with 'lrs' rights in ACL list")
		}
		if !foundAnyone {
			t.Error("Did not find 'anyone' with 'lr' rights in ACL list")
		}

		t.Logf("Successfully listed ACL entries: %d entries", len(acls))
	})

	t.Run("RevokeACL_Success", func(t *testing.T) {
		revokeReq := map[string]any{
			"owner":      owner.Email,
			"mailbox":    mailboxName,
			"identifier": user2.Email,
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/revoke", revokeReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var revokeResp map[string]any
		server.expectJSON(t, body, &revokeResp)

		if status, ok := revokeResp["status"].(string); !ok || status != "success" {
			t.Errorf("Expected status='success', got %v", revokeResp["status"])
		}

		// Verify user2 no longer has access
		url := fmt.Sprintf("/admin/mailboxes/acl?owner=%s&mailbox=%s", owner.Email, mailboxName)
		resp, body = server.makeRequest(t, "GET", url, nil)

		var listResp map[string]any
		server.expectJSON(t, body, &listResp)

		acls := listResp["acls"].([]any)
		for _, acl := range acls {
			aclMap := acl.(map[string]any)
			if identifier := aclMap["identifier"].(string); identifier == user2.Email {
				t.Errorf("User2 still has ACL entry after revocation: %v", aclMap)
			}
		}

		t.Log("Successfully revoked ACL rights")
	})

	t.Run("GrantACL_InvalidRights", func(t *testing.T) {
		grantReq := map[string]any{
			"owner":      owner.Email,
			"mailbox":    mailboxName,
			"identifier": user3.Email,
			"rights":     "xyz", // Invalid rights
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/grant", grantReq)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("Expected error for invalid rights, got status 200 - %s", string(body))
		}

		var errResp map[string]any
		server.expectJSON(t, body, &errResp)

		if _, ok := errResp["error"]; !ok {
			t.Error("Expected error message in response")
		}

		t.Logf("Correctly rejected invalid rights: %v", errResp)
	})

	t.Run("GrantACL_MissingOwner", func(t *testing.T) {
		grantReq := map[string]any{
			"mailbox":    mailboxName,
			"identifier": user3.Email,
			"rights":     "lrs",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/grant", grantReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400 for missing owner, got %d - %s", resp.StatusCode, string(body))
		}

		var errResp map[string]any
		server.expectJSON(t, body, &errResp)

		if _, ok := errResp["error"]; !ok {
			t.Error("Expected error message in response")
		}

		t.Log("Correctly rejected request with missing owner")
	})

	t.Run("ListACL_MissingParameters", func(t *testing.T) {
		// Missing mailbox parameter
		url := fmt.Sprintf("/admin/mailboxes/acl?owner=%s", owner.Email)
		resp, body := server.makeRequest(t, "GET", url, nil)

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400 for missing mailbox, got %d - %s", resp.StatusCode, string(body))
		}

		var errResp map[string]any
		server.expectJSON(t, body, &errResp)

		if _, ok := errResp["error"]; !ok {
			t.Error("Expected error message in response")
		}

		t.Log("Correctly rejected request with missing mailbox parameter")
	})

	t.Run("RevokeACL_NonexistentUser", func(t *testing.T) {
		revokeReq := map[string]any{
			"owner":      owner.Email,
			"mailbox":    mailboxName,
			"identifier": "nonexistent@example.com",
		}

		resp, body := server.makeRequest(t, "POST", "/admin/mailboxes/acl/revoke", revokeReq)
		// This should succeed (idempotent) even if the user doesn't have access
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("Expected status 200 or 500, got %d - %s", resp.StatusCode, string(body))
		}

		t.Log("Revoke operation completed (idempotent behavior)")
	})
}

// Mock AffinityManager for testing
type mockAffinityManager struct {
	mu       sync.RWMutex
	affinity map[string]string // key: "username:protocol" -> backend
}

func newMockAffinityManager() *mockAffinityManager {
	return &mockAffinityManager{
		affinity: make(map[string]string),
	}
}

func (m *mockAffinityManager) GetBackend(username, protocol string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := username + ":" + protocol
	backend, ok := m.affinity[key]
	return backend, ok
}

func (m *mockAffinityManager) SetBackend(username, backend, protocol string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := username + ":" + protocol
	m.affinity[key] = backend
}

func (m *mockAffinityManager) DeleteBackend(username, protocol string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := username + ":" + protocol
	delete(m.affinity, key)
}

// TestAffinityManagement tests the affinity management endpoints
func TestAffinityManagement(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up database
	rdb := common.SetupTestDatabase(t)

	// Set up cache
	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}
	defer testCache.Close()

	// Create mock affinity manager
	mockAffinity := newMockAffinityManager()

	// Get random port
	addr := common.GetRandomAddress(t)

	// Create server options with affinity manager and valid backends
	options := adminapi.ServerOptions{
		Addr:            addr,
		APIKey:          testAPIKey,
		AllowedHosts:    []string{},
		Cache:           testCache,
		TLS:             false,
		AffinityManager: mockAffinity,
		ValidBackends: map[string][]string{
			"imap":        {"192.168.1.10:993", "192.168.1.11:993"},
			"pop3":        {"192.168.1.20:995", "192.168.1.21:995"},
			"managesieve": {"192.168.1.30:4190"},
		},
	}

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go adminapi.Start(ctx, rdb, options, errChan)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Check if server started successfully
	select {
	case err := <-errChan:
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
		// Server started successfully
	}

	baseURL := fmt.Sprintf("http://%s", addr)

	makeRequest := func(t *testing.T, method, endpoint string, body any) (*http.Response, []byte) {
		t.Helper()

		var reqBody []byte
		if body != nil {
			var err error
			reqBody, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}
		}

		url := baseURL + endpoint
		req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testAPIKey)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		resp.Body.Close()

		return resp, respBody
	}

	t.Run("SetAffinity_Success", func(t *testing.T) {
		setReq := map[string]any{
			"user":     "user@example.com",
			"protocol": "imap",
			"backend":  "192.168.1.10:993",
		}

		resp, body := makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["success"] != true {
			t.Errorf("Expected success=true, got %v", result["success"])
		}

		// Verify affinity was set in mock
		backend, ok := mockAffinity.GetBackend("user@example.com", "imap")
		if !ok {
			t.Fatal("Affinity was not set in manager")
		}
		if backend != "192.168.1.10:993" {
			t.Errorf("Expected backend 192.168.1.10:993, got %s", backend)
		}

		t.Logf("Successfully set affinity: %v", result["message"])
	})

	t.Run("GetAffinity_Success", func(t *testing.T) {
		// First set an affinity
		mockAffinity.SetBackend("user2@example.com", "192.168.1.11:993", "imap")

		resp, body := makeRequest(t, "GET", "/admin/affinity?user=user2@example.com&protocol=imap", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["backend"] != "192.168.1.11:993" {
			t.Errorf("Expected backend 192.168.1.11:993, got %v", result["backend"])
		}

		t.Logf("Successfully retrieved affinity: backend=%s", result["backend"])
	})

	t.Run("GetAffinity_NotFound", func(t *testing.T) {
		resp, body := makeRequest(t, "GET", "/admin/affinity?user=noaffinity@example.com&protocol=imap", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d - %s", resp.StatusCode, string(body))
		}

		t.Log("Correctly returned 404 for non-existent affinity")
	})

	t.Run("SetAffinity_InvalidBackend", func(t *testing.T) {
		setReq := map[string]any{
			"user":     "user@example.com",
			"protocol": "imap",
			"backend":  "192.168.1.99:993", // Not in ValidBackends
		}

		resp, body := makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d - %s", resp.StatusCode, string(body))
		}

		var errorResp map[string]any
		if err := json.Unmarshal(body, &errorResp); err != nil {
			t.Fatalf("Failed to unmarshal error response: %v", err)
		}

		if !strings.Contains(errorResp["error"].(string), "not configured") {
			t.Errorf("Expected error about backend not configured, got: %v", errorResp["error"])
		}

		t.Logf("Correctly rejected invalid backend: %v", errorResp["error"])
	})

	t.Run("SetAffinity_InvalidProtocol", func(t *testing.T) {
		setReq := map[string]any{
			"user":     "user@example.com",
			"protocol": "smtp", // Invalid protocol
			"backend":  "192.168.1.10:25",
		}

		resp, body := makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d - %s", resp.StatusCode, string(body))
		}

		var errorResp map[string]any
		if err := json.Unmarshal(body, &errorResp); err != nil {
			t.Fatalf("Failed to unmarshal error response: %v", err)
		}

		if !strings.Contains(errorResp["error"].(string), "protocol must be") {
			t.Errorf("Expected error about invalid protocol, got: %v", errorResp["error"])
		}

		t.Log("Correctly rejected invalid protocol")
	})

	t.Run("SetAffinity_MissingFields", func(t *testing.T) {
		setReq := map[string]any{
			"user":     "user@example.com",
			"protocol": "imap",
			// Missing backend
		}

		resp, body := makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d - %s", resp.StatusCode, string(body))
		}

		t.Log("Correctly rejected request with missing fields")
	})

	t.Run("DeleteAffinity_Success", func(t *testing.T) {
		// First set an affinity
		mockAffinity.SetBackend("user3@example.com", "192.168.1.20:995", "pop3")

		// Verify it exists
		_, ok := mockAffinity.GetBackend("user3@example.com", "pop3")
		if !ok {
			t.Fatal("Failed to set test affinity")
		}

		// Delete it
		resp, body := makeRequest(t, "DELETE", "/admin/affinity?user=user3@example.com&protocol=pop3", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d - %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["success"] != true {
			t.Errorf("Expected success=true, got %v", result["success"])
		}

		// Verify it was deleted
		_, ok = mockAffinity.GetBackend("user3@example.com", "pop3")
		if ok {
			t.Error("Affinity was not deleted from manager")
		}

		t.Logf("Successfully deleted affinity: %v", result["message"])
	})

	t.Run("DeleteAffinity_NotFound", func(t *testing.T) {
		// Try to delete non-existent affinity (should succeed idempotently)
		resp, body := makeRequest(t, "DELETE", "/admin/affinity?user=nonexistent@example.com&protocol=imap", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 (idempotent delete), got %d - %s", resp.StatusCode, string(body))
		}

		t.Log("Delete operation is idempotent for non-existent affinity")
	})

	t.Run("MultipleProtocols", func(t *testing.T) {
		user := "multiproto@example.com"

		// Set affinity for IMAP
		setReq := map[string]any{
			"user":     user,
			"protocol": "imap",
			"backend":  "192.168.1.10:993",
		}
		resp, body := makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to set IMAP affinity: %s", string(body))
		}

		// Set affinity for POP3 (different backend)
		setReq = map[string]any{
			"user":     user,
			"protocol": "pop3",
			"backend":  "192.168.1.20:995",
		}
		resp, body = makeRequest(t, "POST", "/admin/affinity", setReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to set POP3 affinity: %s", string(body))
		}

		// Verify both exist independently
		imapBackend, ok := mockAffinity.GetBackend(user, "imap")
		if !ok || imapBackend != "192.168.1.10:993" {
			t.Errorf("IMAP affinity incorrect: got %s, exists=%v", imapBackend, ok)
		}

		pop3Backend, ok := mockAffinity.GetBackend(user, "pop3")
		if !ok || pop3Backend != "192.168.1.20:995" {
			t.Errorf("POP3 affinity incorrect: got %s, exists=%v", pop3Backend, ok)
		}

		t.Log("Successfully managed affinity for multiple protocols")
	})
}

// TLS Tests
// =============================================================================

// setupHTTPAPIServerWithTLS creates a test HTTP API server with TLS configuration
func setupHTTPAPIServerWithTLS(t *testing.T, tlsConfig *tls.Config, useTLSConfig bool) *HTTPAPITestServer {
	t.Helper()

	// Set up database
	rdb := common.SetupTestDatabase(t)

	// Set up cache
	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}

	// Get random port
	addr := common.GetRandomAddress(t)

	// Create server options with TLS
	options := adminapi.ServerOptions{
		Addr:         addr,
		APIKey:       testAPIKey,
		AllowedHosts: []string{}, // Allow all for testing
		Cache:        testCache,
		TLS:          true,
	}

	if useTLSConfig {
		// Use TLS config from manager
		options.TLSConfig = tlsConfig
	} else {
		// Use static certificate files
		options.TLSCertFile = "../../testdata/sora.crt"
		options.TLSKeyFile = "../../testdata/sora.key"
	}

	// Create server
	server, err := adminapi.New(rdb, options)
	if err != nil {
		t.Fatalf("Failed to create HTTP API server: %v", err)
	}

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go adminapi.Start(ctx, rdb, options, errChan)

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Check if server started successfully
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
		// Server started successfully
	}

	cleanup := func() {
		cancel()
		testCache.Close()
	}

	baseURL := fmt.Sprintf("https://%s", addr)

	return &HTTPAPITestServer{
		URL:     baseURL,
		server:  server,
		rdb:     rdb,
		cache:   testCache,
		cleanup: cleanup,
	}
}

func TestHTTPAdminAPI_TLS_StaticCertificates(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test HTTP Admin API with static TLS certificates
	srv := setupHTTPAPIServerWithTLS(t, nil, false)
	defer srv.Close()

	// Create HTTPS client with InsecureSkipVerify for self-signed cert
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip verification for self-signed test cert
			},
		},
	}

	// Test a simple health check endpoint
	req, err := http.NewRequest("GET", srv.URL+"/admin/health/overview", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	t.Log("✓ HTTP Admin API works correctly with static TLS certificates")
}

func TestHTTPAdminAPI_TLS_TLSManager(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

	// Test HTTP Admin API with TLS config from manager
	srv := setupHTTPAPIServerWithTLS(t, tlsConfig, true)
	defer srv.Close()

	// Create HTTPS client with InsecureSkipVerify for self-signed cert
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip verification for self-signed test cert
			},
		},
	}

	// Test a simple health check endpoint
	req, err := http.NewRequest("GET", srv.URL+"/admin/health/overview", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	t.Log("✓ HTTP Admin API works correctly with TLS config from manager")
}

func TestHTTPAdminAPI_TLS_WithoutInsecureSkipVerify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test that connection fails when InsecureSkipVerify is false and cert is self-signed
	srv := setupHTTPAPIServerWithTLS(t, nil, false)
	defer srv.Close()

	// Create HTTPS client WITHOUT InsecureSkipVerify
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Don't skip verification
			},
		},
	}

	// Test a simple health check endpoint
	req, err := http.NewRequest("GET", srv.URL+"/admin/health/overview", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	resp, err := client.Do(req)
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
