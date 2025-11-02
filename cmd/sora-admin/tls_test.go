//go:build integration

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

const (
	testAPIKeyForTLS = "test-api-key-for-tls-tests"
)

// setupHTTPAdminAPIWithTLS creates an HTTPS HTTP Admin API server for testing
func setupHTTPAdminAPIWithTLS(t *testing.T) (string, func()) {
	t.Helper()

	// Setup database
	rdb := common.SetupTestDatabase(t)

	// Setup cache
	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}

	// Get random port
	addr := common.GetRandomAddress(t)

	// Load test certificate
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create server options with TLS
	options := adminapi.ServerOptions{
		Addr:         addr,
		APIKey:       testAPIKeyForTLS,
		AllowedHosts: []string{}, // Allow all for testing
		Cache:        testCache,
		TLS:          true,
		TLSConfig:    tlsConfig,
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

	baseURL := "https://" + addr

	cleanup := func() {
		cancel()
		testCache.Close()
	}

	return baseURL, cleanup
}

// testSourceDB implements cache.SourceDatabase for testing
type testSourceDB struct {
	rdb any
}

func (t *testSourceDB) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	return nil, nil
}

func (t *testSourceDB) GetRecentMessagesForWarmupWithRetry(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return nil, nil
}

func TestInsecureSkipVerify_Enabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	baseURL, cleanup := setupHTTPAdminAPIWithTLS(t)
	defer cleanup()

	// Create HTTP client config with InsecureSkipVerify = true
	cfg := AdminConfig{
		HTTPAPIAddr:               baseURL,
		HTTPAPIKey:                testAPIKeyForTLS,
		HTTPAPIInsecureSkipVerify: true, // This is the default
	}

	// Create HTTP client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create HTTP client: %v", err)
	}

	// Make a request - should succeed with self-signed cert
	req, err := http.NewRequest("GET", baseURL+"/admin/health/overview", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKeyForTLS)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request should succeed with InsecureSkipVerify=true, but failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify the response is valid JSON
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	t.Log("✓ HTTP Admin API client works with InsecureSkipVerify=true (default)")
}

func TestInsecureSkipVerify_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	baseURL, cleanup := setupHTTPAdminAPIWithTLS(t)
	defer cleanup()

	// Create HTTP client config with InsecureSkipVerify = false
	cfg := AdminConfig{
		HTTPAPIAddr:               baseURL,
		HTTPAPIKey:                testAPIKeyForTLS,
		HTTPAPIInsecureSkipVerify: false, // Explicitly disable
	}

	// Create HTTP client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create HTTP client: %v", err)
	}

	// Make a request - should FAIL with self-signed cert
	req, err := http.NewRequest("GET", baseURL+"/admin/health/overview", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKeyForTLS)

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected TLS verification error with InsecureSkipVerify=false, but request succeeded")
	}

	// Verify the error is certificate-related
	errMsg := err.Error()
	if !contains(errMsg, "certificate") && !contains(errMsg, "x509") {
		t.Fatalf("Expected certificate verification error, got: %v", err)
	}

	t.Logf("✓ TLS verification correctly fails with InsecureSkipVerify=false: %v", err)
}

// Helper function to check if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}
