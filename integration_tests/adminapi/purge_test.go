//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/storage"
)

// setupHTTPAPIServerForPurge is like setupHTTPAPIServer but wires object
// storage, which the default harness leaves nil — without it the purge endpoint
// reports 503 because it cannot remove S3 data. Pass nil to exercise that case.
//
// The storage handle is never called by these tests: the accounts they purge
// have no uploaded messages, so the purge finds no S3 objects to delete.
func setupHTTPAPIServerForPurge(t *testing.T, s3 *storage.S3Storage) *HTTPAPITestServer {
	t.Helper()

	rdb := common.SetupTestDatabase(t)

	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}

	addr := common.GetRandomAddress(t)
	options := adminapi.ServerOptions{
		Addr:         addr,
		APIKey:       testAPIKey,
		AllowedHosts: []string{},
		Cache:        testCache,
		Storage:      s3,
		TLS:          false,
	}

	server, err := adminapi.New(rdb, options)
	if err != nil {
		t.Fatalf("Failed to create HTTP API server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go adminapi.Start(ctx, rdb, options, errChan)
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
	}

	return &HTTPAPITestServer{
		URL:     fmt.Sprintf("http://%s", addr),
		server:  server,
		rdb:     rdb,
		cache:   testCache,
		cleanup: func() { cancel(); testCache.Close() },
	}
}

// createPurgeAccount creates an account with an INBOX so the purge has a
// mailbox to remove, and returns the account ID.
func createPurgeAccount(t *testing.T, server *HTTPAPITestServer, email string) int64 {
	t.Helper()
	ctx := context.Background()

	resp, body := server.makeRequest(t, "POST", "/admin/accounts", map[string]string{
		"email": email, "password": "testpassword123",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account %s: %d %s", email, resp.StatusCode, string(body))
	}

	var accountID int64
	if err := server.rdb.GetDatabase().GetReadPool().QueryRow(ctx,
		"SELECT account_id FROM credentials WHERE address = $1", email).Scan(&accountID); err != nil {
		t.Fatalf("get account ID: %v", err)
	}

	if _, err := server.rdb.GetDatabase().GetWritePool().Exec(ctx,
		"INSERT INTO mailboxes (account_id, name, uid_validity, path) VALUES ($1, $2, extract(epoch from now())::bigint, $3)",
		accountID, "INBOX", "INBOX"); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}

	return accountID
}

// TestAdminAPI_PurgeAccount verifies that DELETE /admin/accounts/{email}?purge=true
// removes the account for good: it is no longer visible through the API and
// cannot be restored.
func TestAdminAPI_PurgeAccount(t *testing.T) {
	server := setupHTTPAPIServerForPurge(t, &storage.S3Storage{})
	defer server.Close()

	email := fmt.Sprintf("purge-%d@example.com", time.Now().UnixNano())
	createPurgeAccount(t, server, email)

	resp, body := server.makeRequest(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("purge: %d %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	server.expectJSON(t, body, &result)
	if result["email"] != email {
		t.Errorf("expected email %q in response, got %v", email, result["email"])
	}
	if message, _ := result["message"].(string); !strings.Contains(message, "purged successfully") {
		t.Errorf("expected purge confirmation, got %v", result["message"])
	}

	t.Run("account no longer exists", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+email+"/exists", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("exists check: %d %s", resp.StatusCode, string(body))
		}
		var existsResult map[string]any
		server.expectJSON(t, body, &existsResult)
		if exists, _ := existsResult["exists"].(bool); exists {
			t.Errorf("expected account to not exist after purge, got %v", existsResult)
		}
	})

	t.Run("account cannot be fetched", func(t *testing.T) {
		resp, _ := server.makeRequest(t, "GET", "/admin/accounts/"+email, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 fetching a purged account, got %d", resp.StatusCode)
		}
	})

	t.Run("purged account cannot be restored", func(t *testing.T) {
		resp, _ := server.makeRequest(t, "POST", "/admin/accounts/"+email+"/restore", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 restoring a purged account, got %d", resp.StatusCode)
		}
	})
}

// TestAdminAPI_DeleteAccount_WithoutPurge guards the default: no purge parameter
// still means a soft delete that honours the grace period and can be restored.
func TestAdminAPI_DeleteAccount_WithoutPurge(t *testing.T) {
	server := setupHTTPAPIServerForPurge(t, &storage.S3Storage{})
	defer server.Close()

	email := fmt.Sprintf("purge-soft-%d@example.com", time.Now().UnixNano())
	createPurgeAccount(t, server, email)

	resp, body := server.makeRequest(t, "DELETE", "/admin/accounts/"+email, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("soft delete: %d %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	server.expectJSON(t, body, &result)
	if message, _ := result["message"].(string); !strings.Contains(message, "grace period") {
		t.Errorf("expected soft-delete message, got %v", result["message"])
	}

	resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+email+"/restore", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore soft-deleted account: %d %s", resp.StatusCode, string(body))
	}
}

// TestAdminAPI_PurgeAccount_Errors covers the failure paths of the purge parameter.
func TestAdminAPI_PurgeAccount_Errors(t *testing.T) {
	t.Run("unknown account", func(t *testing.T) {
		server := setupHTTPAPIServerForPurge(t, &storage.S3Storage{})
		defer server.Close()

		email := fmt.Sprintf("purge-missing-%d@example.com", time.Now().UnixNano())
		resp, _ := server.makeRequest(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 purging an unknown account, got %d", resp.StatusCode)
		}
	})

	t.Run("no storage configured", func(t *testing.T) {
		server := setupHTTPAPIServerForPurge(t, nil)
		defer server.Close()

		email := fmt.Sprintf("purge-nostorage-%d@example.com", time.Now().UnixNano())
		createPurgeAccount(t, server, email)

		resp, body := server.makeRequest(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when storage is unconfigured, got %d %s", resp.StatusCode, string(body))
		}
		server.expectError(t, body, "no object storage configured")

		// A refused purge must leave the account untouched.
		resp, body = server.makeRequest(t, "GET", "/admin/accounts/"+email, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected account to survive a refused purge, got %d %s", resp.StatusCode, string(body))
		}
	})
}
