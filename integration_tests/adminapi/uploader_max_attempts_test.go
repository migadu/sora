//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

// An upload the uploader is still retrying is not failed: without a max_attempts
// query parameter the uploader endpoints use [uploader] max_attempts (default 20),
// not a separate default of 5 (#288).
func TestUploaderEndpointsDefaultToConfiguredMaxAttempts(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	ctx := context.Background()
	account := common.CreateTestAccount(t, server.rdb)
	accountID, err := server.rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}

	// Six failed attempts: past the old default of 5, well short of the uploader's 20.
	hash := fmt.Sprintf("%064x", time.Now().UnixNano())
	pool := server.rdb.GetOperationalDatabase().GetWritePool()
	if _, err := pool.Exec(ctx, `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts)
		VALUES ($1, $2, 100, 'uploader-max-attempts-test', 6)`, accountID, hash); err != nil {
		t.Fatalf("queue pending upload: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM pending_uploads WHERE content_hash = $1`, hash)
	})

	want := config.NewDefaultConfig().Uploader.MaxAttempts

	resp, body := server.makeRequest(t, "GET", "/admin/uploader/failed?limit=1000", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/uploader/failed: %d %s", resp.StatusCode, body)
	}
	var failed struct {
		FailedUploads []struct {
			ContentHash string `json:"ContentHash"`
		} `json:"failed_uploads"`
		MaxAttempts int `json:"max_attempts"`
	}
	server.expectJSON(t, body, &failed)
	if failed.MaxAttempts != want {
		t.Errorf("/admin/uploader/failed max_attempts = %d, want the [uploader] default %d", failed.MaxAttempts, want)
	}
	for _, u := range failed.FailedUploads {
		if u.ContentHash == hash {
			t.Errorf("/admin/uploader/failed lists an upload with 6 attempts, which the uploader still retries")
		}
	}

	resp, body = server.makeRequest(t, "GET", "/admin/uploader/status?show_failed=true&failed_limit=1000", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/uploader/status: %d %s", resp.StatusCode, body)
	}
	var status struct {
		FailedUploads []struct {
			ContentHash string `json:"ContentHash"`
		} `json:"failed_uploads"`
	}
	server.expectJSON(t, body, &status)
	for _, u := range status.FailedUploads {
		if u.ContentHash == hash {
			t.Errorf("/admin/uploader/status lists an upload with 6 attempts as failed")
		}
	}
}
