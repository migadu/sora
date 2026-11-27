//go:build integration

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/adminapi"
)

type quotaAnswer struct {
	StorageQuota *int64 `json:"storage_quota"`
	StorageUsed  int64  `json:"storage_used"`
}

func getQuota(t *testing.T, srv *HTTPAPITestServer, email string) quotaAnswer {
	t.Helper()
	resp, body := srv.makeRequest(t, "GET", "/admin/accounts/"+url.PathEscape(email)+"/quota", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET quota: %d %s", resp.StatusCode, body)
	}
	var q quotaAnswer
	if err := json.Unmarshal(body, &q); err != nil {
		t.Fatalf("GET quota body %s: %v", body, err)
	}
	return q
}

// TestAccountStorageQuota: new accounts take [quota] default_storage_quota unless the
// request names a limit or null, and PUT /quota changes it.
func TestAccountStorageQuota(t *testing.T) {
	const defaultQuota = int64(1 << 30)
	srv := setupHTTPAPIServer(t, func(o *adminapi.ServerOptions) {
		o.Quota = config.QuotaConfig{DefaultStorageQuota: "1gb"}
	})
	defer srv.Close()

	newEmail := func(tag string) string {
		return fmt.Sprintf("quota-%s-%d@example.com", tag, time.Now().UnixNano())
	}
	create := func(t *testing.T, body map[string]any) {
		t.Helper()
		resp, b := srv.makeRequest(t, "POST", "/admin/accounts", body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %v: %d %s", body, resp.StatusCode, b)
		}
	}

	t.Run("DefaultFromConfig", func(t *testing.T) {
		email := newEmail("default")
		create(t, map[string]any{"email": email, "password": "password"})
		if q := getQuota(t, srv, email); q.StorageQuota == nil || *q.StorageQuota != defaultQuota {
			t.Fatalf("storage_quota = %v, want %d", q.StorageQuota, defaultQuota)
		}
	})

	t.Run("ExplicitNullIsUnlimited", func(t *testing.T) {
		email := newEmail("null")
		create(t, map[string]any{"email": email, "password": "password", "storage_quota": nil})
		if q := getQuota(t, srv, email); q.StorageQuota != nil {
			t.Fatalf("storage_quota = %d, want null", *q.StorageQuota)
		}
	})

	t.Run("ExplicitLimitWithCredentials", func(t *testing.T) {
		email := newEmail("creds")
		create(t, map[string]any{
			"credentials":   []map[string]any{{"email": email, "password": "password", "is_primary": true}},
			"storage_quota": 2048,
		})
		if q := getQuota(t, srv, email); q.StorageQuota == nil || *q.StorageQuota != 2048 {
			t.Fatalf("storage_quota = %v, want 2048", q.StorageQuota)
		}
	})

	t.Run("PutSetsAndClears", func(t *testing.T) {
		email := newEmail("put")
		create(t, map[string]any{"email": email, "password": "password"})
		path := "/admin/accounts/" + url.PathEscape(email) + "/quota"

		resp, b := srv.makeRequest(t, "PUT", path, map[string]any{"storage_quota": 5 << 20})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT: %d %s", resp.StatusCode, b)
		}
		if q := getQuota(t, srv, email); q.StorageQuota == nil || *q.StorageQuota != 5<<20 {
			t.Fatalf("after PUT storage_quota = %v", q.StorageQuota)
		}

		resp, b = srv.makeRequest(t, "PUT", path, map[string]any{"storage_quota": nil})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT null: %d %s", resp.StatusCode, b)
		}
		if q := getQuota(t, srv, email); q.StorageQuota != nil {
			t.Fatalf("after PUT null storage_quota = %d", *q.StorageQuota)
		}

		// The account details carry it too.
		resp, b = srv.makeRequest(t, "GET", "/admin/accounts/"+url.PathEscape(email), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET account: %d %s", resp.StatusCode, b)
		}
		var details map[string]any
		if err := json.Unmarshal(b, &details); err != nil {
			t.Fatal(err)
		}
		if v, ok := details["storage_quota"]; !ok || v != nil {
			t.Fatalf("account details storage_quota = %v (present %v), want null", v, ok)
		}
	})

	t.Run("PutRefusals", func(t *testing.T) {
		resp, b := srv.makeRequest(t, "PUT", "/admin/accounts/"+url.PathEscape(newEmail("missing"))+"/quota", map[string]any{"storage_quota": 1})
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unknown account: %d %s, want 404", resp.StatusCode, b)
		}
		email := newEmail("refuse")
		create(t, map[string]any{"email": email, "password": "password"})
		resp, b = srv.makeRequest(t, "PUT", "/admin/accounts/"+url.PathEscape(email)+"/quota", map[string]any{"storage_quota": 0})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("zero: %d %s, want 400", resp.StatusCode, b)
		}
		if q := getQuota(t, srv, email); q.StorageQuota == nil || *q.StorageQuota != defaultQuota {
			t.Errorf("a refused PUT changed the limit to %v", q.StorageQuota)
		}
	})
}
