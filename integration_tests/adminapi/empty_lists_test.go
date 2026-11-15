//go:build integration

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestEmptyListsAreArrays: admin_api_openapi.yaml documents failed_uploads, messages,
// metrics and statuses as arrays. With nothing to list each must be sent as [], not
// null, which a client that reads them as arrays fails on (#988).
func TestEmptyListsAreArrays(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	account := common.CreateTestAccount(t, server.rdb)
	// Values no row of a shared test database can match.
	host := fmt.Sprintf("no-such-host-%d.example.com", time.Now().UnixNano())
	const future = "2999-01-01T00:00:00Z"
	const neverFailed = "max_attempts=1000000"

	field := func(t *testing.T, path, key string) string {
		t.Helper()
		resp, body := server.makeRequest(t, "GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
		}
		var fields map[string]json.RawMessage
		server.expectJSON(t, body, &fields)
		raw, ok := fields[key]
		if !ok {
			t.Fatalf("GET %s: no %q in %s", path, key, body)
		}
		return string(raw)
	}

	for _, c := range []struct{ path, key string }{
		{"/admin/uploader/failed?" + neverFailed, "failed_uploads"},
		{"/admin/uploader/status?show_failed=true&" + neverFailed, "failed_uploads"},
		{"/admin/accounts/" + account.Email + "/messages/deleted", "messages"},
		{"/admin/cache/metrics?since=" + future, "metrics"},
		{"/admin/health/servers/" + host, "statuses"},
	} {
		if got := field(t, c.path, c.key); got != "[]" {
			t.Errorf("GET %s: %q = %s, want []", c.path, c.key, got)
		}
	}

	// latest=true reports every instance, so a shared database may have rows to list;
	// either way the field is an array.
	const latest = "/admin/cache/metrics?latest=true"
	if got := field(t, latest, "metrics"); !strings.HasPrefix(got, "[") {
		t.Errorf("GET %s: %q = %s, want an array", latest, "metrics", got)
	}
}
