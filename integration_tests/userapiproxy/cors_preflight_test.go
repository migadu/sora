//go:build integration

package userapiproxy_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestProxyCORSPreflight sends a browser's CORS preflight for an authenticated endpoint
// through the proxy. A preflight never carries credentials, so the proxy must not ask for
// a token; the backend answers it with its CORS headers as when it is reached directly.
func TestProxyCORSPreflight(t *testing.T) {
	tc := setupTestEnvironment(t)

	req, err := http.NewRequest(http.MethodOptions, fmt.Sprintf("http://%s/user/mailboxes", tc.ProxyAddr), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preflight: status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("preflight: Access-Control-Allow-Origin = %q, want the backend's \"*\"", got)
	}
}
