package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The connection commands put the address in the request path, so a "/" in its
// local part must go as %2F (RFC 3986 §2.2), or the Admin API reads the address
// after the "/".
func TestUserConnectionsRequestEscapesAddress(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"connections":[],"count":0}`))
	}))
	defer srv.Close()

	cfg := AdminConfig{HTTPAPIAddr: srv.URL, HTTPAPIKey: "test-key"}
	ctx := context.Background()
	if err := listConnections(ctx, cfg, "a/b@example.com", "", "", ""); err != nil {
		t.Fatalf("listConnections: %v", err)
	}
	if err := showConnectionStats(ctx, cfg, "a/b@example.com", false); err != nil {
		t.Fatalf("showConnectionStats: %v", err)
	}

	const want = "/admin/connections/user/a%2Fb@example.com"
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 {
		t.Fatalf("requests %q, want two", paths)
	}
	for _, p := range paths {
		if p != want {
			t.Errorf("request path %q, want %q", p, want)
		}
	}
}
