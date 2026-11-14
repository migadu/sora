package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
)

// TestBuildAdminAPIServerOptions_ThreadsSieveExtensions covers the one line that connects
// [sieve] enabled_extensions to the Admin API delivery path. The Admin API compiles a
// user's Sieve script with whatever set it is handed, and a compile failure there is
// swallowed into a plain INBOX keep - so if this hop is dropped, an opted-in extension
// (say editheader) silently stops working over /admin/mail/deliver while it keeps working
// over LMTP, with nothing failing loudly.
//
// The other end of the same option is covered end-to-end by
// integration_tests/adminapi.TestAdminAPI_DeliverMail_HonoursConfiguredSieveExtensions.
func TestBuildAdminAPIServerOptions_ThreadsSieveExtensions(t *testing.T) {
	configured := []string{"fileinto", "vacation", "editheader"}
	deps := &serverDependencies{
		config: config.Config{
			Sieve: config.SieveConfig{EnabledExtensions: configured},
		},
	}

	options := buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: ":8080"})

	if len(options.SieveExtensions) != len(configured) {
		t.Fatalf("[sieve] enabled_extensions did not reach the Admin API options: got %v, want %v",
			options.SieveExtensions, configured)
	}
	for i, ext := range configured {
		if options.SieveExtensions[i] != ext {
			t.Fatalf("[sieve] enabled_extensions altered on the way to the Admin API options: got %v, want %v",
				options.SieveExtensions, configured)
		}
	}
}

// A node without [cluster] or without [auth_cache] enabled has a nil
// *server.AffinityManager / *authcache.Cache. Copied into the Admin API options'
// interface fields, a nil pointer made a non-nil interface, so the handlers' "not
// enabled" checks never fired: affinity writes reported success while storing nothing,
// /admin/affinity/stats answered 500, and /admin/auth-cache/stats dereferenced the nil
// cache (the client saw a dropped connection). The options must carry nil interfaces and
// the endpoints must answer as for a disabled feature.
func TestBuildAdminAPIServerOptions_DisabledAffinityAndAuthCache(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	const apiKey = "test-admin-api-key-0123456789"

	// An IMAP proxy with a backend, as in the report, so an affinity write passes the
	// backend validation and reaches the affinity manager.
	deps := &serverDependencies{config: config.Config{DynamicServers: []config.ServerConfig{
		{Type: "imap_proxy", Name: "imap-proxy", Addr: "127.0.0.1:1143", RemoteAddrs: []string{"192.0.2.10:143"}},
	}}}
	options := buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: addr, APIKey: apiKey})
	if options.AffinityManager != nil {
		t.Errorf("AffinityManager is a non-nil interface (%T) on a node without an affinity manager", options.AffinityManager)
	}
	if options.AuthCache != nil {
		t.Errorf("AuthCache is a non-nil interface (%T) on a node without an auth cache", options.AuthCache)
	}

	srv, err := adminapi.New(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Serve(ctx, make(chan error, 1))

	client := &http.Client{Timeout: 5 * time.Second}
	do := func(method, path, body string) (*http.Response, string, error) {
		req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b), nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, err := do("GET", "/admin/config", ""); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("Admin API did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, tc := range []struct {
		method, path, body string
	}{
		{"POST", "/admin/affinity", `{"user":"user@example.com","protocol":"imap","backend":"192.0.2.10:143"}`},
		{"GET", "/admin/affinity?user=user@example.com&protocol=imap", ""},
		{"DELETE", "/admin/affinity?user=user@example.com&protocol=imap", ""},
		{"GET", "/admin/affinity/stats", ""},
	} {
		resp, body, err := do(tc.method, tc.path, tc.body)
		if err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.path, err)
			continue
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s %s: got %d %s, want 503", tc.method, tc.path, resp.StatusCode, strings.TrimSpace(body))
		}
	}

	resp, body, err := do("GET", "/admin/auth-cache/stats", "")
	if err != nil {
		t.Fatalf("GET /admin/auth-cache/stats: %v", err)
	}
	var stats map[string]any
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &stats) != nil || stats["enabled"] != false {
		t.Errorf("GET /admin/auth-cache/stats: got %d %s, want 200 with enabled=false", resp.StatusCode, strings.TrimSpace(body))
	}
}

// The other half of the nil guard: on a node with [cluster] and [auth_cache] the node's
// affinity manager and auth cache must still reach the Admin API, or its affinity
// endpoints answer 503 and the auth cache reports "not enabled" on exactly the nodes
// that have them.
func TestBuildAdminAPIServerOptions_EnabledAffinityAndAuthCache(t *testing.T) {
	deps := &serverDependencies{
		affinityManager:   &server.AffinityManager{},
		authCacheInstance: &authcache.Cache{},
	}

	options := buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: ":8080"})

	if options.AffinityManager != deps.affinityManager {
		t.Errorf("AffinityManager is %T(%p), want the node's affinity manager %p", options.AffinityManager, options.AffinityManager, deps.affinityManager)
	}
	if options.AuthCache != deps.authCacheInstance {
		t.Errorf("AuthCache is %T(%p), want the node's auth cache %p", options.AuthCache, options.AuthCache, deps.authCacheInstance)
	}
}
