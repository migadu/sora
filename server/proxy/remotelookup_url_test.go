package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migadu/sora/config"
)

// TestInitializeRemoteLookupRejectsPlaceholderInHost is the reported configuration:
// the proxy must refuse to start instead of failing every login.
func TestInitializeRemoteLookupRejectsPlaceholderInHost(t *testing.T) {
	cfg := &config.RemoteLookupConfig{
		Enabled: true,
		URL:     "https://$email.lookup.example.com/lookup",
	}
	if _, err := InitializeRemoteLookup("imap", cfg, 0); err == nil {
		t.Fatalf("InitializeRemoteLookup accepted url %q, whose lookups cannot be requested", cfg.URL)
	}
}

func TestHTTPRemoteLookupRouteOnlyBeforeFragment(t *testing.T) {
	const query = "email=user%40example.com%40TOKEN&ip=2001%3Adb8%3A%3A1"
	for _, tc := range []struct {
		name, suffix, wantQuery, wantPath string
		routeOnly                         bool
	}{
		{"query and fragment", "/lookup?email=$email&ip=$ip#note", query + "&route_only=true", "/lookup", true},
		{"path and fragment", "/lookup/$email/$ip#note?ignored=yes", "route_only=true", "/lookup/user%40example.com%40TOKEN/2001%3Adb8%3A%3A1", true},
		{"existing query encoding", "/lookup?literal=%2f%2B&email=$email&ip=$ip#note", "literal=%2f%2B&" + query + "&route_only=true", "/lookup", true},
		{"without fragment", "/lookup?email=$email&ip=$ip", query + "&route_only=true", "/lookup", true},
		{"ordinary lookup with fragment", "/lookup?email=$email&ip=$ip#note", query, "/lookup", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type observed struct{ query, path, fragment string }
			requests := make(chan observed, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- observed{r.URL.RawQuery, r.URL.EscapedPath(), r.URL.Fragment}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			client, err := InitializeRemoteLookup("imap", &config.RemoteLookupConfig{Enabled: true, URL: srv.URL + tc.suffix}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := client.LookupUserRouteWithClientIP(context.Background(), "user@example.com@TOKEN", "", "2001:db8::1", tc.routeOnly); err != nil {
				t.Fatal(err)
			}
			got := <-requests
			if got.query != tc.wantQuery || got.path != tc.wantPath || got.fragment != "" {
				t.Fatalf("server received query=%q path=%q fragment=%q, want query=%q path=%q and no fragment", got.query, got.path, got.fragment, tc.wantQuery, tc.wantPath)
			}
		})
	}
}
