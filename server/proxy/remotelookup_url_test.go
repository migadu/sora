package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migadu/sora/config"
)

// TestValidateRemoteLookupURL verifies that a plaintext remote-lookup endpoint is
// rejected for non-loopback hosts (audit M3), while https and loopback http are allowed.
func TestValidateRemoteLookupURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://lookup.example.com/auth", false},
		{"https://example.com", false},
		{"http://localhost:8080/lookup", false},
		{"http://127.0.0.1/lookup", false},
		{"http://[::1]:9000/lookup", false},
		{"http://127.0.0.5/lookup", false}, // 127.0.0.0/8 is loopback
		{"http://example.com/lookup", true},
		{"http://10.0.0.5:8080/lookup", true},
		{"http://lookup.internal/auth", true},
		{"ftp://example.com", true},
		{"ftp://localhost/lookup", true},
		{"//localhost/lookup", true},
		{"file://127.0.0.1/lookup", true},
	}
	for _, c := range cases {
		err := validateRemoteLookupURL(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("validateRemoteLookupURL(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
		}
	}
}

// TestValidateRemoteLookupURLPlaceholders verifies the startup check against the URLs
// the client actually requests. The client substitutes $email and $ip with
// url.QueryEscape, which writes %40 (and %3A for IPv6) into a host and leaves a URL
// net/url refuses to parse, so a placeholder in the host must be rejected at startup
// rather than fail every lookup. Placeholders in the path and query stay valid.
func TestValidateRemoteLookupURLPlaceholders(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://lookup.example.com/lookup?email=$email", false},
		{"https://lookup.example.com/user/$email/info", false},
		{"https://lookup.example.com/lookup?email=$email&ip=$ip", false},
		{"https://lookup.example.com/$ip/$email", false},
		{"http://localhost:8080/lookup?email=$email", false},
		{"https://$email.lookup.example.com/lookup", true},
		{"https://lookup-$email/lookup", true},
		{"https://$ip.lookup.example.com/lookup", true}, // parses for IPv4, not for IPv6
		{"https://lookup.example.com.$ip/lookup?email=$email", true},
		{"https:///lookup?email=$email", true}, // no host to send the request to
	}
	for _, c := range cases {
		err := validateRemoteLookupURL(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("validateRemoteLookupURL(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
		}
	}
}

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
