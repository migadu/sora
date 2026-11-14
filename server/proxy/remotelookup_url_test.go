package proxy

import (
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
