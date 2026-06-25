package main

import "testing"

// TestIsLoopbackHostPort covers the helper that decides whether the admin CLI may skip
// TLS verification by default. A false positive here would silently disable cert
// verification for a remote Admin API and expose the bearer key to a MITM.
func TestIsLoopbackHostPort(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"localhost:8080", true},
		{"127.0.0.1:8080", true},
		{"127.0.0.1", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"[::1]", true},
		{"https://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		// Non-loopback must verify (false).
		{"192.0.2.1:8080", false},
		{"example.com:8080", false},
		{"mail.example.com", false},
		{":8080", false}, // empty host -> verify (secure default)
		{"", false},
		// userinfo spoofing: real host is after '@' -> must not auto-skip.
		{"http://127.0.0.1:8080@evil.com", false},
		{"127.0.0.1@evil.com", false},
	}
	for _, c := range cases {
		if got := isLoopbackHostPort(c.addr); got != c.want {
			t.Errorf("isLoopbackHostPort(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
