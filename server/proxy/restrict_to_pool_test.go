package proxy

import "testing"

// TestAllowRemoteLookupBackend covers the restrict_to_pool SSRF defense: a backend
// address (from remote-lookup, affinity, or cache) may only be dialed when the feature
// is off (passthrough) or the address is a member of the configured pool — matched
// against both configured hostnames and resolved IPs, with consistent normalization.
func TestAllowRemoteLookupBackend(t *testing.T) {
	cm := &ConnectionManager{
		serverName:      "test",
		configuredAddrs: []string{"backend1.internal:143", "[2001:db8::1]:143"},
		// Simulated post-ResolveAddresses() resolved IPs (configuredAddrs stays as-is).
		remoteAddrs: []string{"10.0.0.5:143", "10.0.0.6:143"},
	}

	// Feature OFF (default): pure passthrough — even an SSRF target is allowed.
	if !cm.AllowRemoteLookupBackend("169.254.169.254:80") {
		t.Fatalf("restrict_to_pool off must allow any address (passthrough)")
	}

	cm.SetRestrictRemoteLookupToPool(true)
	cases := []struct {
		addr string
		want bool
	}{
		{"backend1.internal:143", true},  // configured hostname (pre-resolution)
		{"10.0.0.5:143", true},           // resolved IP (post-resolution)
		{"[2001:db8::1]:143", true},      // IPv6 canonical form
		{"2001:db8::1:143", true},        // IPv6 non-bracketed form normalizes to the same
		{"169.254.169.254:80", false},    // classic SSRF target, not in pool
		{"10.0.0.5:144", false},          // right host, wrong port
		{"backend2.internal:143", false}, // unknown host
		{"", false},                      // empty
	}
	for _, c := range cases {
		if got := cm.AllowRemoteLookupBackend(c.addr); got != c.want {
			t.Errorf("AllowRemoteLookupBackend(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
