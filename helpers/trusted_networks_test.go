package helpers

import (
	"net"
	"slices"
	"testing"
)

func TestParseTrustedNetworks(t *testing.T) {
	tests := []struct {
		name          string
		input         []string
		expectedCount int
		shouldError   bool
		description   string
	}{
		{
			name:          "valid CIDR notation",
			input:         []string{"192.168.1.0/24", "10.0.0.0/8"},
			expectedCount: 2,
			shouldError:   false,
			description:   "Should parse valid CIDR notation correctly",
		},
		{
			name:          "IPv4 addresses without subnet",
			input:         []string{"192.168.1.1", "10.0.0.1"},
			expectedCount: 2,
			shouldError:   false,
			description:   "Should automatically add /32 to IPv4 addresses",
		},
		{
			name:          "IPv6 addresses without subnet",
			input:         []string{"2001:db8::1", "::1"},
			expectedCount: 2,
			shouldError:   false,
			description:   "Should automatically add /128 to IPv6 addresses",
		},
		{
			name:          "mixed CIDR and plain IPs",
			input:         []string{"192.168.1.0/24", "10.0.0.1", "2001:db8::1", "::1/128"},
			expectedCount: 4,
			shouldError:   false,
			description:   "Should handle mix of CIDR notation and plain IPs",
		},
		{
			name:          "invalid IP address",
			input:         []string{"not.an.ip.address"},
			expectedCount: 0,
			shouldError:   true,
			description:   "Should return error for invalid IP addresses",
		},
		{
			name:          "invalid CIDR notation",
			input:         []string{"192.168.1.0/33"},
			expectedCount: 0,
			shouldError:   true,
			description:   "Should return error for invalid CIDR notation",
		},
		{
			name:          "empty input",
			input:         []string{},
			expectedCount: 0,
			shouldError:   false,
			description:   "Should handle empty input gracefully",
		},
		{
			name:          "localhost variations",
			input:         []string{"127.0.0.1", "::1", "localhost"},
			expectedCount: 2, // localhost will fail, only the first two should succeed
			shouldError:   true,
			description:   "Should handle localhost IP addresses but reject hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := ParseTrustedNetworks(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none for test: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v for test: %s", err, tt.description)
				return
			}

			if len(networks) != tt.expectedCount {
				t.Errorf("Expected %d networks, got %d for test: %s", tt.expectedCount, len(networks), tt.description)
			}

			// Verify each network is valid
			for i, network := range networks {
				if network == nil {
					t.Errorf("Network %d is nil for test: %s", i, tt.description)
				}
			}
		})
	}
}

func TestParseTrustedNetworks_IPv4AutoSubnet(t *testing.T) {
	networks, err := ParseTrustedNetworks([]string{"54.38.178.38"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(networks) != 1 {
		t.Fatalf("Expected 1 network, got %d", len(networks))
	}

	// Test that the IP matches itself (single host)
	testIP := net.ParseIP("54.38.178.38")
	if !networks[0].Contains(testIP) {
		t.Errorf("Network should contain the original IP address")
	}

	// Test that it doesn't match other IPs
	otherIP := net.ParseIP("54.38.178.39")
	if networks[0].Contains(otherIP) {
		t.Errorf("Network should not contain other IP addresses")
	}

	// Verify the subnet mask is /32
	ones, bits := networks[0].Mask.Size()
	if ones != 32 || bits != 32 {
		t.Errorf("Expected /32 subnet mask, got /%d", ones)
	}
}

func TestParseTrustedNetworks_IPv6AutoSubnet(t *testing.T) {
	networks, err := ParseTrustedNetworks([]string{"2001:db8::1"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(networks) != 1 {
		t.Fatalf("Expected 1 network, got %d", len(networks))
	}

	// Test that the IP matches itself (single host)
	testIP := net.ParseIP("2001:db8::1")
	if !networks[0].Contains(testIP) {
		t.Errorf("Network should contain the original IP address")
	}

	// Test that it doesn't match other IPs
	otherIP := net.ParseIP("2001:db8::2")
	if networks[0].Contains(otherIP) {
		t.Errorf("Network should not contain other IP addresses")
	}

	// Verify the subnet mask is /128
	ones, bits := networks[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("Expected /128 subnet mask, got /%d", ones)
	}
}

// A bare IPv4-mapped IPv6 address is the single IPv4 host it maps. Appending "/32" to its
// text turned it into the IPv6 network ::/32, which matches no IPv4 client (the intended
// host included) and matches ::1 and every other address whose first 32 bits are zero.
func TestParseTrustedNetworks_IPv4MappedBareIP(t *testing.T) {
	networks, err := ParseTrustedNetworks([]string{"::ffff:192.0.2.5"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("Expected 1 network, got %d", len(networks))
	}
	network := networks[0]

	if got := network.String(); got != "192.0.2.5/32" {
		t.Errorf("network = %s, want 192.0.2.5/32", got)
	}
	for _, ip := range []string{"192.0.2.5", "::ffff:192.0.2.5"} {
		if !network.Contains(net.ParseIP(ip)) {
			t.Errorf("network %s does not contain %s", network, ip)
		}
	}
	for _, ip := range []string{"192.0.2.6", "::ffff:192.0.2.6", "::1", "::", "0:0:1::1"} {
		if network.Contains(net.ParseIP(ip)) {
			t.Errorf("network %s contains %s", network, ip)
		}
	}
}

func TestParseTrustedNetworks_RealWorldExample(t *testing.T) {
	// This is the exact case from the error message
	input := []string{"54.38.178.38"}

	networks, err := ParseTrustedNetworks(input)
	if err != nil {
		t.Fatalf("Should not error on plain IPv4 address: %v", err)
	}

	if len(networks) != 1 {
		t.Fatalf("Expected 1 network, got %d", len(networks))
	}

	// Verify it works as expected
	ip := net.ParseIP("54.38.178.38")
	if !networks[0].Contains(ip) {
		t.Errorf("Network should contain the original IP")
	}
}

// TestIPInNetworks pins the contract of the shared IP-in-list primitive that all trust
// checks (forwarding, rate-limit exemptions, host allow-lists) route through. It MUST accept
// bare IPs identically to ParseTrustedNetworks — divergence caused the "451 XCLIENT denied"
// prod bug where one check normalized a bare IP and the other dropped it.
func TestIPInNetworks(t *testing.T) {
	cases := []struct {
		name     string
		ip       string
		networks []string
		want     bool
	}{
		{"bare IPv4 match", "10.10.10.31", []string{"10.10.10.31"}, true},
		{"bare IPv4 no match", "10.10.10.99", []string{"10.10.10.31"}, false},
		{"CIDR match", "10.10.10.31", []string{"10.10.10.0/24"}, true},
		{"CIDR no match", "10.10.11.1", []string{"10.10.10.0/24"}, false},
		{"mixed list, bare hit", "192.168.1.5", []string{"10.0.0.0/8", "192.168.1.5"}, true},
		{"bare IPv6 -> /128 match", "2001:db8::1", []string{"2001:db8::1"}, true},
		{"IPv6 canonicalization", "2001:0db8::0:1", []string{"2001:db8::1"}, true},
		{"bare IPv4-mapped matches its IPv4 host", "192.0.2.5", []string{"::ffff:192.0.2.5"}, true},
		{"bare IPv4-mapped matches its mapped form", "::ffff:192.0.2.5", []string{"::ffff:192.0.2.5"}, true},
		{"bare IPv4-mapped no match other IPv4", "192.0.2.6", []string{"::ffff:192.0.2.5"}, false},
		{"bare IPv4-mapped no match ::1", "::1", []string{"::ffff:192.0.2.5"}, false},
		{"bare IPv4-mapped no match ::/32 address", "0:0:1::1", []string{"::ffff:192.0.2.5"}, false},
		{"invalid entry skipped, valid wins", "10.0.0.1", []string{"not-an-ip", "10.0.0.0/8"}, true},
		{"all entries invalid", "10.0.0.1", []string{"not-an-ip", "garbage"}, false},
		{"empty list", "10.0.0.1", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IPInNetworks(net.ParseIP(tc.ip), tc.networks); got != tc.want {
				t.Errorf("IPInNetworks(%s, %v) = %v, want %v", tc.ip, tc.networks, got, tc.want)
			}
		})
	}
	// A nil IP is never trusted (e.g. unparseable client address).
	if IPInNetworks(nil, []string{"0.0.0.0/0"}) {
		t.Error("nil IP must never match, even against 0.0.0.0/0")
	}
}

// InvalidNetworkEntries reports exactly the entries IPInNetworks skips: anything that is
// not an IP address or CIDR, host names included (they are never resolved).
func TestInvalidNetworkEntries(t *testing.T) {
	entries := []string{
		"10.0.1.0/24", "192.0.2.7", "2001:db8::/32", "2001:db8::1",
		"admin.example.com", "localhost", "", " 192.0.2.8", "10.0.0.0/33", "fe80::1%eth0",
	}
	want := []string{"admin.example.com", "localhost", "", " 192.0.2.8", "10.0.0.0/33", "fe80::1%eth0"}
	if got := InvalidNetworkEntries(entries); !slices.Equal(got, want) {
		t.Errorf("InvalidNetworkEntries(%q) = %q, want %q", entries, got, want)
	}
	if got := InvalidNetworkEntries([]string{"10.0.0.0/8", "::1"}); len(got) != 0 {
		t.Errorf("valid list reported invalid entries %q", got)
	}
}
