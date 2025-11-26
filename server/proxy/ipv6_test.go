package proxy

import (
	"net"
	"testing"
)

// This file tests the IPv6 address resolution fix for the connection manager.
// The problem was that addresses like "localhost" from remotelookup would get
// normalized to "localhost:993" but not resolved to "[::1]:993" before dialing,
// causing "too many colons in address" errors when Go's network stack resolved
// localhost to ::1 and tried to create "::1:993" instead of "[::1]:993".

func TestConnectionManagerResolveAddress(t *testing.T) {
	cm := &ConnectionManager{}

	tests := []struct {
		name string
		addr string
		// We can't predict exact resolved IPs, but we can test format validity
		shouldBeValid bool
		description   string
	}{
		{
			name:          "IPv4 address with port",
			addr:          "127.0.0.1:993",
			shouldBeValid: true,
			description:   "Should remain unchanged as it's already an IP",
		},
		{
			name:          "IPv6 address with port and brackets",
			addr:          "[::1]:993",
			shouldBeValid: true,
			description:   "Should remain unchanged as it's already properly formatted",
		},
		{
			name:          "localhost with port",
			addr:          "localhost:993",
			shouldBeValid: true,
			description:   "Should resolve to a valid IP:port format",
		},
		{
			name:          "malformed address",
			addr:          "invalid-host-that-should-not-resolve:993",
			shouldBeValid: true,
			description:   "Should return original if resolution fails",
		},
		{
			name:          "address without port",
			addr:          "localhost",
			shouldBeValid: false,
			description:   "Should return as-is since no port specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cm.resolveAddress(tt.addr)

			if !tt.shouldBeValid {
				// For invalid cases, just check it returns something
				if result == "" {
					t.Errorf("resolveAddress(%q) returned empty string", tt.addr)
				}
				return
			}

			// For valid cases, verify the result can be parsed by net.SplitHostPort
			host, port, err := net.SplitHostPort(result)
			if err != nil {
				t.Errorf("resolveAddress(%q) = %q, but net.SplitHostPort failed: %v", tt.addr, result, err)
				return
			}

			// Verify host is a valid IP address (if resolved) or hostname
			if net.ParseIP(host) == nil && host != "invalid-host-that-should-not-resolve" {
				// If it's not an IP, it should be the original hostname (resolution failed)
				originalHost, _, _ := net.SplitHostPort(tt.addr)
				if host != originalHost {
					t.Errorf("resolveAddress(%q) returned host %q, expected either valid IP or original host", tt.addr, host)
				}
			}

			// Verify port is preserved
			_, originalPort, err := net.SplitHostPort(tt.addr)
			if err == nil && port != originalPort {
				t.Errorf("resolveAddress(%q) changed port from %q to %q", tt.addr, originalPort, port)
			}

			t.Logf("%s: %q -> %q (host=%q, port=%q)", tt.description, tt.addr, result, host, port)
		})
	}
}

func TestIPv6AddressValidation(t *testing.T) {
	// Test that our normalized addresses are valid for net.Dial
	tests := []struct {
		name    string
		addr    string
		wantErr bool
		errType string
	}{
		{
			name:    "properly formatted IPv6",
			addr:    "[::1]:993",
			wantErr: false,
		},
		{
			name:    "IPv4 address",
			addr:    "127.0.0.1:993",
			wantErr: false,
		},
		{
			name:    "malformed IPv6 (too many colons)",
			addr:    "::1:993",
			wantErr: true,
			errType: "too many colons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually dial (no server listening), but we can check
			// if the address format would cause the "too many colons" error
			host, port, err := net.SplitHostPort(tt.addr)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for address %q, but net.SplitHostPort succeeded", tt.addr)
				} else if tt.errType != "" && !containsString(err.Error(), tt.errType) {
					t.Errorf("Expected error containing %q, got: %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("net.SplitHostPort(%q) failed: %v", tt.addr, err)
				return
			}

			// For valid addresses, verify the format is correct
			rejoined := net.JoinHostPort(host, port)
			if rejoined != tt.addr {
				t.Errorf("Round-trip failed: %q -> split -> %q", tt.addr, rejoined)
			}
		})
	}
}

func TestFullIPv6WorkflowWithLocalhost(t *testing.T) {
	// This test simulates the exact problem scenario:
	// 1. Address from remotelookup (e.g., "localhost")
	// 2. Normalization with default port
	// 3. Resolution before dial

	cm := &ConnectionManager{}
	defaultPort := 993

	// Simulate remotelookup returning "localhost"
	remotelookupAddr := "localhost"

	// Step 1: Normalize (what happens in remotelookup.go)
	normalized := normalizeHostPort(remotelookupAddr, defaultPort)

	// Step 2: Resolve (what happens in connection_manager.go before dial)
	resolved := cm.resolveAddress(normalized)

	// Step 3: Verify the resolved address won't cause "too many colons" error
	host, port, err := net.SplitHostPort(resolved)
	if err != nil {
		t.Fatalf("Full workflow failed at SplitHostPort: %v\nAddress chain: %q -> %q -> %q",
			err, remotelookupAddr, normalized, resolved)
	}

	// Verify we have a valid format
	if port != "993" {
		t.Errorf("Port should be 993, got %q", port)
	}

	// If host resolved to IPv6, it should be properly formatted
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// It's IPv6, verify the resolved address has brackets
		if resolved[0] != '[' || resolved[len("[::1]")-1] != ']' {
			// This is a more flexible check than exact string matching
			rejoined := net.JoinHostPort(host, port)
			if rejoined != resolved {
				t.Errorf("IPv6 address not properly formatted: resolved=%q, rejoined=%q", resolved, rejoined)
			}
		}
	}

	t.Logf("Successful workflow: %q -> %q -> %q (host=%q, port=%q)",
		remotelookupAddr, normalized, resolved, host, port)
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
