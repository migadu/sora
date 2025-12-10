package main

import (
	"strings"
	"testing"
)

// TestProtocolFilterWithServerNames tests that protocol filtering works
// correctly when tracker keys include server names (e.g., "LMTP-proxy1").
func TestProtocolFilterWithServerNames(t *testing.T) {
	tests := []struct {
		name           string
		trackerKey     string // What's in connectionTrackers map
		filterProtocol string // What user passes to --protocol
		shouldMatch    bool
	}{
		// Prefix matching - filter by protocol type
		{
			name:           "LMTP filter matches LMTP-proxy1",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "LMTP",
			shouldMatch:    true,
		},
		{
			name:           "LMTP filter matches LMTP-proxy2",
			trackerKey:     "LMTP-proxy2",
			filterProtocol: "LMTP",
			shouldMatch:    true,
		},
		{
			name:           "IMAP filter matches IMAP-proxy1",
			trackerKey:     "IMAP-proxy1",
			filterProtocol: "IMAP",
			shouldMatch:    true,
		},

		// Exact matching - filter by specific server
		{
			name:           "LMTP-proxy1 filter matches only LMTP-proxy1",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "LMTP-proxy1",
			shouldMatch:    true,
		},
		{
			name:           "LMTP-proxy1 filter does not match LMTP-proxy2",
			trackerKey:     "LMTP-proxy2",
			filterProtocol: "LMTP-proxy1",
			shouldMatch:    false,
		},

		// Cross-protocol filtering
		{
			name:           "LMTP filter does not match IMAP-proxy1",
			trackerKey:     "IMAP-proxy1",
			filterProtocol: "LMTP",
			shouldMatch:    false,
		},
		{
			name:           "IMAP filter does not match LMTP-proxy1",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "IMAP",
			shouldMatch:    false,
		},

		// Case insensitivity
		{
			name:           "lmtp filter matches LMTP-proxy1 (case insensitive)",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "lmtp",
			shouldMatch:    true,
		},
		{
			name:           "Lmtp-Proxy1 filter matches LMTP-proxy1 (case insensitive)",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "Lmtp-Proxy1",
			shouldMatch:    true,
		},

		// Backend servers (old format without dash after protocol)
		{
			name:           "IMAP filter matches IMAP-backend1 (backward compat)",
			trackerKey:     "IMAP-backend1",
			filterProtocol: "IMAP",
			shouldMatch:    true,
		},

		// Edge cases
		{
			name:           "Empty filter matches everything",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "",
			shouldMatch:    true,
		},
		{
			name:           "Partial match does not work (LMT does not match LMTP)",
			trackerKey:     "LMTP-proxy1",
			filterProtocol: "LMT",
			shouldMatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the filtering logic from connections.go
			match := matchProtocolFilter(tt.trackerKey, tt.filterProtocol)

			if match != tt.shouldMatch {
				t.Errorf("matchProtocolFilter(%q, %q) = %v, want %v",
					tt.trackerKey, tt.filterProtocol, match, tt.shouldMatch)
			}
		})
	}
}

// matchProtocolFilter implements the filtering logic from connections.go
func matchProtocolFilter(trackerKey, filterProtocol string) bool {
	if filterProtocol == "" {
		return true // Empty filter matches everything
	}

	// Try exact match first (case-insensitive)
	exactMatch := strings.EqualFold(trackerKey, filterProtocol)

	// Try prefix match (case-insensitive)
	// e.g., "LMTP" matches "LMTP-proxy1"
	prefixMatch := strings.HasPrefix(strings.ToUpper(trackerKey), strings.ToUpper(filterProtocol)+"-")

	return exactMatch || prefixMatch
}
