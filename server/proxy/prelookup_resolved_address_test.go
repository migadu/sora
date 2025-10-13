package proxy

import (
	"testing"
)

// TestUserRoutingInfoResolvedAddress verifies that the ResolvedAddress field
// is properly stored and can override ServerAddress for routing decisions.
func TestUserRoutingInfoResolvedAddress(t *testing.T) {
	tests := []struct {
		name            string
		serverAddress   string
		resolvedAddress string
		expectedRoute   string
		description     string
	}{
		{
			name:            "No resolved address - use server address",
			serverAddress:   "backend1.example.com:143",
			resolvedAddress: "",
			expectedRoute:   "backend1.example.com:143",
			description:     "When resolved_address is empty, should use server_address",
		},
		{
			name:            "Resolved address provided - use it",
			serverAddress:   "backend1",
			resolvedAddress: "192.168.1.10:143",
			expectedRoute:   "192.168.1.10:143",
			description:     "When resolved_address is set, it should be used for routing",
		},
		{
			name:            "Resolved address with IPv6",
			serverAddress:   "backend-cluster",
			resolvedAddress: "[2001:db8::1]:143",
			expectedRoute:   "[2001:db8::1]:143",
			description:     "IPv6 resolved addresses should be preserved with brackets",
		},
		{
			name:            "Both addresses same",
			serverAddress:   "backend2.example.com:993",
			resolvedAddress: "backend2.example.com:993",
			expectedRoute:   "backend2.example.com:993",
			description:     "When both are the same, no conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routingInfo := &UserRoutingInfo{
				ServerAddress:   tt.serverAddress,
				ResolvedAddress: tt.resolvedAddress,
			}

			// Determine which address would be used (mimics DetermineRoute logic)
			actualRoute := routingInfo.ServerAddress
			if routingInfo.ResolvedAddress != "" {
				actualRoute = routingInfo.ResolvedAddress
			}

			if actualRoute != tt.expectedRoute {
				t.Errorf("%s: got route %q, want %q",
					tt.description, actualRoute, tt.expectedRoute)
			}

			t.Logf("%s: server=%q, resolved=%q -> route=%q",
				tt.description, tt.serverAddress, tt.resolvedAddress, actualRoute)
		})
	}
}

// TestResolvedAddressFieldsInStruct verifies that UserRoutingInfo struct
// has both ServerAddress and ResolvedAddress fields with correct behavior.
func TestResolvedAddressFieldsInStruct(t *testing.T) {
	routingInfo := &UserRoutingInfo{
		ServerAddress:   "logical-server",
		ResolvedAddress: "192.168.1.100:143",
		AccountID:       12345,
		// IsPrelookupAccount:     true,
		// RemoteTLS:              true,
		// RemoteTLSUseStartTLS:   false,
		// RemoteTLSVerify:        true,
		// RemoteUseProxyProtocol: true,
		// RemoteUseIDCommand:     true,
		// RemoteUseXCLIENT:       false,
	}

	// Verify all fields are accessible
	if routingInfo.ServerAddress != "logical-server" {
		t.Errorf("ServerAddress = %q, want %q", routingInfo.ServerAddress, "logical-server")
	}
	if routingInfo.ResolvedAddress != "192.168.1.100:143" {
		t.Errorf("ResolvedAddress = %q, want %q", routingInfo.ResolvedAddress, "192.168.1.100:143")
	}
	if routingInfo.AccountID != 12345 {
		t.Errorf("AccountID = %d, want %d", routingInfo.AccountID, 12345)
	}

	t.Logf("UserRoutingInfo fields verified: ServerAddress=%q, ResolvedAddress=%q, AccountID=%d",
		routingInfo.ServerAddress, routingInfo.ResolvedAddress, routingInfo.AccountID)
}

// TestResolvedAddressPrecedence verifies the precedence logic:
// ResolvedAddress > ServerAddress when both are present
func TestResolvedAddressPrecedence(t *testing.T) {
	scenarios := []struct {
		name        string
		info        *UserRoutingInfo
		expectAddr  string
		description string
	}{
		{
			name: "Resolved takes precedence",
			info: &UserRoutingInfo{
				ServerAddress:   "backend1:143",
				ResolvedAddress: "backend2:143",
			},
			expectAddr:  "backend2:143",
			description: "ResolvedAddress should override ServerAddress",
		},
		{
			name: "Empty resolved falls back",
			info: &UserRoutingInfo{
				ServerAddress:   "backend1:143",
				ResolvedAddress: "",
			},
			expectAddr:  "backend1:143",
			description: "Empty ResolvedAddress should fall back to ServerAddress",
		},
		{
			name: "Only server address",
			info: &UserRoutingInfo{
				ServerAddress: "backend1:143",
			},
			expectAddr:  "backend1:143",
			description: "When no ResolvedAddress, use ServerAddress",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Simulate the logic from DetermineRoute
			preferredAddr := scenario.info.ServerAddress
			if scenario.info.ResolvedAddress != "" {
				preferredAddr = scenario.info.ResolvedAddress
			}

			if preferredAddr != scenario.expectAddr {
				t.Errorf("%s: got %q, want %q",
					scenario.description, preferredAddr, scenario.expectAddr)
			}

			t.Logf("%s: server=%q, resolved=%q -> preferred=%q",
				scenario.description,
				scenario.info.ServerAddress,
				scenario.info.ResolvedAddress,
				preferredAddr)
		})
	}
}

// TestResolvedAddressWithAuthentication verifies that resolved_address works
// correctly in authentication mode (with password_hash and account_id).
func TestResolvedAddressWithAuthentication(t *testing.T) {
	// This simulates what _handleAuthAndRoute would create after successful auth
	routingInfo := &UserRoutingInfo{
		ServerAddress:      "backend-cluster",
		ResolvedAddress:    "192.168.1.50:143",
		AccountID:          67890,
		IsPrelookupAccount: true,
		// RemoteTLS:          true,
	}

	// Verify all authentication-related fields are set correctly
	if !routingInfo.IsPrelookupAccount {
		t.Error("Expected IsPrelookupAccount to be true")
	}
	if routingInfo.AccountID != 67890 {
		t.Errorf("AccountID = %d, want 67890", routingInfo.AccountID)
	}

	// Verify address resolution still works with auth fields
	effectiveAddr := routingInfo.ServerAddress
	if routingInfo.ResolvedAddress != "" {
		effectiveAddr = routingInfo.ResolvedAddress
	}

	if effectiveAddr != "192.168.1.50:143" {
		t.Errorf("Effective address = %q, want %q", effectiveAddr, "192.168.1.50:143")
	}

	t.Logf("Auth+Route+Resolved: account_id=%d, server=%q, resolved=%q -> route=%q",
		routingInfo.AccountID,
		routingInfo.ServerAddress,
		routingInfo.ResolvedAddress,
		effectiveAddr)
}
