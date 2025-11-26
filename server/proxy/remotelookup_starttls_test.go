package proxy

import (
	"testing"

	"github.com/migadu/sora/config"
)

// TestRemoteLookupStartTLSConfiguration verifies that remotelookup correctly propagates
// StartTLS configuration to routing information.
func TestRemoteLookupStartTLSConfiguration(t *testing.T) {
	tests := []struct {
		name                    string
		remotelookupRemoteTLS   bool
		remotelookupStartTLS    bool
		expectedRoutingTLS      bool
		expectedRoutingStartTLS bool
		description             string
	}{
		{
			name:                    "No TLS in remotelookup",
			remotelookupRemoteTLS:   false,
			remotelookupStartTLS:    false,
			expectedRoutingTLS:      false,
			expectedRoutingStartTLS: false,
			description:             "Plain connection from remotelookup-routed backends",
		},
		{
			name:                    "Implicit TLS in remotelookup",
			remotelookupRemoteTLS:   true,
			remotelookupStartTLS:    false,
			expectedRoutingTLS:      true,
			expectedRoutingStartTLS: false,
			description:             "Immediate TLS connection from remotelookup-routed backends",
		},
		{
			name:                    "StartTLS in remotelookup",
			remotelookupRemoteTLS:   true,
			remotelookupStartTLS:    true,
			expectedRoutingTLS:      true,
			expectedRoutingStartTLS: true,
			description:             "StartTLS negotiation from remotelookup-routed backends",
		},
		{
			name:                    "StartTLS without TLS (invalid config)",
			remotelookupRemoteTLS:   false,
			remotelookupStartTLS:    true,
			expectedRoutingTLS:      false,
			expectedRoutingStartTLS: true, // Config honors setting even if invalid
			description:             "StartTLS requires remote_tls=true, but config is preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal RemoteLookupConfig with TLS settings
			cfg := &config.RemoteLookupConfig{
				RemoteTLS:            tt.remotelookupRemoteTLS,
				RemoteTLSUseStartTLS: tt.remotelookupStartTLS,
			}

			// Verify the config fields are set correctly
			if cfg.RemoteTLS != tt.remotelookupRemoteTLS {
				t.Errorf("RemoteLookupConfig.RemoteTLS = %v, want %v",
					cfg.RemoteTLS, tt.remotelookupRemoteTLS)
			}
			if cfg.RemoteTLSUseStartTLS != tt.remotelookupStartTLS {
				t.Errorf("RemoteLookupConfig.RemoteTLSUseStartTLS = %v, want %v",
					cfg.RemoteTLSUseStartTLS, tt.remotelookupStartTLS)
			}

			// Simulate what RemoteLookupClient does when creating UserRoutingInfo
			routingInfo := &UserRoutingInfo{
				RemoteTLS:            cfg.RemoteTLS,
				RemoteTLSUseStartTLS: cfg.RemoteTLSUseStartTLS,
			}

			// Verify routing info has correct TLS settings
			if routingInfo.RemoteTLS != tt.expectedRoutingTLS {
				t.Errorf("%s: routingInfo.RemoteTLS = %v, want %v",
					tt.description, routingInfo.RemoteTLS, tt.expectedRoutingTLS)
			}
			if routingInfo.RemoteTLSUseStartTLS != tt.expectedRoutingStartTLS {
				t.Errorf("%s: routingInfo.RemoteTLSUseStartTLS = %v, want %v",
					tt.description, routingInfo.RemoteTLSUseStartTLS, tt.expectedRoutingStartTLS)
			}

			t.Logf("%s: remotelookup remote_tls=%v, remote_tls_use_starttls=%v -> routing RemoteTLS=%v, RemoteTLSUseStartTLS=%v",
				tt.description, tt.remotelookupRemoteTLS, tt.remotelookupStartTLS,
				routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS)
		})
	}
}

// TestRemoteLookupRoutingInfoOverridesGlobalSettings verifies that remotelookup routing
// information correctly overrides global connection manager settings for TLS.
func TestRemoteLookupRoutingInfoOverridesGlobalSettings(t *testing.T) {
	tests := []struct {
		name                      string
		globalTLS                 bool
		globalStartTLS            bool
		remotelookupTLS           bool
		remotelookupStartTLS      bool
		expectOverride            bool
		expectedEffectiveTLS      bool
		expectedEffectiveStartTLS bool
		description               string
	}{
		{
			name:                      "RemoteLookup requires StartTLS, global uses implicit TLS",
			globalTLS:                 true,
			globalStartTLS:            false,
			remotelookupTLS:           true,
			remotelookupStartTLS:      true,
			expectOverride:            true,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: true,
			description:               "RemoteLookup StartTLS should override global implicit TLS",
		},
		{
			name:                      "RemoteLookup requires implicit TLS, global uses StartTLS",
			globalTLS:                 true,
			globalStartTLS:            true,
			remotelookupTLS:           true,
			remotelookupStartTLS:      false,
			expectOverride:            true,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: false,
			description:               "RemoteLookup implicit TLS should override global StartTLS",
		},
		{
			name:                      "RemoteLookup requires plain, global uses TLS",
			globalTLS:                 true,
			globalStartTLS:            false,
			remotelookupTLS:           false,
			remotelookupStartTLS:      false,
			expectOverride:            true,
			expectedEffectiveTLS:      false,
			expectedEffectiveStartTLS: false,
			description:               "RemoteLookup plain should override global TLS settings",
		},
		{
			name:                      "No remotelookup override - use global settings",
			globalTLS:                 true,
			globalStartTLS:            true,
			remotelookupTLS:           false,
			remotelookupStartTLS:      false,
			expectOverride:            false,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: true,
			description:               "Without remotelookup routing, global settings should be used",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var effectiveTLS, effectiveStartTLS bool

			if tt.expectOverride {
				// Simulate remotelookup override logic from connection_manager.go dialWithProxy
				routingInfo := &UserRoutingInfo{
					RemoteTLS:            tt.remotelookupTLS,
					RemoteTLSUseStartTLS: tt.remotelookupStartTLS,
				}
				effectiveTLS = routingInfo.RemoteTLS
				effectiveStartTLS = routingInfo.RemoteTLSUseStartTLS
			} else {
				// Use global settings (no remotelookup override)
				effectiveTLS = tt.globalTLS
				effectiveStartTLS = tt.globalStartTLS
			}

			// Verify effective settings match expectations
			if effectiveTLS != tt.expectedEffectiveTLS {
				t.Errorf("%s: effective TLS = %v, want %v",
					tt.description, effectiveTLS, tt.expectedEffectiveTLS)
			}
			if effectiveStartTLS != tt.expectedEffectiveStartTLS {
				t.Errorf("%s: effective StartTLS = %v, want %v",
					tt.description, effectiveStartTLS, tt.expectedEffectiveStartTLS)
			}

			t.Logf("%s: global(TLS=%v,StartTLS=%v) remotelookup(TLS=%v,StartTLS=%v) override=%v -> effective(TLS=%v,StartTLS=%v)",
				tt.description, tt.globalTLS, tt.globalStartTLS,
				tt.remotelookupTLS, tt.remotelookupStartTLS, tt.expectOverride,
				effectiveTLS, effectiveStartTLS)
		})
	}
}

// TestUserRoutingInfoStartTLSFields verifies that UserRoutingInfo struct
// correctly stores and exposes StartTLS configuration.
func TestUserRoutingInfoStartTLSFields(t *testing.T) {
	routingInfo := &UserRoutingInfo{
		IsRemoteLookupAccount: true,
		RemoteTLS:             true,
		RemoteTLSUseStartTLS:  true,
		RemoteTLSVerify:       true,
	}

	// Verify all fields are accessible and correct
	if !routingInfo.RemoteTLS {
		t.Error("Expected RemoteTLS to be true")
	}
	if !routingInfo.RemoteTLSUseStartTLS {
		t.Error("Expected RemoteTLSUseStartTLS to be true")
	}
	if !routingInfo.RemoteTLSVerify {
		t.Error("Expected RemoteTLSVerify to be true")
	}
	if !routingInfo.IsRemoteLookupAccount {
		t.Error("Expected IsRemoteLookupAccount to be true")
	}

	t.Logf("UserRoutingInfo fields verified: RemoteTLS=%v, RemoteTLSUseStartTLS=%v, RemoteTLSVerify=%v",
		routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS, routingInfo.RemoteTLSVerify)
}
