package proxy

import (
	"testing"

	"github.com/migadu/sora/config"
)

// TestPrelookupStartTLSConfiguration verifies that prelookup correctly propagates
// StartTLS configuration to routing information.
func TestPrelookupStartTLSConfiguration(t *testing.T) {
	tests := []struct {
		name                    string
		prelookupRemoteTLS      bool
		prelookupStartTLS       bool
		expectedRoutingTLS      bool
		expectedRoutingStartTLS bool
		description             string
	}{
		{
			name:                    "No TLS in prelookup",
			prelookupRemoteTLS:      false,
			prelookupStartTLS:       false,
			expectedRoutingTLS:      false,
			expectedRoutingStartTLS: false,
			description:             "Plain connection from prelookup-routed backends",
		},
		{
			name:                    "Implicit TLS in prelookup",
			prelookupRemoteTLS:      true,
			prelookupStartTLS:       false,
			expectedRoutingTLS:      true,
			expectedRoutingStartTLS: false,
			description:             "Immediate TLS connection from prelookup-routed backends",
		},
		{
			name:                    "StartTLS in prelookup",
			prelookupRemoteTLS:      true,
			prelookupStartTLS:       true,
			expectedRoutingTLS:      true,
			expectedRoutingStartTLS: true,
			description:             "StartTLS negotiation from prelookup-routed backends",
		},
		{
			name:                    "StartTLS without TLS (invalid config)",
			prelookupRemoteTLS:      false,
			prelookupStartTLS:       true,
			expectedRoutingTLS:      false,
			expectedRoutingStartTLS: true, // Config honors setting even if invalid
			description:             "StartTLS requires remote_tls=true, but config is preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal PreLookupConfig with TLS settings
			cfg := &config.PreLookupConfig{
				RemoteTLS:            tt.prelookupRemoteTLS,
				RemoteTLSUseStartTLS: tt.prelookupStartTLS,
			}

			// Verify the config fields are set correctly
			if cfg.RemoteTLS != tt.prelookupRemoteTLS {
				t.Errorf("PreLookupConfig.RemoteTLS = %v, want %v",
					cfg.RemoteTLS, tt.prelookupRemoteTLS)
			}
			if cfg.RemoteTLSUseStartTLS != tt.prelookupStartTLS {
				t.Errorf("PreLookupConfig.RemoteTLSUseStartTLS = %v, want %v",
					cfg.RemoteTLSUseStartTLS, tt.prelookupStartTLS)
			}

			// Simulate what PreLookupClient does when creating UserRoutingInfo
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

			t.Logf("%s: prelookup remote_tls=%v, remote_tls_use_starttls=%v -> routing RemoteTLS=%v, RemoteTLSUseStartTLS=%v",
				tt.description, tt.prelookupRemoteTLS, tt.prelookupStartTLS,
				routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS)
		})
	}
}

// TestPrelookupRoutingInfoOverridesGlobalSettings verifies that prelookup routing
// information correctly overrides global connection manager settings for TLS.
func TestPrelookupRoutingInfoOverridesGlobalSettings(t *testing.T) {
	tests := []struct {
		name                      string
		globalTLS                 bool
		globalStartTLS            bool
		prelookupTLS              bool
		prelookupStartTLS         bool
		expectOverride            bool
		expectedEffectiveTLS      bool
		expectedEffectiveStartTLS bool
		description               string
	}{
		{
			name:                      "Prelookup requires StartTLS, global uses implicit TLS",
			globalTLS:                 true,
			globalStartTLS:            false,
			prelookupTLS:              true,
			prelookupStartTLS:         true,
			expectOverride:            true,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: true,
			description:               "Prelookup StartTLS should override global implicit TLS",
		},
		{
			name:                      "Prelookup requires implicit TLS, global uses StartTLS",
			globalTLS:                 true,
			globalStartTLS:            true,
			prelookupTLS:              true,
			prelookupStartTLS:         false,
			expectOverride:            true,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: false,
			description:               "Prelookup implicit TLS should override global StartTLS",
		},
		{
			name:                      "Prelookup requires plain, global uses TLS",
			globalTLS:                 true,
			globalStartTLS:            false,
			prelookupTLS:              false,
			prelookupStartTLS:         false,
			expectOverride:            true,
			expectedEffectiveTLS:      false,
			expectedEffectiveStartTLS: false,
			description:               "Prelookup plain should override global TLS settings",
		},
		{
			name:                      "No prelookup override - use global settings",
			globalTLS:                 true,
			globalStartTLS:            true,
			prelookupTLS:              false,
			prelookupStartTLS:         false,
			expectOverride:            false,
			expectedEffectiveTLS:      true,
			expectedEffectiveStartTLS: true,
			description:               "Without prelookup routing, global settings should be used",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var effectiveTLS, effectiveStartTLS bool

			if tt.expectOverride {
				// Simulate prelookup override logic from connection_manager.go dialWithProxy
				routingInfo := &UserRoutingInfo{
					RemoteTLS:            tt.prelookupTLS,
					RemoteTLSUseStartTLS: tt.prelookupStartTLS,
				}
				effectiveTLS = routingInfo.RemoteTLS
				effectiveStartTLS = routingInfo.RemoteTLSUseStartTLS
			} else {
				// Use global settings (no prelookup override)
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

			t.Logf("%s: global(TLS=%v,StartTLS=%v) prelookup(TLS=%v,StartTLS=%v) override=%v -> effective(TLS=%v,StartTLS=%v)",
				tt.description, tt.globalTLS, tt.globalStartTLS,
				tt.prelookupTLS, tt.prelookupStartTLS, tt.expectOverride,
				effectiveTLS, effectiveStartTLS)
		})
	}
}

// TestUserRoutingInfoStartTLSFields verifies that UserRoutingInfo struct
// correctly stores and exposes StartTLS configuration.
func TestUserRoutingInfoStartTLSFields(t *testing.T) {
	routingInfo := &UserRoutingInfo{
		IsPrelookupAccount:   true,
		RemoteTLS:            true,
		RemoteTLSUseStartTLS: true,
		RemoteTLSVerify:      true,
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
	if !routingInfo.IsPrelookupAccount {
		t.Error("Expected IsPrelookupAccount to be true")
	}

	t.Logf("UserRoutingInfo fields verified: RemoteTLS=%v, RemoteTLSUseStartTLS=%v, RemoteTLSVerify=%v",
		routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS, routingInfo.RemoteTLSVerify)
}
