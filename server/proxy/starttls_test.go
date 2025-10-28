package proxy

import (
	"testing"
	"time"
)

// TestNewConnectionManagerWithRoutingAndStartTLS verifies that the connection manager
// is properly initialized with StartTLS settings.
func TestNewConnectionManagerWithRoutingAndStartTLS(t *testing.T) {
	tests := []struct {
		name                 string
		remoteTLS            bool
		remoteTLSUseStartTLS bool
		wantStartTLS         bool
		description          string
	}{
		{
			name:                 "No TLS",
			remoteTLS:            false,
			remoteTLSUseStartTLS: false,
			wantStartTLS:         false,
			description:          "Plain connection, no TLS at all",
		},
		{
			name:                 "Implicit TLS",
			remoteTLS:            true,
			remoteTLSUseStartTLS: false,
			wantStartTLS:         false,
			description:          "Immediate TLS connection (implicit TLS)",
		},
		{
			name:                 "StartTLS",
			remoteTLS:            true,
			remoteTLSUseStartTLS: true,
			wantStartTLS:         true,
			description:          "Plain connection with StartTLS negotiation",
		},
		{
			name:                 "StartTLS without TLS enabled (invalid)",
			remoteTLS:            false,
			remoteTLSUseStartTLS: true,
			wantStartTLS:         false,
			description:          "StartTLS requires remoteTLS=true, should behave as no TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm, err := NewConnectionManagerWithRoutingAndStartTLS(
				[]string{"backend1.example.com:143", "backend2.example.com:143"},
				143,
				tt.remoteTLS,
				tt.remoteTLSUseStartTLS,
				true,  // remoteTLSVerify
				false, // remoteUseProxyProtocol
				10*time.Second,
				nil, // routingLookup
				"",  // serverName (empty for tests)
			)

			if err != nil {
				t.Fatalf("Failed to create connection manager: %v", err)
			}

			// Verify TLS settings
			if cm.remoteTLS != tt.remoteTLS {
				t.Errorf("Expected remoteTLS=%v, got %v", tt.remoteTLS, cm.remoteTLS)
			}

			if cm.remoteTLSUseStartTLS != tt.remoteTLSUseStartTLS {
				t.Errorf("Expected remoteTLSUseStartTLS=%v, got %v", tt.remoteTLSUseStartTLS, cm.remoteTLSUseStartTLS)
			}

			// Verify IsRemoteStartTLS() returns correct value
			gotStartTLS := cm.IsRemoteStartTLS()
			if gotStartTLS != tt.wantStartTLS {
				t.Errorf("%s: IsRemoteStartTLS() = %v, want %v", tt.description, gotStartTLS, tt.wantStartTLS)
			}

			// Verify GetTLSConfig() behavior
			tlsConfig := cm.GetTLSConfig()
			if tt.remoteTLS {
				if tlsConfig == nil {
					t.Errorf("Expected TLS config when remoteTLS=true, got nil")
				} else {
					// Verify InsecureSkipVerify is set correctly (opposite of remoteTLSVerify)
					if tlsConfig.InsecureSkipVerify != false {
						t.Errorf("Expected InsecureSkipVerify=false (remoteTLSVerify=true), got %v",
							tlsConfig.InsecureSkipVerify)
					}
				}
			} else {
				if tlsConfig != nil {
					t.Errorf("Expected nil TLS config when remoteTLS=false, got %+v", tlsConfig)
				}
			}

			t.Logf("%s: remoteTLS=%v, useStartTLS=%v -> IsRemoteStartTLS()=%v",
				tt.description, tt.remoteTLS, tt.remoteTLSUseStartTLS, gotStartTLS)
		})
	}
}

// TestConnectionManagerGetTLSConfig verifies TLS config generation.
func TestConnectionManagerGetTLSConfig(t *testing.T) {
	tests := []struct {
		name            string
		remoteTLS       bool
		remoteTLSVerify bool
		wantNil         bool
		wantSkipVerify  bool
	}{
		{
			name:            "No TLS",
			remoteTLS:       false,
			remoteTLSVerify: false,
			wantNil:         true,
			wantSkipVerify:  false, // irrelevant when nil
		},
		{
			name:            "TLS with verification",
			remoteTLS:       true,
			remoteTLSVerify: true,
			wantNil:         false,
			wantSkipVerify:  false, // InsecureSkipVerify should be false
		},
		{
			name:            "TLS without verification",
			remoteTLS:       true,
			remoteTLSVerify: false,
			wantNil:         false,
			wantSkipVerify:  true, // InsecureSkipVerify should be true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm, err := NewConnectionManagerWithRoutingAndStartTLS(
				[]string{"backend1.example.com:143"},
				143,
				tt.remoteTLS,
				false, // remoteTLSUseStartTLS (doesn't affect GetTLSConfig)
				tt.remoteTLSVerify,
				false, // remoteUseProxyProtocol
				10*time.Second,
				nil,
				"", // serverName (empty for tests)
			)

			if err != nil {
				t.Fatalf("Failed to create connection manager: %v", err)
			}

			tlsConfig := cm.GetTLSConfig()

			if tt.wantNil {
				if tlsConfig != nil {
					t.Errorf("Expected nil TLS config, got %+v", tlsConfig)
				}
				return
			}

			if tlsConfig == nil {
				t.Fatalf("Expected TLS config, got nil")
			}

			if tlsConfig.InsecureSkipVerify != tt.wantSkipVerify {
				t.Errorf("Expected InsecureSkipVerify=%v, got %v", tt.wantSkipVerify, tlsConfig.InsecureSkipVerify)
			}

			// Verify no client certificates are set
			if len(tlsConfig.Certificates) != 0 {
				t.Errorf("Expected no certificates, got %d", len(tlsConfig.Certificates))
			}

			// Verify GetClientCertificate returns nil
			if tlsConfig.GetClientCertificate != nil {
				cert, err := tlsConfig.GetClientCertificate(nil)
				if cert != nil || err != nil {
					t.Errorf("Expected GetClientCertificate to return (nil, nil), got (%v, %v)", cert, err)
				}
			}
		})
	}
}

// TestConnectionManagerIsRemoteStartTLS verifies the StartTLS detection logic.
func TestConnectionManagerIsRemoteStartTLS(t *testing.T) {
	tests := []struct {
		name                 string
		remoteTLS            bool
		remoteTLSUseStartTLS bool
		want                 bool
	}{
		{
			name:                 "No TLS",
			remoteTLS:            false,
			remoteTLSUseStartTLS: false,
			want:                 false,
		},
		{
			name:                 "Implicit TLS only",
			remoteTLS:            true,
			remoteTLSUseStartTLS: false,
			want:                 false,
		},
		{
			name:                 "StartTLS enabled",
			remoteTLS:            true,
			remoteTLSUseStartTLS: true,
			want:                 true,
		},
		{
			name:                 "StartTLS flag without TLS",
			remoteTLS:            false,
			remoteTLSUseStartTLS: true,
			want:                 false, // Should return false because remoteTLS must be true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm, err := NewConnectionManagerWithRoutingAndStartTLS(
				[]string{"backend1.example.com:143"},
				143,
				tt.remoteTLS,
				tt.remoteTLSUseStartTLS,
				true,
				false,
				10*time.Second,
				nil,
				"", // serverName (empty for tests)
			)

			if err != nil {
				t.Fatalf("Failed to create connection manager: %v", err)
			}

			got := cm.IsRemoteStartTLS()
			if got != tt.want {
				t.Errorf("IsRemoteStartTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestConnectionManagerBackwardCompatibility ensures that the new StartTLS functionality
// doesn't break existing code that uses the old constructors.
func TestConnectionManagerBackwardCompatibility(t *testing.T) {
	// Test old constructor still works
	cm1, err := NewConnectionManager(
		[]string{"backend1.example.com:143"},
		143,
		true,  // remoteTLS
		true,  // remoteTLSVerify
		false, // remoteUseProxyProtocol
		10*time.Second,
	)

	if err != nil {
		t.Fatalf("NewConnectionManager failed: %v", err)
	}

	// Should default to implicit TLS (no StartTLS)
	if cm1.remoteTLSUseStartTLS {
		t.Error("Expected remoteTLSUseStartTLS=false for old constructor")
	}

	if cm1.IsRemoteStartTLS() {
		t.Error("Expected IsRemoteStartTLS()=false for old constructor")
	}

	// Test NewConnectionManagerWithRouting still works
	cm2, err := NewConnectionManagerWithRouting(
		[]string{"backend1.example.com:143"},
		143,
		true,  // remoteTLS
		true,  // remoteTLSVerify
		false, // remoteUseProxyProtocol
		10*time.Second,
		nil, // routingLookup
		"",  // serverName (empty for tests)
	)

	if err != nil {
		t.Fatalf("NewConnectionManagerWithRouting failed: %v", err)
	}

	// Should default to implicit TLS (no StartTLS)
	if cm2.remoteTLSUseStartTLS {
		t.Error("Expected remoteTLSUseStartTLS=false for NewConnectionManagerWithRouting")
	}

	if cm2.IsRemoteStartTLS() {
		t.Error("Expected IsRemoteStartTLS()=false for NewConnectionManagerWithRouting")
	}

	t.Log("Backward compatibility verified: old constructors default to implicit TLS")
}

// TestConnectionManagerTLSConfigIndependence verifies that GetTLSConfig returns
// a new config each time (not a shared reference).
func TestConnectionManagerTLSConfigIndependence(t *testing.T) {
	cm, err := NewConnectionManagerWithRoutingAndStartTLS(
		[]string{"backend1.example.com:143"},
		143,
		true,  // remoteTLS
		true,  // remoteTLSUseStartTLS
		true,  // remoteTLSVerify
		false, // remoteUseProxyProtocol
		10*time.Second,
		nil,
		"", // serverName (empty for tests)
	)

	if err != nil {
		t.Fatalf("Failed to create connection manager: %v", err)
	}

	config1 := cm.GetTLSConfig()
	config2 := cm.GetTLSConfig()

	// Configs should have the same settings but be different objects
	if config1 == config2 {
		t.Error("GetTLSConfig() returned the same object reference, expected independent configs")
	}

	// But they should have the same values
	if config1.InsecureSkipVerify != config2.InsecureSkipVerify {
		t.Error("TLS configs should have the same InsecureSkipVerify value")
	}
}
