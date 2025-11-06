package managesieveproxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestManageSieveProxyServerOptions verifies that ServerOptions correctly stores StartTLS settings.
func TestManageSieveProxyServerOptions(t *testing.T) {
	tests := []struct {
		name                 string
		tlsUseStartTLS       bool
		remoteTLSUseStartTLS bool
		description          string
	}{
		{
			name:                 "No StartTLS",
			tlsUseStartTLS:       false,
			remoteTLSUseStartTLS: false,
			description:          "Traditional implicit TLS or no TLS",
		},
		{
			name:                 "Client StartTLS only",
			tlsUseStartTLS:       true,
			remoteTLSUseStartTLS: false,
			description:          "StartTLS for client connections, implicit TLS for backend",
		},
		{
			name:                 "Remote StartTLS only",
			tlsUseStartTLS:       false,
			remoteTLSUseStartTLS: true,
			description:          "Implicit TLS for clients, StartTLS for backend",
		},
		{
			name:                 "Both StartTLS",
			tlsUseStartTLS:       true,
			remoteTLSUseStartTLS: true,
			description:          "StartTLS for both client and backend connections",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ServerOptions{
				TLSUseStartTLS:       tt.tlsUseStartTLS,
				RemoteTLSUseStartTLS: tt.remoteTLSUseStartTLS,
				AuthRateLimit: server.AuthRateLimiterConfig{
					Enabled: false,
				},
			}

			// Verify the options are stored correctly
			if opts.TLSUseStartTLS != tt.tlsUseStartTLS {
				t.Errorf("Expected TLSUseStartTLS=%v, got %v", tt.tlsUseStartTLS, opts.TLSUseStartTLS)
			}

			if opts.RemoteTLSUseStartTLS != tt.remoteTLSUseStartTLS {
				t.Errorf("Expected RemoteTLSUseStartTLS=%v, got %v", tt.remoteTLSUseStartTLS, opts.RemoteTLSUseStartTLS)
			}

			t.Logf("%s: TLSUseStartTLS=%v, RemoteTLSUseStartTLS=%v",
				tt.description, opts.TLSUseStartTLS, opts.RemoteTLSUseStartTLS)
		})
	}
}

// TestManageSieveProxyServerStartTLSConfiguration tests that the server
// properly stores and uses StartTLS configuration.
func TestManageSieveProxyServerStartTLSConfiguration(t *testing.T) {
	// Note: We can't fully test server.Start() without setting up actual
	// network listeners, but we can verify that configuration is properly
	// stored in the Server struct.

	tests := []struct {
		name                 string
		tlsEnabled           bool
		tlsUseStartTLS       bool
		remoteTLSEnabled     bool
		remoteTLSUseStartTLS bool
		wantTLSUseStartTLS   bool
		description          string
	}{
		{
			name:                 "No TLS at all",
			tlsEnabled:           false,
			tlsUseStartTLS:       false,
			remoteTLSEnabled:     false,
			remoteTLSUseStartTLS: false,
			wantTLSUseStartTLS:   false,
			description:          "Plain connections everywhere",
		},
		{
			name:                 "Client implicit TLS",
			tlsEnabled:           true,
			tlsUseStartTLS:       false,
			remoteTLSEnabled:     false,
			remoteTLSUseStartTLS: false,
			wantTLSUseStartTLS:   false,
			description:          "Implicit TLS for clients, plain for backend",
		},
		{
			name:                 "Client StartTLS",
			tlsEnabled:           true,
			tlsUseStartTLS:       true,
			remoteTLSEnabled:     false,
			remoteTLSUseStartTLS: false,
			wantTLSUseStartTLS:   true,
			description:          "StartTLS for clients, plain for backend",
		},
		{
			name:                 "Remote StartTLS",
			tlsEnabled:           false,
			tlsUseStartTLS:       false,
			remoteTLSEnabled:     true,
			remoteTLSUseStartTLS: true,
			wantTLSUseStartTLS:   false,
			description:          "Plain for clients, StartTLS for backend",
		},
		{
			name:                 "Both StartTLS",
			tlsEnabled:           true,
			tlsUseStartTLS:       true,
			remoteTLSEnabled:     true,
			remoteTLSUseStartTLS: true,
			wantTLSUseStartTLS:   true,
			description:          "StartTLS everywhere",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			opts := ServerOptions{
				Name:                 "test-proxy",
				Addr:                 ":14190",
				RemoteAddrs:          []string{"backend1.example.com:4190"},
				RemotePort:           4190,
				TLS:                  tt.tlsEnabled,
				TLSUseStartTLS:       tt.tlsUseStartTLS,
				TLSCertFile:          "../../testdata/sora.crt",
				TLSKeyFile:           "../../testdata/sora.key",
				TLSVerify:            false,
				RemoteTLS:            tt.remoteTLSEnabled,
				RemoteTLSUseStartTLS: tt.remoteTLSUseStartTLS,
				RemoteTLSVerify:      true,
				ConnectTimeout:       10 * time.Second,
				AuthIdleTimeout:      30 * time.Minute,
				CommandTimeout:       5 * time.Minute,
				MasterSASLUsername:   "proxyuser",
				MasterSASLPassword:   "proxypass",
				AuthRateLimit: server.AuthRateLimiterConfig{
					Enabled: false,
				},
			}

			// Create server (but don't start it - we'd need real certs for that)
			srv, err := New(ctx, nil, "test.example.com", opts)

			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Verify the server stored the configuration correctly
			if srv.tls != tt.tlsEnabled {
				t.Errorf("Expected tls=%v, got %v", tt.tlsEnabled, srv.tls)
			}

			if srv.tlsUseStartTLS != tt.wantTLSUseStartTLS {
				t.Errorf("Expected tlsUseStartTLS=%v, got %v", tt.wantTLSUseStartTLS, srv.tlsUseStartTLS)
			}

			// Verify connection manager was configured with correct StartTLS settings
			if srv.connManager != nil {
				isRemoteStartTLS := srv.connManager.IsRemoteStartTLS()
				wantRemoteStartTLS := tt.remoteTLSEnabled && tt.remoteTLSUseStartTLS

				if isRemoteStartTLS != wantRemoteStartTLS {
					t.Errorf("Expected connManager.IsRemoteStartTLS()=%v, got %v",
						wantRemoteStartTLS, isRemoteStartTLS)
				}

				t.Logf("%s: Client StartTLS=%v, Backend StartTLS=%v",
					tt.description, srv.tlsUseStartTLS, isRemoteStartTLS)
			}

			// Clean up
			srv.Stop()
		})
	}
}

// TestManageSieveProxyTLSModeMatrix verifies all valid combinations of TLS modes.
func TestManageSieveProxyTLSModeMatrix(t *testing.T) {
	// This test documents all valid TLS configuration combinations
	modes := []struct {
		clientMode  string
		backendMode string
		config      ServerOptions
	}{
		{
			clientMode:  "Plain",
			backendMode: "Plain",
			config: ServerOptions{
				TLS:                  false,
				TLSUseStartTLS:       false,
				RemoteTLS:            false,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "Implicit TLS",
			backendMode: "Plain",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       false,
				RemoteTLS:            false,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "StartTLS",
			backendMode: "Plain",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       true,
				RemoteTLS:            false,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "Plain",
			backendMode: "Implicit TLS",
			config: ServerOptions{
				TLS:                  false,
				TLSUseStartTLS:       false,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "Implicit TLS",
			backendMode: "Implicit TLS",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       false,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "StartTLS",
			backendMode: "Implicit TLS",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       true,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: false,
			},
		},
		{
			clientMode:  "Plain",
			backendMode: "StartTLS",
			config: ServerOptions{
				TLS:                  false,
				TLSUseStartTLS:       false,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: true,
			},
		},
		{
			clientMode:  "Implicit TLS",
			backendMode: "StartTLS",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       false,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: true,
			},
		},
		{
			clientMode:  "StartTLS",
			backendMode: "StartTLS",
			config: ServerOptions{
				TLS:                  true,
				TLSUseStartTLS:       true,
				RemoteTLS:            true,
				RemoteTLSUseStartTLS: true,
			},
		},
	}

	for _, mode := range modes {
		t.Run(mode.clientMode+"_to_"+mode.backendMode, func(t *testing.T) {
			ctx := context.Background()

			opts := mode.config
			opts.Name = "test-proxy"
			opts.Addr = ":14190"
			opts.RemoteAddrs = []string{"backend.example.com:4190"}
			opts.RemotePort = 4190
			opts.ConnectTimeout = 10 * time.Second
			opts.AuthIdleTimeout = 30 * time.Minute
			opts.CommandTimeout = 5 * time.Minute
			opts.MasterSASLUsername = "proxyuser"
			opts.MasterSASLPassword = "proxypass"
			opts.AuthRateLimit = server.AuthRateLimiterConfig{Enabled: false}
			opts.TLSCertFile = "../../testdata/sora.crt"
			opts.TLSKeyFile = "../../testdata/sora.key"

			srv, err := New(ctx, nil, "test.example.com", opts)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			t.Logf("✓ Valid configuration: Client=%s, Backend=%s", mode.clientMode, mode.backendMode)

			srv.Stop()
		})
	}
}
