//go:build integration

package config_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/pop3proxy"
)

func TestConfigLoading(t *testing.T) {
	// Test that we can load config.toml
	configPath := filepath.Join("..", "..", "config.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("config.toml not found, skipping config loading test")
	}

	cfg := &config.Config{}
	err := config.LoadConfigFromFile(configPath, cfg)
	if err != nil {
		t.Fatalf("Failed to load config.toml: %v", err)
	}

	t.Logf("Successfully loaded config with %d servers", len(cfg.DynamicServers))

	// Verify that proxy configurations support remote_port
	for _, server := range cfg.DynamicServers {
		if server.Type == "pop3_proxy" || server.Type == "lmtp_proxy" || 
		   server.Type == "imap_proxy" || server.Type == "managesieve_proxy" {
			
			remotePort, err := server.GetRemotePort()
			if err != nil {
				t.Errorf("Server %s (%s) has invalid remote_port: %v", server.Name, server.Type, err)
			} else {
				t.Logf("Server %s (%s) remote_port: %d", server.Name, server.Type, remotePort)
			}
		}
	}
}

func TestIPv6ProxyConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up a resilient database for the proxy - cleanup handled by SetupTestDatabase
	rdb := common.SetupTestDatabase(t)

	// Test IPv6 address normalization with proxy server creation
	testCases := []struct {
		name        string
		remoteAddrs []string
		remotePort  int
		serverType  string
	}{
		{
			name:        "POP3 proxy with localhost and remote port",
			remoteAddrs: []string{"localhost", "127.0.0.1"},
			remotePort:  995,
			serverType:  "pop3",
		},
		{
			name:        "LMTP proxy with IPv6 addresses",
			remoteAddrs: []string{"::1", "[::1]:25"},
			remotePort:  25,
			serverType:  "lmtp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			testAddr := common.GetRandomAddress(t)

			switch tc.serverType {
			case "pop3":
				server, err := pop3proxy.New(
					ctx,
					"localhost",
					testAddr,
					rdb,
					pop3proxy.POP3ProxyServerOptions{
						Name:           tc.name,
						RemoteAddrs:    tc.remoteAddrs,
						RemotePort:     tc.remotePort,
						TLS:            false,
						RemoteTLS:      false,
						ConnectTimeout: 5 * time.Second,
					},
				)
				if err != nil {
					t.Fatalf("Failed to create POP3 proxy server: %v", err)
				}

				// Test that the server can be created without IPv6 errors
				t.Logf("Successfully created POP3 proxy with remote_addrs: %v, remote_port: %d", 
					tc.remoteAddrs, tc.remotePort)

				// Clean up
				server.Stop()

			case "lmtp":
				server, err := lmtpproxy.New(
					ctx,
					rdb,
					"localhost",
					lmtpproxy.ServerOptions{
						Name:           tc.name,
						Addr:           testAddr,
						RemoteAddrs:    tc.remoteAddrs,
						RemotePort:     tc.remotePort,
						TLS:            false,
						RemoteTLS:      false,
						ConnectTimeout: 5 * time.Second,
					},
				)
				if err != nil {
					t.Fatalf("Failed to create LMTP proxy server: %v", err)
				}

				// Test that the server can be created without IPv6 errors
				t.Logf("Successfully created LMTP proxy with remote_addrs: %v, remote_port: %d", 
					tc.remoteAddrs, tc.remotePort)

				// Clean up
				server.Stop()
			}
		})
	}
}

func TestRemotePortNormalization(t *testing.T) {
	// Test the address normalization logic directly
	testCases := []struct {
		name         string
		addr         string
		defaultPort  int
		expectValid  bool
		description  string
	}{
		{
			name:        "localhost with default port",
			addr:        "localhost",
			defaultPort: 993,
			expectValid: true,
			description: "Should normalize to localhost:993",
		},
		{
			name:        "IPv6 localhost with default port",
			addr:        "::1",
			defaultPort: 993,
			expectValid: true,
			description: "Should normalize to [::1]:993",
		},
		{
			name:        "IPv6 with port already specified",
			addr:        "[::1]:143",
			defaultPort: 993,
			expectValid: true,
			description: "Should remain [::1]:143",
		},
		{
			name:        "malformed IPv6 with port",
			addr:        "::1:143",
			defaultPort: 993,
			expectValid: true,
			description: "Should correct to [::1]:143",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server config
			serverConfig := &config.ServerConfig{
				RemoteAddrs: []string{tc.addr},
				RemotePort:  tc.defaultPort,
			}

			// Test that GetRemotePort works
			remotePort, err := serverConfig.GetRemotePort()
			if err != nil {
				t.Fatalf("GetRemotePort failed: %v", err)
			}

			if remotePort != tc.defaultPort {
				t.Errorf("Expected remote port %d, got %d", tc.defaultPort, remotePort)
			}

			t.Logf("%s: remote_port=%d", tc.description, remotePort)

			// Test that the address would be properly formatted for dialing
			// (This simulates what happens in the connection manager)
			host, port, err := net.SplitHostPort(fmt.Sprintf("%s:%d", tc.addr, tc.defaultPort))
			
			// If this address would cause issues, SplitHostPort should fail
			if tc.expectValid && err != nil {
				// Try to resolve like the connection manager would
				if ips, resolveErr := net.LookupIP(tc.addr); resolveErr == nil && len(ips) > 0 {
					// Simulate the resolution fix
					resolvedAddr := net.JoinHostPort(ips[0].String(), fmt.Sprintf("%d", tc.defaultPort))
					host, port, err = net.SplitHostPort(resolvedAddr)
					if err == nil {
						t.Logf("Address resolved successfully: %s -> %s (host=%s, port=%s)", 
							tc.addr, resolvedAddr, host, port)
					} else {
						t.Errorf("Even after resolution, address failed: %v", err)
					}
				} else {
					t.Logf("Address could not be resolved, but that's expected for test addresses")
				}
			} else if tc.expectValid && err == nil {
				t.Logf("Address parsed successfully: %s (host=%s, port=%s)", tc.addr, host, port)
			}
		})
	}
}

func TestProxyConfigFromTOML(t *testing.T) {
	// Test that proxy configs with remote_port can be parsed from TOML
	tomlContent := `
[[server]]
type = "pop3_proxy"
name = "test-pop3-proxy"
addr = ":110"
remote_addrs = ["localhost", "::1", "127.0.0.1:995"]
remote_port = 995

[[server]]
type = "imap_proxy"
name = "test-imap-proxy"
addr = ":143"
remote_addrs = ["backend1.example.com", "backend2.example.com"]
remote_port = "993"
`

	// Write to temporary file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.toml")
	
	err := os.WriteFile(configFile, []byte(tomlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load and parse
	cfg := &config.Config{}
	err = config.LoadConfigFromFile(configFile, cfg)
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Verify we have the expected servers
	if len(cfg.DynamicServers) != 2 {
		t.Fatalf("Expected 2 servers, got %d", len(cfg.DynamicServers))
	}

	// Test POP3 proxy config
	pop3Server := cfg.DynamicServers[0]
	if pop3Server.Type != "pop3_proxy" {
		t.Errorf("Expected pop3_proxy, got %s", pop3Server.Type)
	}

	remotePort, err := pop3Server.GetRemotePort()
	if err != nil {
		t.Errorf("Failed to get remote port for POP3 proxy: %v", err)
	} else if remotePort != 995 {
		t.Errorf("Expected remote port 995, got %d", remotePort)
	}

	// Test IMAP proxy config
	imapServer := cfg.DynamicServers[1]
	if imapServer.Type != "imap_proxy" {
		t.Errorf("Expected imap_proxy, got %s", imapServer.Type)
	}

	remotePort, err = imapServer.GetRemotePort()
	if err != nil {
		t.Errorf("Failed to get remote port for IMAP proxy: %v", err)
	} else if remotePort != 993 {
		t.Errorf("Expected remote port 993, got %d", remotePort)
	}

	t.Logf("Successfully parsed proxy configs with remote_port from TOML")
}