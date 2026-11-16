package config

import (
	"strings"
	"testing"
)

// TestClusterConfig_IPv6Addr: addr takes an IPv6 address with or without a port,
// bracketed as net.JoinHostPort writes it when a port follows.
func TestClusterConfig_IPv6Addr(t *testing.T) {
	cases := []struct {
		addr     string
		port     int
		wantHost string
		wantPort int
	}{
		{addr: "[2001:db8::40]:7947", wantHost: "2001:db8::40", wantPort: 7947},
		{addr: "[2001:db8::40]:7947", port: 8888, wantHost: "2001:db8::40", wantPort: 7947},
		{addr: "2001:db8::40", port: 8888, wantHost: "2001:db8::40", wantPort: 8888},
		{addr: "2001:db8::40", wantHost: "2001:db8::40", wantPort: 7946},
		{addr: "[2001:db8::40]", wantHost: "2001:db8::40", wantPort: 7946},
		{addr: "::1", wantHost: "::1", wantPort: 7946},
		{addr: "[::1]:7947", wantHost: "::1", wantPort: 7947},
		{addr: "[::1]:0", port: 8888, wantHost: "::1", wantPort: 0},
		{addr: "127.0.0.1", port: 0, wantHost: "127.0.0.1", wantPort: 7946},
	}

	for _, tc := range cases {
		cfg := ClusterConfig{Addr: tc.addr, Port: tc.port}
		if got := cfg.GetBindAddr(); got != tc.wantHost {
			t.Errorf("addr %q: GetBindAddr() = %q, want %q", tc.addr, got, tc.wantHost)
		}
		if got := cfg.GetBindPort(); got != tc.wantPort {
			t.Errorf("addr %q, port %d: GetBindPort() = %d, want %d", tc.addr, tc.port, got, tc.wantPort)
		}
	}
}

// Unparseable explicit ports must not silently select port= or the default port.
func TestClusterConfigRejectsUnparseablePort(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:999999999999999999999999999999", "[::1]:999999999999999999999999999999", "127.0.0.1:-999999999999999999999999999999", "127.0.0.1:not-a-port"} {
		t.Run(addr, func(t *testing.T) {
			cfg := ClusterConfig{Enabled: true, Addr: addr, Port: 7947, SecretKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cluster port") || !strings.Contains(err.Error(), "not a valid port") {
				t.Fatalf("Validate()=%v for addr=%q (GetBindPort=%d)", err, addr, cfg.GetBindPort())
			}
		})
	}
}
