package config

import "testing"

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
