package proxy

import (
	"testing"
)

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		defaultPort int
		want        string
	}{
		// IPv6 Test Cases
		{
			name:        "IPv6 with brackets and port",
			addr:        "[2001:db8::1]:143",
			defaultPort: 993,
			want:        "[2001:db8::1]:143",
		},
		{
			name:        "IPv6 without port",
			addr:        "2001:db8::1",
			defaultPort: 143,
			want:        "[2001:db8::1]:143",
		},
		{
			name:        "Malformed IPv6 with port, no brackets",
			addr:        "2001:db8::1:143",
			defaultPort: 993,
			want:        "[2001:db8::1]:143",
		},
		{
			name:        "Full IPv6 without port",
			addr:        "2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
			defaultPort: 143,
			want:        "[2001:0db8:85a3:08d3:1319:8a2e:0370:7344]:143",
		},
		{
			name:        "Malformed full IPv6 with port, no brackets",
			addr:        "2001:0db8:85a3:08d3:1319:8a2e:0370:7344:143",
			defaultPort: 993,
			want:        "[2001:0db8:85a3:08d3:1319:8a2e:0370:7344]:143",
		},
		{
			name:        "IPv6 loopback without port",
			addr:        "::1",
			defaultPort: 143,
			want:        "[::1]:143",
		},
		{
			name:        "IPv6 loopback with port",
			addr:        "[::1]:143",
			defaultPort: 993,
			want:        "[::1]:143",
		},
		{
			name:        "Malformed IPv6 loopback with port, no brackets",
			addr:        "::1:143",
			defaultPort: 993,
			want:        "[::1]:143",
		},

		// IPv4 Test Cases
		{
			name:        "IPv4 with port",
			addr:        "192.168.1.1:143",
			defaultPort: 993,
			want:        "192.168.1.1:143",
		},
		{
			name:        "IPv4 without port",
			addr:        "192.168.1.1",
			defaultPort: 143,
			want:        "192.168.1.1:143",
		},

		// Hostname Test Cases
		{
			name:        "Hostname with port",
			addr:        "localhost:143",
			defaultPort: 993,
			want:        "localhost:143",
		},
		{
			name:        "Hostname without port",
			addr:        "localhost",
			defaultPort: 143,
			want:        "localhost:143",
		},

		// Edge Cases
		{
			name:        "Empty address",
			addr:        "",
			defaultPort: 143,
			want:        "",
		},
		{
			name:        "Address without port, no default port",
			addr:        "localhost",
			defaultPort: 0,
			want:        "localhost",
		},
		{
			name:        "IPv6 without port, no default port",
			addr:        "2001:db8::1",
			defaultPort: 0,
			want:        "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHostPort(tt.addr, tt.defaultPort); got != tt.want {
				t.Errorf("normalizeHostPort() = %v, want %v", got, tt.want)
			}
		})
	}
}
