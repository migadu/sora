package helpers

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},     // loopback
		{"::1", false},           // loopback v6
		{"10.0.0.5", false},      // RFC1918
		{"172.16.4.4", false},    // RFC1918
		{"192.168.1.1", false},   // RFC1918
		{"169.254.1.1", false},   // link-local
		{"fe80::1", false},       // link-local v6
		{"fd00::1", false},       // ULA
		{"100.64.0.1", false},    // CGNAT (RFC6598)
		{"100.127.255.1", false}, // CGNAT upper
		{"224.0.0.1", false},     // multicast (not global unicast)
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", c.ip)
		}
		if got := isPublicIP(ip); got != c.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestBindIsPubliclyReachable(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:143", false}, // loopback bind
		{"[::1]:143", false},     // loopback v6 bind
		{"10.0.0.5:143", false},  // private bind (standard backend)
		{"192.168.1.10:993", false},
		{"8.8.8.8:993", true}, // explicit public bind
		{"[2606:4700::1]:993", true},
		{"mail.example.com:143", false}, // hostname — fail quiet
		{"100.64.0.1:143", false},       // CGNAT
	}
	for _, c := range cases {
		if got := BindIsPubliclyReachable(c.addr); got != c.want {
			t.Errorf("BindIsPubliclyReachable(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
	// Wildcard binds depend on the host's real interfaces, so we don't assert a fixed
	// value — just that classification runs without panicking.
	for _, addr := range []string{":143", "0.0.0.0:143", "[::]:143"} {
		_ = BindIsPubliclyReachable(addr)
	}
}
