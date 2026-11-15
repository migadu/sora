package config

import (
	"fmt"
	"net"
	"testing"

	"github.com/migadu/sora/helpers"
)

// TestNewDefaultConfig_TrustedNetworksEmpty pins the fail-closed default: no host is
// trusted to spoof client IPs or skip rate limiting unless explicitly configured. (M2)
func TestNewDefaultConfig_TrustedNetworksEmpty(t *testing.T) {
	cfg := NewDefaultConfig()
	if got := len(cfg.Servers.TrustedNetworks); got != 0 {
		t.Fatalf("default trusted_networks must be empty (fail-closed), got %d entries: %v",
			got, cfg.Servers.TrustedNetworks)
	}
}

func proxyServer(name string, proxyProtocol bool) ServerConfig {
	return ServerConfig{Type: "imap", Name: name, Addr: ":143", ProxyProtocol: proxyProtocol}
}

// TestProxyProtocolListenersMissingTrust verifies the startup fail-closed gate: a listener
// that accepts PROXY protocol with an empty trusted_networks is reported (and rejected). (M2)
func TestProxyProtocolListenersMissingTrust(t *testing.T) {
	t.Run("proxy_protocol + empty trusted_networks => reported", func(t *testing.T) {
		cfg := &Config{}
		cfg.DynamicServers = []ServerConfig{proxyServer("imap-pp", true)}
		got := cfg.ProxyProtocolListenersMissingTrust()
		if len(got) != 1 || got[0] != "imap-pp" {
			t.Fatalf("expected [imap-pp], got %v", got)
		}
	})

	t.Run("proxy_protocol + configured trusted_networks => ok", func(t *testing.T) {
		cfg := &Config{}
		cfg.Servers.TrustedNetworks = []string{"10.20.0.5/32"}
		cfg.DynamicServers = []ServerConfig{proxyServer("imap-pp", true)}
		if got := cfg.ProxyProtocolListenersMissingTrust(); got != nil {
			t.Fatalf("expected nil when trusted_networks is set, got %v", got)
		}
	})

	// The metrics endpoint does not read PROXY headers, so its proxy_protocol is warned
	// about and ignored instead (#272); it must not demand trusted_networks.
	t.Run("proxy_protocol on metrics + empty trusted_networks => ok", func(t *testing.T) {
		cfg := &Config{}
		cfg.DynamicServers = []ServerConfig{{Type: "metrics", Name: "metrics", Addr: ":9090", ProxyProtocol: true}}
		if got := cfg.ProxyProtocolListenersMissingTrust(); got != nil {
			t.Fatalf("expected nil for a listener that does not read PROXY headers, got %v", got)
		}
	})

	t.Run("no proxy_protocol + empty trusted_networks => ok", func(t *testing.T) {
		cfg := &Config{}
		cfg.DynamicServers = []ServerConfig{proxyServer("imap-plain", false)}
		if got := cfg.ProxyProtocolListenersMissingTrust(); got != nil {
			t.Fatalf("expected nil when no listener uses proxy_protocol, got %v", got)
		}
	})
}

// TestTrustedNetworksHaveBroadPrivateRanges checks the insecure-wide detector that drives
// the startup WARN: whole private supernets trip it; narrow CIDRs and loopback do not. (M2)
func TestTrustedNetworksHaveBroadPrivateRanges(t *testing.T) {
	cases := []struct {
		name string
		nets []string
		want bool
	}{
		{"empty", nil, false},
		{"rfc1918 /8", []string{"10.0.0.0/8"}, true},
		{"rfc1918 /12", []string{"172.16.0.0/12"}, true},
		{"rfc1918 /16", []string{"192.168.0.0/16"}, true},
		{"ipv6 ula", []string{"fc00::/7"}, true},
		{"ipv6 link-local", []string{"fe80::/10"}, true},
		{"broader-than supernet", []string{"10.0.0.0/7"}, true},
		{"mixed with one broad", []string{"10.20.0.5/32", "192.168.0.0/16"}, true},
		{"narrow proxy /32", []string{"10.20.0.5/32"}, false},
		{"narrow subnet /24", []string{"10.1.2.0/24"}, false},
		{"loopback only", []string{"127.0.0.0/8", "::1/128"}, false},
		{"bare ip ignored", []string{"10.20.0.5"}, false},
		{"all ipv4", []string{"0.0.0.0/0"}, true},
		// An IPv4-mapped CIDR matches IPv4 clients as the IPv4 network it maps
		// (net.IPNet.Contains, and so every trust check, sees ::ffff:10.0.0.0/104 as
		// 10.0.0.0/8), so it is as broad as that spelling. (#765)
		{"ipv4-mapped rfc1918 /8", []string{"::ffff:10.0.0.0/104"}, true},
		{"ipv4-mapped rfc1918 /12", []string{"::ffff:172.16.0.0/108"}, true},
		{"ipv4-mapped rfc1918 /16", []string{"::ffff:192.168.0.0/112"}, true},
		{"ipv4-mapped all ipv4", []string{"::ffff:0:0/96"}, true},
		{"ipv4-mapped narrow subnet /24", []string{"::ffff:10.1.2.0/120"}, false},
		{"ipv4-mapped narrow proxy /32", []string{"::ffff:10.20.0.5/128"}, false},
		{"mapped prefix below 96 stays IPv6", []string{"::ffff:0:0/95"}, false},
		{"mapped /80 stays IPv6", []string{"::ffff:10.20.0.5/80"}, false},
		{"mapped /48 stays IPv6", []string{"::ffff:10.20.0.5/48"}, false},
		{"mapped /0 covers native IPv6 private ranges", []string{"::ffff:10.20.0.5/0"}, true},
		{"bare mapped host", []string{"::ffff:10.20.0.5"}, false},
		{"leading-zero mapped prefix", []string{"::ffff:10.20.0.5/0104"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrustedNetworksHaveBroadPrivateRanges(tc.nets); got != tc.want {
				t.Errorf("TrustedNetworksHaveBroadPrivateRanges(%v) = %v, want %v", tc.nets, got, tc.want)
			}
		})
	}
}

// The warning must describe the network the trust helpers actually accept. For
// contiguous CIDRs, containing both endpoints of a private supernet is an
// independent check that the entire supernet is covered; it does not depend on
// converting the configured mask or subtracting a mapped-prefix width.
func TestMappedTrustedNetworkBreadthMatchesRuntimeCoverage(t *testing.T) {
	bounds := [][2]string{
		{"10.0.0.0", "10.255.255.255"},
		{"172.16.0.0", "172.31.255.255"},
		{"192.168.0.0", "192.168.255.255"},
		{"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	var entries []string
	for _, address := range []string{
		"::ffff:0:0", "::ffff:10.20.0.5", "::ffff:172.16.1.2",
		"::ffff:192.168.10.20", "::ffff:127.0.0.1", "::ffff:203.0.113.4",
	} {
		entries = append(entries, address) // A bare mapped address is one IPv4 host.
		for prefix := 0; prefix <= 128; prefix++ {
			entries = append(entries, fmt.Sprintf("%s/%d", address, prefix))
		}
	}
	entries = append(entries, "::ffff:10.20.0.5/048", "::ffff:10.20.0.5/096", "::ffff:172.16.1.2/0108", "fc00::/0", "fc00::/7", "fd00::/48", "fe80::/10", "fe80::/64")
	for _, entry := range entries {
		networks, err := helpers.ParseTrustedNetworks([]string{entry})
		if err != nil {
			t.Fatalf("invalid fixture %q: %v", entry, err)
		}
		want := false
		for _, ends := range bounds {
			if networks[0].Contains(net.ParseIP(ends[0])) && networks[0].Contains(net.ParseIP(ends[1])) {
				want = true
			}
		}
		if got := TrustedNetworksHaveBroadPrivateRanges([]string{entry}); got != want {
			t.Errorf("%s: broad warning=%v, runtime covers a whole private supernet=%v", entry, got, want)
		}
	}
}
