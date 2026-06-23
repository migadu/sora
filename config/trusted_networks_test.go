package config

import "testing"

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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrustedNetworksHaveBroadPrivateRanges(tc.nets); got != tc.want {
				t.Errorf("TrustedNetworksHaveBroadPrivateRanges(%v) = %v, want %v", tc.nets, got, tc.want)
			}
		})
	}
}
