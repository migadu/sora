package proxy

import (
	"net"
	"testing"
	"time"
)

func TestNormalizeHostPortIPv6Spellings(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		defaultPort int
		want        string
	}{
		{
			name:        "bracketed port-less IPv6 with default port",
			addr:        "[2001:db8::21]",
			defaultPort: 143,
			want:        "[2001:db8::21]:143",
		},
		{
			name:        "bracketed non-canonical port-less IPv6 with default port",
			addr:        "[2001:0db8::0021]",
			defaultPort: 143,
			want:        "[2001:db8::21]:143",
		},
		{
			name:        "bracketed port-less IPv6 without default port",
			addr:        "[2001:0db8::21]",
			defaultPort: 0,
			want:        "2001:db8::21",
		},
		{
			name:        "bare non-canonical port-less IPv6 with default port",
			addr:        "2001:0db8::21",
			defaultPort: 143,
			want:        "[2001:db8::21]:143",
		},
		{
			name:        "bare non-canonical port-less IPv6 without default port",
			addr:        "2001:0db8::21",
			defaultPort: 0,
			want:        "2001:db8::21",
		},
		{
			name:        "unbracketed IPv6 with port canonicalizes host and port",
			addr:        "2001:0db8:0:0:0:0:0:21:0143",
			defaultPort: 993,
			want:        "[2001:db8::21]:143",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHostPort(tt.addr, tt.defaultPort); got != tt.want {
				t.Errorf("normalizeHostPort(%q, %d) = %q, want %q", tt.addr, tt.defaultPort, got, tt.want)
			}
		})
	}
}

func TestPoolAndRemoteLookupIPv6SpellingsMatch(t *testing.T) {
	// config.ValidatePools accepts bracketed port-less IPv6 "[2001:db8::21]" when
	// remote_port is set on the proxy server.
	cm, err := NewConnectionManagerWithPools([]PoolSpec{
		{
			Name:     "sora1",
			Backends: []string{"[2001:db8::21]"},
			Default:  true,
		},
	}, 143, time.Second, nil, "imap-proxy-test", true)
	if err != nil {
		t.Fatalf("NewConnectionManagerWithPools: %v", err)
	}
	cm.SetRestrictRemoteLookupToPool(true)

	backend := cm.GetBackendByConsistentHashInPool("sora1", "alice@example.com")
	if backend != "[2001:db8::21]:143" {
		t.Fatalf("routed backend = %q, want [2001:db8::21]:143", backend)
	}
	if _, _, err := net.SplitHostPort(backend); err != nil {
		t.Fatalf("routed backend %q is not a dialable host:port: %v", backend, err)
	}

	// Equivalent IPv6 spellings from remote_lookup (before and after ResolveAddresses)
	// must match the pool member under restrict_to_pool and BindBackendRoute.
	for _, lookupAnswer := range []string{
		"[2001:db8::21]",
		"2001:0db8::21",
		"[2001:0db8::21]:143",
		"[2001:db8::21]:143",
	} {
		normalized := NormalizeBackendAddr(lookupAnswer, 143)
		if normalized != "[2001:db8::21]:143" {
			t.Errorf("NormalizeBackendAddr(%q, 143) = %q, want [2001:db8::21]:143", lookupAnswer, normalized)
		}
		if !cm.AllowRemoteLookupBackend(normalized) {
			t.Errorf("AllowRemoteLookupBackend(%q) = false, want true", normalized)
		}
		if gotPool := cm.PoolOfBackend(normalized); gotPool != "sora1" {
			t.Errorf("PoolOfBackend(%q) = %q, want sora1", normalized, gotPool)
		}
		if _, err := cm.BindBackendRoute("sora1", normalized); err != nil {
			t.Errorf("BindBackendRoute(sora1, %q) failed: %v", normalized, err)
		}
	}

	// Port-less manager (e.g. user_api_proxy with remote_port = 0): bracketed IPv6
	// must normalize to bare canonical IPv6 and strip brackets in BindBackendRoute's
	// TLS ServerName/VerifyHostname candidate list.
	portlessCM, err := NewConnectionManagerFromOptions(ManagerOptions{
		RemoteAddrs:        []string{"[2001:0db8::21]"},
		RemotePort:         0,
		ConnectTimeout:     time.Second,
		ServerName:         "userapi-proxy-test",
		DisableHealthCheck: true,
	})
	if err != nil {
		t.Fatalf("NewConnectionManagerFromOptions: %v", err)
	}
	if err := portlessCM.ResolveAddresses(); err != nil {
		t.Fatalf("ResolveAddresses: %v", err)
	}
	if got := portlessCM.GetBackendByConsistentHash("alice@example.com"); got != "2001:db8::21" {
		t.Fatalf("port-less backend = %q, want 2001:db8::21", got)
	}
	route, err := portlessCM.BindBackendRoute("", "[2001:db8::21]")
	if err != nil {
		t.Fatalf("BindBackendRoute port-less bracketed IPv6: %v", err)
	}
	tlsCfg := route.TLSConfig(true)
	if tlsCfg.ServerName != "2001:db8::21" {
		t.Errorf("TLSConfig.ServerName = %q, want 2001:db8::21 (unbracketed)", tlsCfg.ServerName)
	}
}
