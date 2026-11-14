package lmtpproxy

import (
	"context"
	"net"
	"strings"
	"testing"
)

// A trusted_networks entry that is neither an IP nor a CIDR fails the proxy's
// construction (#337). It used to drop the whole list at debug level, so the proxy
// closed every connection as "not from trusted network".
func TestNewRejectsMalformedTrustedNetworks(t *testing.T) {
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name:           "malformed-trust",
		Addr:           "127.0.0.1:0",
		RemoteAddrs:    []string{"192.0.2.10:24"},
		TrustedProxies: []string{"192.0.2.0/24", "10.0.0.0/33"},
	})
	if err == nil {
		srv.Stop()
		t.Fatal("New accepted trusted_networks with 10.0.0.0/33; want an error naming it")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Errorf("error %q does not name the malformed entry", err)
	}
}

// With trusted_networks empty (the default), lmtp_proxy admits the same peers as the
// LMTP backend: loopback and the RFC 1918 ranges (#337). It used to admit no peer at all
// and close every connection, while the start-up log said LMTP still accepted delivery
// from the default private ranges. A configured list replaces the default, as on the
// backend.
func TestAdmissionDefaultsToPrivateRangesLikeLMTPBackend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		trusted  []string
		admitted []string
		refused  []string
	}{
		{
			name:     "no trusted networks",
			trusted:  nil,
			admitted: []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.5.6", "192.168.1.1"},
			refused:  []string{"192.0.2.25", "2001:db8::25"},
		},
		{
			name:     "configured trusted networks",
			trusted:  []string{"192.0.2.0/24"},
			admitted: []string{"192.0.2.25"},
			refused:  []string{"127.0.0.1", "10.1.2.3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(context.Background(), nil, "test-host", ServerOptions{
				Name:           "admission",
				Addr:           "127.0.0.1:0",
				RemoteAddrs:    []string{"192.0.2.10:24"},
				TrustedProxies: tc.trusted,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Stop()

			for _, ip := range tc.admitted {
				if !srv.isFromTrustedNetwork(net.ParseIP(ip)) {
					t.Errorf("peer %s refused, want it admitted", ip)
				}
			}
			for _, ip := range tc.refused {
				if srv.isFromTrustedNetwork(net.ParseIP(ip)) {
					t.Errorf("peer %s admitted, want it refused", ip)
				}
			}
		})
	}
}
