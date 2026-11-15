package server

import (
	"net"
	"testing"
)

// max_connections_per_ip counts the client a PROXY header names. A PROXY header
// is only ever read from a trusted peer, so before #539 the trusted peer's
// exemption swallowed every client behind it.
func TestConnectionLimiter_PerIPCountsPROXYClientBehindTrustedPeer(t *testing.T) {
	cl := NewConnectionLimiterWithTrustedNets("TEST", 0, 1, []string{"127.0.0.0/8"})
	lb := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	release, err := cl.AcceptWithRealIP(lb, "192.0.2.10")
	if err != nil {
		t.Fatalf("first connection from 192.0.2.10: %v", err)
	}
	if err := cl.CanAcceptWithRealIP(lb, "192.0.2.10"); err == nil {
		t.Error("CanAcceptWithRealIP: second connection from 192.0.2.10 behind the trusted peer was allowed, want the per-IP limit")
	}
	if r, err := cl.AcceptWithRealIP(lb, "192.0.2.10"); err == nil {
		r()
		t.Error("AcceptWithRealIP: second connection from 192.0.2.10 behind the trusted peer was accepted, want the per-IP limit")
	}
	if got := cl.GetStats().IPConnections; got["192.0.2.10"] != 1 || len(got) != 1 {
		t.Errorf("per-IP counts = %v, want map[192.0.2.10:1]", got)
	}

	other, err := cl.AcceptWithRealIP(lb, "192.0.2.11")
	if err != nil {
		t.Fatalf("another client behind the same peer was refused: %v", err)
	}
	other()

	release()
	again, err := cl.AcceptWithRealIP(lb, "192.0.2.10")
	if err != nil {
		t.Fatalf("192.0.2.10 after its connection closed: %v", err)
	}
	again()
	if got := cl.GetStats(); got.TotalConnections != 0 || len(got.IPConnections) != 0 {
		t.Errorf("after every release: total %d, per-IP %v; want 0 and none", got.TotalConnections, got.IPConnections)
	}
}

// The exemption applies to the address the limit counts: a trusted peer that
// names no client (no PROXY header, or PROXY LOCAL) and a PROXY client that is
// itself in trusted_networks stay unlimited.
func TestConnectionLimiter_PerIPExemptsTrustedCountedAddress(t *testing.T) {
	trusted := []string{"127.0.0.0/8", "10.0.0.0/24"}
	lb := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	untrustedPeer := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1234}

	cases := []struct {
		name     string
		peer     net.Addr
		clientIP string
	}{
		{"trusted peer without PROXY client", lb, ""},
		{"PROXY client in trusted_networks", lb, "10.0.0.7"},
		{"PROXY client in trusted_networks behind a peer outside them", untrustedPeer, "10.0.0.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl := NewConnectionLimiterWithTrustedNets("TEST", 0, 1, trusted)
			for i := 0; i < 3; i++ {
				r, err := cl.AcceptWithRealIP(tc.peer, tc.clientIP)
				if err != nil {
					t.Fatalf("connection %d refused: %v", i+1, err)
				}
				defer r()
			}
		})
	}
}

// One client spelled two ways in PROXY headers (IPv6 case, IPv4-mapped) is one
// address for the limit.
func TestConnectionLimiter_PerIPCanonicalisesPROXYClient(t *testing.T) {
	lb := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	for _, pair := range [][2]string{
		{"2001:db8::1", "2001:DB8:0::1"},
		{"192.0.2.10", "::ffff:192.0.2.10"},
	} {
		cl := NewConnectionLimiterWithTrustedNets("TEST", 0, 1, []string{"127.0.0.0/8"})
		r, err := cl.AcceptWithRealIP(lb, pair[0])
		if err != nil {
			t.Fatalf("%s: %v", pair[0], err)
		}
		if r2, err := cl.AcceptWithRealIP(lb, pair[1]); err == nil {
			r2()
			t.Errorf("%s was counted apart from %s", pair[1], pair[0])
		}
		r()
	}
}
