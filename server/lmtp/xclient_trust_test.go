package lmtp

import (
	"net"
	"testing"

	"github.com/migadu/sora/server"
)

// mustParseNets parses CIDRs for tests, failing the test on error.
func mustParseNets(t *testing.T, cidrs []string) []*net.IPNet {
	t.Helper()
	nets, err := server.ParseTrustedNetworks(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedNetworks(%v): %v", cidrs, err)
	}
	return nets
}

// TestXClientTrustedProxies_FailsClosedOnEmpty is the M2 regression guard: when
// trusted_networks is empty, the XCLIENT/XRCPTFORWARD source-IP override trust list must
// be empty (trust nobody) — NOT silently widened to RFC1918. This mirrors IMAP/POP3,
// which deny forwarding when their trusted list is empty. Without the fix, the LMTP path
// fell back to GetDefaultTrustedNetworks() (all of RFC1918), letting any private-network
// host spoof the client IP.
func TestXClientTrustedProxies_FailsClosedOnEmpty(t *testing.T) {
	// proxyReader == nil (PROXY protocol disabled) and an empty configured XCLIENT set,
	// exactly as the constructor produces when trusted_networks is explicitly empty.
	s := &LMTPSession{
		backend: &LMTPServerBackend{
			xclientTrustedNets: nil,
		},
	}

	if got := s.xclientTrustedProxies(); len(got) != 0 {
		t.Fatalf("xclientTrustedProxies() = %v, want empty (fail closed)", got)
	}

	// A private-network proxy must be denied the source-IP override. ProxyIP is set so
	// IsTrustedForwardingWithProxy evaluates the proxy IP and never touches the conn.
	for _, ip := range []string{"10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1"} {
		if server.IsTrustedForwardingWithProxy(nil, ip, s.xclientTrustedProxies()) {
			t.Errorf("proxy %s was trusted for XCLIENT override with empty trusted_networks; want denied", ip)
		}
	}
}

// TestXClientTrustedProxies_HonorsConfigured confirms the fix does not regress the normal
// case: an explicitly configured proxy network is still trusted for the source-IP override.
func TestXClientTrustedProxies_HonorsConfigured(t *testing.T) {
	s := &LMTPSession{
		backend: &LMTPServerBackend{
			xclientTrustedNets: mustParseNets(t, []string{"10.0.0.0/8"}),
		},
	}

	if got := s.xclientTrustedProxies(); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("xclientTrustedProxies() = %v, want [10.0.0.0/8]", got)
	}

	if !server.IsTrustedForwardingWithProxy(nil, "10.0.0.1", s.xclientTrustedProxies()) {
		t.Error("proxy 10.0.0.1 should be trusted when 10.0.0.0/8 is configured")
	}
	// An IP outside the configured range is still denied.
	if server.IsTrustedForwardingWithProxy(nil, "192.168.1.1", s.xclientTrustedProxies()) {
		t.Error("proxy 192.168.1.1 should NOT be trusted when only 10.0.0.0/8 is configured")
	}
}

// TestXClient_AdmissionVsForwardingDecoupling documents the M2 decoupling: with
// trusted_networks unset, an RFC1918 peer is still ADMITTED for delivery (LMTP is
// internal-only) but is DENIED the XCLIENT/XRCPTFORWARD source-IP override. The two gates
// must use different defaults — admission falls back to RFC1918, forwarding fails closed.
func TestXClient_AdmissionVsForwardingDecoupling(t *testing.T) {
	// Field values as the constructor produces them for an empty trusted_networks config.
	admissionDefault := []string{
		"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	}
	backend := &LMTPServerBackend{
		trustedNetworks:    mustParseNets(t, admissionDefault), // RFC1918 default kept
		xclientTrustedNets: nil,                                // fails closed
	}
	s := &LMTPSession{backend: backend}

	peer := net.ParseIP("10.20.30.40")

	// Admission: allowed (delivery must keep working with an empty config).
	if !backend.isFromTrustedNetwork(peer) {
		t.Errorf("peer %s should be admitted for delivery under empty config (RFC1918 default)", peer)
	}

	// Forwarding override: denied (cannot spoof the client IP without explicit trust).
	if server.IsTrustedForwardingWithProxy(nil, peer.String(), s.xclientTrustedProxies()) {
		t.Errorf("peer %s must NOT be trusted to override the client IP under empty config", peer)
	}
}
