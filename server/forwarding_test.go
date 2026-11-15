package server

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/migadu/sora/helpers"
)

// TestIsTrustedForwardingWithProxy_BareIP is the regression guard for the XCLIENT
// "451 XCLIENT denied" bug: a backend whose trusted_networks lists a BARE IP (no /mask)
// advertised XCLIENT (because isXCLIENTTrusted uses ParseTrustedNetworks, which normalizes
// "10.10.10.31" -> "10.10.10.31/32") but then DENIED the command, because this trust check
// used raw net.ParseCIDR and silently skipped the maskless entry. The two checks read the
// same list and MUST agree (both now route through helpers.IPInNetworks). This pins the
// bare-IP behavior so the proxy-protocol XCLIENT path keeps working.
func TestIsTrustedForwardingWithProxy_BareIP(t *testing.T) {
	// trusted_networks exactly as a bare IP, the way that triggered the prod bug.
	bareIP := []string{"10.10.10.31"}

	// Sanity: this is the same list isXCLIENTTrusted parses — and it DOES trust the IP.
	// If our forwarding check disagrees, XCLIENT is advertised but the command is denied.
	if nets, err := helpers.ParseTrustedNetworks(bareIP); err != nil || !nets[0].Contains(net.ParseIP("10.10.10.31")) {
		t.Fatalf("precondition: ParseTrustedNetworks must trust the bare IP (err=%v)", err)
	}

	// PROXY-protocol path: the proxy IP is passed explicitly. Must be trusted.
	if !IsTrustedForwardingWithProxy(nil, "10.10.10.31", bareIP) {
		t.Errorf("bare-IP trusted_networks must trust proxy 10.10.10.31 (got denied — this is the 451 bug)")
	}
	// An IP outside the list is still denied.
	if IsTrustedForwardingWithProxy(nil, "10.10.10.99", bareIP) {
		t.Errorf("10.10.10.99 must NOT be trusted when only 10.10.10.31 is listed")
	}
	// CIDR entries must still work (no regression).
	if !IsTrustedForwardingWithProxy(nil, "10.10.10.31", []string{"10.10.10.0/24"}) {
		t.Errorf("CIDR 10.10.10.0/24 must still trust 10.10.10.31")
	}

	// Direct-connection path (no PROXY protocol) must also accept bare IPs.
	conn := &mockAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("10.10.10.31"), Port: 2424}}
	if !IsTrustedForwarding(conn, bareIP) {
		t.Errorf("bare-IP trusted_networks must trust a direct connection from 10.10.10.31")
	}

	// IPv6 bare IP -> /128.
	if !IsTrustedForwardingWithProxy(nil, "2001:db8::1", []string{"2001:db8::1"}) {
		t.Errorf("bare IPv6 trusted_networks must trust 2001:db8::1")
	}
}

// mockAddrConn is a minimal net.Conn that only needs to report a RemoteAddr for the
// IsTrustedForwarding direct-connection path.
type mockAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *mockAddrConn) RemoteAddr() net.Addr { return c.remote }

// A TTL that is not a number is a malformed forwarding parameter. It must be reported,
// not skipped: skipping it leaves the default hop budget in place, so a looping proxy
// that garbles its TTL would start every hop with a fresh one.
func TestParseXCLIENT_MalformedTTLIsAnError(t *testing.T) {
	parsers := map[string]func(string) (*ForwardingParams, error){
		"POP3": ParsePOP3XCLIENT,
		"LMTP": ParseLMTPXCLIENT,
	}
	for proto, parse := range parsers {
		for _, ttl := range []string{"invalid", "", "5x", "1.5", "0x10"} {
			t.Run(proto+"/TTL="+ttl, func(t *testing.T) {
				params, err := parse("ADDR=192.0.2.1 PORT=12345 TTL=" + ttl)
				if err == nil {
					t.Fatalf("no error for TTL=%q; parsed ProxyTTL = %d", ttl, params.ProxyTTL)
				}
			})
		}
		t.Run(proto+"/valid", func(t *testing.T) {
			params, err := parse("ADDR=192.0.2.1 TTL=3")
			if err != nil || params.ProxyTTL != 3 {
				t.Fatalf("TTL=3: ProxyTTL = %v, err = %v", params, err)
			}
			params, err = parse("ADDR=192.0.2.1 TTL=0")
			if err != nil || params.ProxyTTL != 0 {
				t.Fatalf("TTL=0: ProxyTTL = %v, err = %v", params, err)
			}
		})
		t.Run(proto+"/absent", func(t *testing.T) {
			params, err := parse("ADDR=192.0.2.1")
			if err != nil || params.ProxyTTL != 10 {
				t.Fatalf("no TTL: ProxyTTL = %v, err = %v; want the default 10", params, err)
			}
		})
	}
}

// ParseIMAPID reports a malformed x-proxy-ttl too, and leaves ProxyTTL at 0 when the ID
// carries none: IMAP has no default hop budget.
func TestParseIMAPID_MalformedTTLIsAnError(t *testing.T) {
	for _, ttl := range []string{"invalid", "", "5x"} {
		if params, err := ParseIMAPID(map[string]string{"x-originating-ip": "192.0.2.1", "x-proxy-ttl": ttl}); err == nil {
			t.Errorf("no error for x-proxy-ttl %q; parsed %+v", ttl, params)
		}
	}
	params, err := ParseIMAPID(map[string]string{"x-originating-ip": "192.0.2.1", "x-proxy-ttl": "-1"})
	if err != nil || params.ProxyTTL != -1 {
		t.Errorf("x-proxy-ttl -1: params = %+v, err = %v", params, err)
	}
	params, err = ParseIMAPID(map[string]string{"x-originating-ip": "192.0.2.1"})
	if err != nil || params.ProxyTTL != 0 {
		t.Errorf("no x-proxy-ttl: params = %+v, err = %v", params, err)
	}
}

// ForwardingSourceIP is the address IMAP ID forwarding and POP3 XCLIENT are judged by, and
// the one LMTP XCLIENT ADDR needs trusted (docs/SECURITY.md 3.1): the client a PROXY header
// names, else the socket peer. A header that names no client (v2 LOCAL, v1 UNKNOWN or an
// UNSPEC v2 header) falls back to the socket peer, the trusted host that sent it, so a
// proxy that reaches the backend that way can still forward.
func TestForwardingSourceIP(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	socket := &mockAddrConn{remote: peer}
	proxied := func(info *ProxyProtocolInfo) net.Conn {
		return &ProxyProtocolConn{Conn: socket, proxyInfo: info}
	}
	named := &ProxyProtocolInfo{Version: 2, Command: "PROXY", SrcIP: "198.51.100.7", SrcPort: 51000}

	for _, tc := range []struct {
		name string
		conn net.Conn
		want string
	}{
		{"no PROXY header", socket, "192.0.2.10"},
		{"header names a client", proxied(named), "198.51.100.7"},
		{"header names a client, behind TLS", tls.Server(proxied(named), &tls.Config{}), "198.51.100.7"},
		{"v2 LOCAL", proxied(&ProxyProtocolInfo{Version: 2, Command: "LOCAL"}), "192.0.2.10"},
		{"v1 UNKNOWN", proxied(&ProxyProtocolInfo{Version: 1, Command: "UNKNOWN", Protocol: "UNKNOWN"}), "192.0.2.10"},
		{"v2 UNSPEC", proxied(&ProxyProtocolInfo{Version: 2, Command: "UNKNOWN", Protocol: "UNKNOWN"}), "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ForwardingSourceIP(tc.conn); !got.Equal(net.ParseIP(tc.want)) {
				t.Errorf("ForwardingSourceIP = %v, want %s", got, tc.want)
			}
		})
	}

	if got := ForwardingSourceIP(nil); got != nil {
		t.Errorf("ForwardingSourceIP(nil) = %v, want nil (in no network)", got)
	}
}
