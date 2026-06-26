package server

import (
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
