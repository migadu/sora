package server

import (
	"context"
	"net"

	"github.com/migadu/sora/helpers"
)

// MasterSASLNetworkGate restricts which source networks may use master
// credentials (master SASL and the master-username form) to impersonate users on
// a backend server. Applied through Session.AdmitMasterLogin.
//
// It MUST be anchored to the real socket peer (net.Conn.RemoteAddr), never to a
// client-asserted address. The PROXY protocol, the IMAP ID command, and XCLIENT can
// all rewrite the session's notion of the "client IP" (e.g. IMAPSession.RemoteIP),
// but none of them can change the underlying TCP peer returned by RemoteAddr — so
// the peer is the only value a directly-connected attacker cannot forge.
//
// An empty gate (no configured networks) is disabled: Allowed always returns true,
// preserving the legacy behavior where master SASL is accepted from any source and
// security rests solely on network isolation + secret secrecy.
type MasterSASLNetworkGate struct {
	nets []*net.IPNet
}

// NewMasterSASLNetworkGate parses the configured CIDRs/IPs into a gate. A parse
// failure is returned as an error so the caller can fail closed at startup rather
// than silently dropping a misconfigured allow-list (which would re-open the gate).
func NewMasterSASLNetworkGate(cidrs []string) (*MasterSASLNetworkGate, error) {
	if len(cidrs) == 0 {
		return &MasterSASLNetworkGate{}, nil
	}
	nets, err := helpers.ParseTrustedNetworks(cidrs)
	if err != nil {
		return nil, err
	}
	return &MasterSASLNetworkGate{nets: nets}, nil
}

// Enabled reports whether any networks are configured (the gate is enforcing).
func (g *MasterSASLNetworkGate) Enabled() bool {
	return g != nil && len(g.nets) > 0
}

// Equal reports whether two gates enforce the same set of networks. Used to detect
// changes on config reload.
func (g *MasterSASLNetworkGate) Equal(other *MasterSASLNetworkGate) bool {
	gn := 0
	if g != nil {
		gn = len(g.nets)
	}
	on := 0
	if other != nil {
		on = len(other.nets)
	}
	if gn != on {
		return false
	}
	for i := 0; i < gn; i++ {
		if g.nets[i].String() != other.nets[i].String() {
			return false
		}
	}
	return true
}

// Allowed reports whether master SASL may be used from the given real socket peer.
// Returns true when the gate is disabled (no networks configured). When enabled,
// only peers whose IP falls within a configured network are allowed.
func (g *MasterSASLNetworkGate) Allowed(realPeer net.Addr) bool {
	if !g.Enabled() {
		return true
	}

	ip := addrIP(realPeer)
	if ip == nil {
		return false
	}
	for _, network := range g.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// AdmitMasterLogin applies gate to a master login whose credential has already been
// verified: master SASL, or the master-username form "user@domain@<master_username>".
// Both impersonate any account with one tenant-wide password, so one list confines
// both, on every protocol. form names the credential in the log ("master SASL",
// "master username").
//
// It reports whether the login may proceed. A refusal is logged and recorded under
// authKey exactly like a wrong master password, and the caller must answer it exactly
// like one too: this point is reachable only with the CORRECT password, so a refusal
// that is worded or charged differently (an uncharged failure diverges from a wrong
// password at the block threshold) confirms a guessed password to a peer that is not
// even allowed to use it.
//
// The gate reads conn's real socket peer, never a forwarded client address.
func (s *Session) AdmitMasterLogin(ctx context.Context, gate *MasterSASLNetworkGate, limiter AuthLimiter, conn net.Conn, proxyInfo *ProxyProtocolInfo, authKey, form string) bool {
	if gate.Allowed(conn.RemoteAddr()) {
		return true
	}
	s.WarnLog(form+" credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", GetAddrString(conn.RemoteAddr()))
	if limiter != nil {
		limiter.RecordAuthAttemptWithProxy(ctx, conn, proxyInfo, authKey, false)
	}
	return false
}

// addrIP extracts the IP from a net.Addr without triggering DNS resolution for the
// common TCP/UDP cases.
func addrIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}
