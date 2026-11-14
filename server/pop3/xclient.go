package pop3

import (
	"net"

	"github.com/migadu/sora/server"
)

const xclientTTLExpired = "Proxy TTL expired"

// handleXCLIENT handles the POP3 XCLIENT command for Dovecot-style parameter
// forwarding. This is a custom extension that follows Dovecot's XCLIENT
// specification. It returns whether the parameters were accepted together with
// the response message to send; the caller writes the +OK/-ERR line and marks
// XCLIENT as applied (at most once per session) on success.
func (s *POP3Session) handleXCLIENT(args string) (bool, string) {
	// Check if connection is from trusted proxy
	if !s.isFromTrustedProxy() {
		return false, "Connection not from trusted proxy"
	}

	// Parse XCLIENT parameters
	forwardingParams, err := server.ParsePOP3XCLIENT(args)
	if err != nil {
		s.DebugLog("failed to parse xclient parameters", "error", err)
		return false, "Invalid XCLIENT parameters"
	}

	// Validate parameters
	if forwardingParams.ProxyTTL <= 0 {
		return false, xclientTTLExpired
	}
	if err := forwardingParams.ValidateForwarding(); err != nil {
		s.DebugLog("invalid xclient parameters", "error", err)
		return false, "Invalid forwarding parameters"
	}

	// Check TTL to prevent loops
	if !forwardingParams.DecrementTTL() {
		s.DebugLog("xclient ttl expired, possible forwarding loop")
		return false, xclientTTLExpired
	}

	if forwardingParams.OriginatingIP != "" && !s.mayReplaceClientAddr() {
		s.DebugLog("xclient client address ignored: the PROXY header's source is not trusted", "client_ip", forwardingParams.OriginatingIP)
		forwardingParams.OriginatingIP = ""
		forwardingParams.OriginatingPort = 0
	}

	// Store forwarding parameters in session
	s.ForwardingParams = forwardingParams

	// Update session's RemoteIP if forwarding parameters provide it
	if forwardingParams.OriginatingIP != "" {
		s.RemoteIP = forwardingParams.OriginatingIP
		s.DebugLog("updated client ip from xclient forwarding parameters", "client_ip", forwardingParams.OriginatingIP)
	}

	// The proxy might also send its own source IP. Let's check for that.
	if proxySourceIP, ok := forwardingParams.Variables["proxy-source-ip"]; ok {
		// If PROXY protocol wasn't used, this is our best source for the proxy's IP.
		if s.ProxyIP == "" {
			s.ProxyIP = proxySourceIP
		}
	}

	s.DebugLog("processed xclient forwarding parameters", "client_ip", forwardingParams.OriginatingIP, "client_port", forwardingParams.OriginatingPort, "session_id", forwardingParams.SessionID, "ttl", forwardingParams.ProxyTTL, "variables_count", len(forwardingParams.Variables))

	return true, "XCLIENT parameters accepted"
}

// isFromTrustedProxy reports whether this connection may send XCLIENT: its socket peer or,
// with a PROXY header, the header's source is in trusted_networks (the limiter's list,
// consistent with connection limiting). A trusted peer may relay a client's own XCLIENT,
// so only mayReplaceClientAddr decides whether XCLIENT ADDR is applied.
func (s *POP3Session) isFromTrustedProxy() bool {
	if s.server.limiter == nil {
		return false
	}
	return s.server.limiter.IsTrustedConnection(s.conn.RemoteAddr()) || s.mayReplaceClientAddr()
}

// mayReplaceClientAddr reports whether XCLIENT ADDR may replace the client address the
// connection established, as for LMTP XCLIENT (server/lmtp/xclient.go): only when the
// source of the PROXY header, else the socket peer, is in trusted_networks (see
// server.ForwardingSourceIP). A pop3_proxy may send a PROXY header and XCLIENT on one
// connection, so XCLIENT from a trusted peer is still answered +OK: refusing it would be
// a warning on that proxy at every login. Behind a layer-4 load balancer the XCLIENT is
// the client's own, and its address stays the one the header gave.
func (s *POP3Session) mayReplaceClientAddr() bool {
	if s.server.limiter == nil {
		return false
	}
	return s.server.limiter.IsTrustedConnection(&net.TCPAddr{IP: server.ForwardingSourceIP(s.conn)})
}
