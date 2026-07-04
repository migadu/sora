package pop3

import (
	"net"

	"github.com/migadu/sora/server"
)

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
	if err := forwardingParams.ValidateForwarding(); err != nil {
		s.DebugLog("invalid xclient parameters", "error", err)
		return false, "Invalid forwarding parameters"
	}

	// Check TTL to prevent loops
	if !forwardingParams.DecrementTTL() {
		s.DebugLog("xclient ttl expired, possible forwarding loop")
		return false, "Proxy TTL expired"
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

// isFromTrustedProxy checks if the connection is from a trusted network that can send forwarding parameters
func (s *POP3Session) isFromTrustedProxy() bool {
	// Use the server's limiter trusted networks for XCLIENT command forwarding
	// This ensures consistency with connection limiting behavior
	if s.server.limiter == nil {
		return false
	}

	// When PROXY protocol is used, check the proxy's IP (not the real client IP)
	// The ProxyIP contains the actual IP of the proxy server that sent the PROXY header
	if s.ProxyIP != "" {
		// Create a fake net.Addr with the proxy IP for trusted network checking
		proxyAddr := &net.TCPAddr{
			IP: net.ParseIP(s.ProxyIP),
		}
		return s.server.limiter.IsTrustedConnection(proxyAddr)
	}

	// Fall back to checking the direct connection's remote address (no PROXY protocol)
	remoteAddr := s.conn.RemoteAddr()
	return s.server.limiter.IsTrustedConnection(remoteAddr)
}
