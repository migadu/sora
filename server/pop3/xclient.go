package pop3

import (
	"bufio"

	"github.com/migadu/sora/server"
)

// handleXCLIENT handles the POP3 XCLIENT command for Dovecot-style parameter forwarding
// This is a custom extension that follows Dovecot's XCLIENT specification
// It needs to be called from the main command loop with writer available
func (s *POP3Session) handleXCLIENT(args string, writer *bufio.Writer) {
	// Check if connection is from trusted proxy
	if !s.isFromTrustedProxy() {
		writer.WriteString("-ERR Connection not from trusted proxy\r\n")
		return
	}

	// Parse XCLIENT parameters
	forwardingParams, err := server.ParsePOP3XCLIENT(args)
	if err != nil {
		writer.WriteString("-ERR Invalid XCLIENT parameters\r\n")
		s.Log("[XCLIENT] Failed to parse parameters: %v", err)
		return
	}

	// Validate parameters
	if err := forwardingParams.ValidateForwarding(); err != nil {
		writer.WriteString("-ERR Invalid forwarding parameters\r\n")
		s.Log("[XCLIENT] Invalid parameters: %v", err)
		return
	}

	// Check TTL to prevent loops
	if !forwardingParams.DecrementTTL() {
		writer.WriteString("-ERR Proxy TTL expired\r\n")
		s.Log("[XCLIENT] TTL expired, possible forwarding loop")
		return
	}

	// Store forwarding parameters in session
	s.ForwardingParams = forwardingParams

	// Update session's RemoteIP if forwarding parameters provide it
	if forwardingParams.OriginatingIP != "" {
		s.RemoteIP = forwardingParams.OriginatingIP
		s.Log("[XCLIENT] Updated client IP from forwarding parameters: %s", forwardingParams.OriginatingIP)
	}

	s.Log("[XCLIENT] Processed forwarding parameters: client=%s:%d session=%s ttl=%d variables=%d",
		forwardingParams.OriginatingIP, forwardingParams.OriginatingPort,
		forwardingParams.SessionID, forwardingParams.ProxyTTL, len(forwardingParams.Variables))

	writer.WriteString("+OK XCLIENT parameters accepted\r\n")
}

// isFromTrustedProxy checks if the connection is from a trusted proxy
func (s *POP3Session) isFromTrustedProxy() bool {
	// Get trusted proxies configuration from server PROXY protocol config
	// This reuses the same trusted network logic as PROXY protocol
	trustedProxies := s.server.getTrustedProxies()

	return server.IsTrustedForwarding(*s.conn, trustedProxies)
}
