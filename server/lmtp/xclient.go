package lmtp

import (
	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server"
)

// handleXCLIENTFromRcptOptions processes XCLIENT information that might be embedded
// in RCPT TO options or other LMTP-specific mechanisms
// This is a simplified approach since the go-smtp library doesn't directly
// support custom SMTP commands without significant modification
func (s *LMTPSession) handleXCLIENTFromRcptOptions(opts *smtp.RcptOptions) {
	// In a full implementation, this would process XCLIENT-style parameters
	// that might be passed via RCPT TO options or other mechanisms
	
	// For now, we'll implement this as a placeholder that can be extended
	// when LMTP proxy functionality is actually needed
	
	s.Log("[LMTP] XCLIENT processing placeholder - needs full implementation")
}

// isFromTrustedProxy checks if the LMTP connection is from a trusted proxy
func (s *LMTPSession) isFromTrustedProxy() bool {
	// Get the underlying network connection through the SMTP connection
	netConn := s.conn.Conn()
	
	// Get trusted proxies configuration from server PROXY protocol config
	// This reuses the same trusted network logic as PROXY protocol
	trustedProxies := s.backend.getTrustedProxies()
	
	return server.IsTrustedForwarding(netConn, trustedProxies)
}

// ParseRCPTForward processes XRCPTFORWARD parameters from RCPT TO command
// This is used for per-recipient forwarding parameters
func (s *LMTPSession) ParseRCPTForward(rcptOptions map[string]string) {
	xrcptforward, exists := rcptOptions["XRCPTFORWARD"]
	if !exists {
		return
	}
	
	// Check if connection is from trusted proxy
	if !s.isFromTrustedProxy() {
		s.Log("[RCPT] XRCPTFORWARD not permitted from this host")
		return
	}
	
	// Initialize forwarding parameters if not already present
	if s.ForwardingParams == nil {
		s.ForwardingParams = &server.ForwardingParams{
			Variables: make(map[string]string),
		}
	}
	
	// Parse the Base64-encoded, tab-separated variables
	// This reuses the same parsing logic as POP3 XCLIENT FORWARD parameter
	forwardParams, err := server.ParsePOP3XCLIENT("FORWARD=" + xrcptforward)
	if err != nil {
		s.Log("[RCPT] Failed to parse XRCPTFORWARD: %v", err)
		return
	}
	
	// Merge variables into existing forwarding parameters
	for key, value := range forwardParams.Variables {
		s.ForwardingParams.Variables[key] = value
	}
	
	s.Log("[RCPT] Processed XRCPTFORWARD parameters: %d variables", len(forwardParams.Variables))
}

// Note: Full XCLIENT support for LMTP would require extending the go-smtp library
// to support custom SMTP commands. The current implementation provides the framework
// for handling forwarded parameters but doesn't implement the full XCLIENT command.
// 
// For production use, this could be implemented by:
// 1. Forking go-smtp to add XCLIENT command support
// 2. Using RCPT TO options for parameter forwarding (XRCPTFORWARD)
// 3. Processing parameters through PROXY protocol (already supported)
// 4. Using environment variables or configuration for static forwarding parameters