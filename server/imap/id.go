package imap

import (
	"github.com/emersion/go-imap/v2"

	"github.com/migadu/sora/server"
)

// ID handles the IMAP ID command (RFC 2971)
// It logs the client-provided ID information and returns server ID information
// Also supports Dovecot-style parameter forwarding via x-* fields
func (s *IMAPSession) ID(clientID *imap.IDData) *imap.IDData {
	if clientID != nil {
		s.Log("[ID] Client identified itself with: Name=%s Version=%s OS=%s OSVersion=%s Vendor=%s",
			clientID.Name, clientID.Version, clientID.OS, clientID.OSVersion, clientID.Vendor)

		// Check for Dovecot-style forwarding parameters in client ID
		if s.isFromTrustedProxy() {
			s.processForwardingParameters(clientID)
		}
	} else {
		s.Log("[ID] Client sent empty ID command")
	}

	// Build server response with basic server information
	serverID := &imap.IDData{
		Name:       "Sora",
		Version:    "1.0.0", // TODO Get right version
		Vendor:     "Migadu",
		SupportURL: "https://migadu.com",
	}

	// Add forwarding parameters to response if we're acting as a proxy
	if s.ForwardingParams != nil {
		s.addForwardingToIMAPID(serverID)
	}

	return serverID
}

// isFromTrustedProxy checks if the connection is from a trusted network that can send forwarding parameters
func (s *IMAPSession) isFromTrustedProxy() bool {
	conn := s.conn.NetConn()

	// Use the server's limiter trusted networks for ID command forwarding
	// This ensures consistency with connection limiting behavior
	if s.server.limiter == nil {
		return false
	}

	// Extract IP from connection
	remoteAddr := conn.RemoteAddr()
	return s.server.limiter.IsTrustedConnection(remoteAddr)
}

// processForwardingParameters extracts and validates forwarding parameters from client ID
func (s *IMAPSession) processForwardingParameters(clientID *imap.IDData) {
	if len(clientID.Raw) == 0 {
		return
	}

	// Parse forwarding parameters from the Raw map
	forwardingParams := server.ParseIMAPID(clientID.Raw)

	// Validate parameters
	if err := forwardingParams.ValidateForwarding(); err != nil {
		s.Log("[ID] Invalid forwarding parameters: %v", err)
		return
	}

	// Decrement TTL to prevent loops. This is for proxy-chaining.
	if !forwardingParams.DecrementTTL() {
		s.Log("[ID] Proxy TTL expired, dropping connection to prevent loop")
		s.Close() // Close the connection to prevent loops
		return
	}

	// Store forwarding parameters in session for potential further proxying
	s.ForwardingParams = forwardingParams

	// Update session's IP addresses
	if forwardingParams.OriginatingIP != "" {
		// If s.ProxyIP is not set, it means we haven't received PROXY protocol.
		// In this case, the current s.RemoteIP is the proxy's IP.
		if s.ProxyIP == "" && s.RemoteIP != "" {
			s.ProxyIP = s.RemoteIP
		}
		// Now, update s.RemoteIP to the real client's IP from the ID command.
		s.RemoteIP = forwardingParams.OriginatingIP
	}

	// The proxy might also send its own source IP. Let's check for that.
	if proxySourceIP, ok := forwardingParams.Variables["proxy-source-ip"]; ok {
		// If PROXY protocol wasn't used, this is our best source for the proxy's IP.
		if s.ProxyIP == "" {
			s.ProxyIP = proxySourceIP
		}
	}

	s.Log("[ID] Processed forwarding parameters: client=%s:%d, proxy=%s, session=%s, ttl=%d",
		forwardingParams.OriginatingIP, forwardingParams.OriginatingPort, s.ProxyIP,
		forwardingParams.SessionID, forwardingParams.ProxyTTL)
}

// addForwardingToIMAPID adds forwarding parameters to IMAP ID response
func (s *IMAPSession) addForwardingToIMAPID(serverID *imap.IDData) {
	if s.ForwardingParams == nil {
		return
	}
	// Get forwarding parameters as map
	forwardingMap := s.ForwardingParams.ToIMAPID()

	// Initialize the Raw map if it's nil
	if serverID.Raw == nil {
		serverID.Raw = make(map[string]string)
	}

	// Add the forwarding parameters to the server's ID response
	for k, v := range forwardingMap {
		serverID.Raw[k] = v
	}

	s.Log("[ID] Added %d forwarding parameters to server ID response for proxy chaining", len(forwardingMap))
}
