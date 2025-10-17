package imap

import (
	"net"
	"strings"

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

		// Store client ID and apply capability filtering
		s.SetClientID(clientID)

		// Log any additional (non-forwarding) fields from Raw data
		if len(clientID.Raw) > 0 {
			s.logAdditionalIDFields(clientID.Raw)
		}

		// Check for Dovecot-style forwarding parameters in client ID
		// Only process forwarding parameters if the connection is from a trusted proxy
		if s.isFromTrustedProxy() && len(clientID.Raw) > 0 {
			// Extract only forwarding parameters (x-* prefixed fields)
			forwardingFields := s.extractForwardingFields(clientID.Raw)
			if len(forwardingFields) > 0 {
				s.processForwardingParameters(forwardingFields)
			}
		}
	} else {
		s.Log("[ID] Client sent empty ID command")
	}

	// Build server response with basic server information
	version := s.server.version
	if version == "" {
		version = "dev"
	}
	serverID := &imap.IDData{
		Name:       "Sora",
		Version:    version,
		Vendor:     "Migadu-Mail GmbH",
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
	// Use the server's limiter trusted networks for ID command forwarding
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
	conn := s.conn.NetConn()
	remoteAddr := conn.RemoteAddr()
	return s.server.limiter.IsTrustedConnection(remoteAddr)
}

// logAdditionalIDFields logs any additional ID fields that aren't forwarding parameters
func (s *IMAPSession) logAdditionalIDFields(rawFields map[string]string) {
	var nonForwardingFields []string
	for key, value := range rawFields {
		// Skip forwarding parameters (x-* prefixed fields)
		if !strings.HasPrefix(key, "x-") {
			nonForwardingFields = append(nonForwardingFields, key+"="+value)
		}
	}

	if len(nonForwardingFields) > 0 {
		s.Log("[ID] Client identified as: %s", strings.Join(nonForwardingFields, ", "))
	}
}

// extractForwardingFields extracts only the x-* prefixed fields for forwarding
func (s *IMAPSession) extractForwardingFields(rawFields map[string]string) map[string]string {
	forwardingFields := make(map[string]string)
	for key, value := range rawFields {
		if strings.HasPrefix(key, "x-") {
			forwardingFields[key] = value
		}
	}
	return forwardingFields
}

// processForwardingParameters extracts and validates forwarding parameters from filtered fields
func (s *IMAPSession) processForwardingParameters(forwardingFields map[string]string) {
	// Parse forwarding parameters from the filtered forwarding fields
	forwardingParams := server.ParseIMAPID(forwardingFields)

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

	// Extract JA4 fingerprint if forwarded from proxy
	// This allows capability filtering to work even when client connects through a proxy
	// Only use ID command fingerprint if we don't already have one from PROXY v2 TLV (higher priority)
	if ja4Fingerprint, ok := forwardingParams.Variables["ja4-fingerprint"]; ok && ja4Fingerprint != "" {
		if s.ja4Fingerprint == "" {
			s.ja4Fingerprint = ja4Fingerprint
			s.Log("[ID] Received JA4 fingerprint from proxy ID command: %s", ja4Fingerprint)
			// Apply capability filters based on the forwarded fingerprint
			s.applyCapabilityFilters()
		} else {
			s.Log("[ID] Ignoring JA4 from ID command (already have %s from PROXY TLV)", s.ja4Fingerprint)
		}
	}

	s.Log("[ID] Processed forwarding parameters: client=%s:%d, proxy=%s, session=%s, ttl=%d, ja4=%s",
		forwardingParams.OriginatingIP, forwardingParams.OriginatingPort, s.ProxyIP,
		forwardingParams.SessionID, forwardingParams.ProxyTTL, s.ja4Fingerprint)
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
