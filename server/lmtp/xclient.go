package lmtp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server"
)

// XCLIENT implements the smtp.XCLIENTBackend interface for full XCLIENT support
// This method is called by the go-smtp library when an XCLIENT command is received
func (s *LMTPSession) XCLIENT(session smtp.Session, attrs map[string]string) error {
	s.DebugLog("xclient command received", "attributes_count", len(attrs), "attributes", attrs)

	// Check if connection is from trusted proxy
	if !s.isFromTrustedProxy() {
		s.InfoLog("xclient not permitted from this host")
		return fmt.Errorf("XCLIENT denied")
	}

	// Initialize forwarding parameters if not already present
	if s.ForwardingParams == nil {
		s.ForwardingParams = &server.ForwardingParams{
			Variables: make(map[string]string),
			ProxyTTL:  10, // Default TTL
		}
	}

	// Process standard XCLIENT attributes and map them to ForwardingParams
	for name, value := range attrs {
		upperName := strings.ToUpper(name)

		// Skip [UNAVAILABLE] and [TEMPUNAVAIL] values
		if value == "[UNAVAILABLE]" || value == "[TEMPUNAVAIL]" {
			continue
		}

		switch upperName {
		case "ADDR":
			s.ForwardingParams.OriginatingIP = value
			// If s.ProxyIP is not set, the current s.RemoteIP is the proxy's IP
			if s.ProxyIP == "" && s.RemoteIP != "" {
				s.ProxyIP = s.RemoteIP
			}
			// Update s.RemoteIP to the real client's IP from XCLIENT
			s.RemoteIP = value

		case "PORT":
			if port, err := strconv.Atoi(value); err == nil {
				s.ForwardingParams.OriginatingPort = port
			}

		case "PROTO":
			s.ForwardingParams.Protocol = value

		case "HELO":
			s.ForwardingParams.HELO = value

		case "LOGIN":
			s.ForwardingParams.Login = value

		case "NAME":
			// Store client hostname in variables
			s.ForwardingParams.Variables["client-hostname"] = value

		default:
			// Store unknown attributes in variables with xclient- prefix
			s.ForwardingParams.Variables["xclient-"+strings.ToLower(name)] = value
		}
	}

	s.DebugLog("processed xclient attributes", "client_ip", s.ForwardingParams.OriginatingIP, "client_port", s.ForwardingParams.OriginatingPort, "protocol", s.ForwardingParams.Protocol, "helo", s.ForwardingParams.HELO, "login", s.ForwardingParams.Login)

	return nil
}

// isFromTrustedProxy checks if the LMTP connection is from a trusted proxy
func (s *LMTPSession) isFromTrustedProxy() bool {
	// Get the underlying network connection through the SMTP connection
	netConn := s.conn.Conn()

	// First try to get trusted proxies from PROXY protocol config
	var trustedProxies []string
	if s.backend.proxyReader != nil {
		trustedProxies = server.GetTrustedProxiesForServer(s.backend.proxyReader)
	} else {
		// If PROXY protocol is disabled, use the server's own trusted networks
		// Convert trusted networks back to string format for compatibility
		for _, network := range s.backend.trustedNetworks {
			trustedProxies = append(trustedProxies, network.String())
		}
	}

	// When PROXY protocol is used, check the proxy's IP (not the real client IP)
	return server.IsTrustedForwardingWithProxy(netConn, s.ProxyIP, trustedProxies)
}

// ParseRCPTForward processes XRCPTFORWARD parameters from RCPT TO command
// This is used for per-recipient forwarding parameters
func (s *LMTPSession) ParseRCPTForward(rcptOptions *smtp.RcptOptions) {
	if rcptOptions == nil || rcptOptions.Extensions == nil {
		return
	}

	xrcptforward, exists := rcptOptions.Extensions["XRCPTFORWARD"]
	if !exists {
		return
	}

	// Check if connection is from trusted proxy
	if !s.isFromTrustedProxy() {
		s.InfoLog("xrcptforward not permitted from this host")
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
		s.InfoLog("failed to parse xrcptforward", "error", err)
		return
	}

	// Merge variables into existing forwarding parameters
	for key, value := range forwardParams.Variables {
		s.ForwardingParams.Variables[key] = value
	}

	// Update session proxy information like XCLIENT does
	// Check if we have proxy information in the forwarding parameters
	if proxyIP, exists := forwardParams.Variables["proxy"]; exists && proxyIP != "" {
		// If s.ProxyIP is not set, the current s.RemoteIP is the proxy's IP
		if s.ProxyIP == "" && s.RemoteIP != "" {
			s.ProxyIP = s.RemoteIP
		}
		// Don't update s.RemoteIP for XRCPTFORWARD, unlike XCLIENT
		// XRCPTFORWARD is per-recipient forwarding, not session-level IP forwarding

		s.InfoLog("xrcptforward set proxy information", "proxy", proxyIP)
	}

	s.InfoLog("processed xrcptforward parameters", "variables_count", len(forwardParams.Variables))
}
