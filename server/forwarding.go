package server

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ForwardingParams represents connection parameters that can be forwarded across protocols
// Following Dovecot's parameter forwarding specification
type ForwardingParams struct {
	// Core connection information
	OriginatingIP   string // x-originating-ip / ADDR - Real client IP
	OriginatingPort int    // x-originating-port / PORT - Real client port
	ConnectedIP     string // x-connected-ip - Server IP the client connected to
	ConnectedPort   int    // x-connected-port - Server port the client connected to

	// Session management
	SessionID    string // x-session-id / SESSION - Session identifier
	SessionExtID string // x-session-ext-id - Extended session identifier
	ProxyTTL     int    // x-proxy-ttl / TTL - Hop count for loop prevention

	// Protocol-specific information
	Protocol string // PROTO - Original protocol (SMTP, ESTMP, LMTP)
	HELO     string // HELO - Original HELO/EHLO value
	Login    string // LOGIN - Original LOGIN value
	Timeout  string // TIMEOUT - Original timeout value

	// Custom forwarded variables
	Variables map[string]string // x-forward-<name> / FORWARD - Custom variables
}

// NewForwardingParams creates ForwardingParams from connection and proxy info
func NewForwardingParams(conn net.Conn, proxyInfo *ProxyProtocolInfo) *ForwardingParams {
	params := &ForwardingParams{
		Variables: make(map[string]string),
		ProxyTTL:  10, // Default TTL
	}

	// Extract connection information
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		// Connection came through proxy
		params.OriginatingIP = proxyInfo.SrcIP
		params.OriginatingPort = proxyInfo.SrcPort
		params.ConnectedIP = proxyInfo.DstIP
		params.ConnectedPort = proxyInfo.DstPort
	} else {
		// Direct connection, use helper to extract host/port from any net.Addr
		params.OriginatingIP, params.OriginatingPort = GetHostPortFromAddr(conn.RemoteAddr())
		params.ConnectedIP, params.ConnectedPort = GetHostPortFromAddr(conn.LocalAddr())
	}

	return params
}

// ToIMAPID converts forwarding parameters to IMAP ID fields
// Returns a map suitable for extending IMAP ID responses
func (fp *ForwardingParams) ToIMAPID() map[string]string {
	id := make(map[string]string)

	if fp.OriginatingIP != "" {
		id["x-originating-ip"] = fp.OriginatingIP
	}
	if fp.OriginatingPort > 0 {
		id["x-originating-port"] = strconv.Itoa(fp.OriginatingPort)
	}
	if fp.ConnectedIP != "" {
		id["x-connected-ip"] = fp.ConnectedIP
	}
	if fp.ConnectedPort > 0 {
		id["x-connected-port"] = strconv.Itoa(fp.ConnectedPort)
	}
	if fp.SessionID != "" {
		id["x-session-id"] = fp.SessionID
	}
	if fp.SessionExtID != "" {
		id["x-session-ext-id"] = fp.SessionExtID
	}
	if fp.ProxyTTL > 0 {
		id["x-proxy-ttl"] = strconv.Itoa(fp.ProxyTTL)
	}

	// Add custom variables with x-forward- prefix
	for key, value := range fp.Variables {
		id["x-forward-"+key] = value
	}

	return id
}

// ToPOP3XCLIENT converts forwarding parameters to POP3 XCLIENT command parameters
func (fp *ForwardingParams) ToPOP3XCLIENT() string {
	var parts []string

	if fp.OriginatingIP != "" {
		parts = append(parts, "ADDR="+fp.OriginatingIP)
	}
	if fp.OriginatingPort > 0 {
		parts = append(parts, "PORT="+strconv.Itoa(fp.OriginatingPort))
	}
	if fp.SessionID != "" {
		parts = append(parts, "SESSION="+fp.SessionID)
	}
	if fp.ProxyTTL > 0 {
		parts = append(parts, "TTL="+strconv.Itoa(fp.ProxyTTL))
	}

	// Encode forwarded variables using Dovecot's tab-escape format
	if len(fp.Variables) > 0 {
		forward := fp.encodeForwardVariables()
		parts = append(parts, "FORWARD="+forward)
	}

	return strings.Join(parts, " ")
}

// ToLMTPXCLIENT converts forwarding parameters to LMTP XCLIENT command parameters
func (fp *ForwardingParams) ToLMTPXCLIENT() string {
	var parts []string

	if fp.OriginatingIP != "" {
		// Check if IPv6 and add prefix as per Postfix XCLIENT specification
		if strings.Contains(fp.OriginatingIP, ":") {
			parts = append(parts, "ADDR=IPV6:"+fp.OriginatingIP)
		} else {
			parts = append(parts, "ADDR="+fp.OriginatingIP)
		}
	}
	if fp.OriginatingPort > 0 {
		parts = append(parts, "PORT="+strconv.Itoa(fp.OriginatingPort))
	}
	if fp.ProxyTTL > 0 {
		parts = append(parts, "TTL="+strconv.Itoa(fp.ProxyTTL))
	}
	if fp.HELO != "" {
		parts = append(parts, "HELO="+fp.HELO)
	}
	if fp.Login != "" {
		parts = append(parts, "LOGIN="+fp.Login)
	}
	if fp.Timeout != "" {
		parts = append(parts, "TIMEOUT="+fp.Timeout)
	}
	if fp.Protocol != "" {
		parts = append(parts, "PROTO="+fp.Protocol)
	}

	return strings.Join(parts, " ")
}

// ToLMTPRCPTForward converts forwarding parameters for LMTP RCPT TO XRCPTFORWARD
func (fp *ForwardingParams) ToLMTPRCPTForward() string {
	if len(fp.Variables) == 0 {
		return ""
	}
	return fp.encodeForwardVariables()
}

// encodeForwardVariables encodes variables using Dovecot's tab-escape format and Base64
func (fp *ForwardingParams) encodeForwardVariables() string {
	var pairs []string
	for key, value := range fp.Variables {
		// Apply Dovecot's tab-escape format
		escapedKey := strings.ReplaceAll(key, "\t", "\\t")
		escapedKey = strings.ReplaceAll(escapedKey, "\n", "\\n")
		escapedKey = strings.ReplaceAll(escapedKey, "\r", "\\r")
		escapedKey = strings.ReplaceAll(escapedKey, "\\", "\\\\")

		escapedValue := strings.ReplaceAll(value, "\t", "\\t")
		escapedValue = strings.ReplaceAll(escapedValue, "\n", "\\n")
		escapedValue = strings.ReplaceAll(escapedValue, "\r", "\\r")
		escapedValue = strings.ReplaceAll(escapedValue, "\\", "\\\\")

		pairs = append(pairs, escapedKey+"="+escapedValue)
	}

	// Join with tabs and Base64 encode
	tabSeparated := strings.Join(pairs, "\t")
	return base64.StdEncoding.EncodeToString([]byte(tabSeparated))
}

// ParseIMAPID parses forwarding parameters from IMAP ID command
func ParseIMAPID(idData map[string]string) *ForwardingParams {
	params := &ForwardingParams{
		Variables: make(map[string]string),
	}

	for key, value := range idData {
		switch key {
		case "x-originating-ip":
			params.OriginatingIP = value
		case "x-originating-port":
			if port, err := strconv.Atoi(value); err == nil {
				params.OriginatingPort = port
			}
		case "x-connected-ip":
			params.ConnectedIP = value
		case "x-connected-port":
			if port, err := strconv.Atoi(value); err == nil {
				params.ConnectedPort = port
			}
		case "x-session-id":
			params.SessionID = value
		case "x-session-ext-id":
			params.SessionExtID = value
		case "x-proxy-ttl":
			if ttl, err := strconv.Atoi(value); err == nil {
				params.ProxyTTL = ttl
			}
		default:
			// Handle x-forward- prefixed variables
			if strings.HasPrefix(key, "x-forward-") {
				varName := strings.TrimPrefix(key, "x-forward-")
				params.Variables[varName] = value
			}
		}
	}

	return params
}

// ParsePOP3XCLIENT parses forwarding parameters from POP3 XCLIENT command
func ParsePOP3XCLIENT(xclientLine string) (*ForwardingParams, error) {
	params := &ForwardingParams{
		Variables: make(map[string]string),
		ProxyTTL:  10, // Default TTL
	}

	// Split by spaces to get key=value pairs
	parts := strings.Fields(xclientLine)
	for _, part := range parts {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		key, value := keyValue[0], keyValue[1]
		switch key {
		case "ADDR":
			params.OriginatingIP = value
		case "PORT":
			if port, err := strconv.Atoi(value); err == nil {
				params.OriginatingPort = port
			}
		case "SESSION":
			params.SessionID = value
		case "TTL":
			if ttl, err := strconv.Atoi(value); err == nil {
				params.ProxyTTL = ttl
			}
		case "FORWARD":
			// Decode Base64 and parse tab-separated variables
			if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
				pairs := strings.Split(string(decoded), "\t")
				for _, pair := range pairs {
					if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
						// Unescape Dovecot's tab-escape format
						unescapedKey := strings.ReplaceAll(kv[0], "\\\\", "\\")
						unescapedKey = strings.ReplaceAll(unescapedKey, "\\t", "\t")
						unescapedKey = strings.ReplaceAll(unescapedKey, "\\n", "\n")
						unescapedKey = strings.ReplaceAll(unescapedKey, "\\r", "\r")

						unescapedValue := strings.ReplaceAll(kv[1], "\\\\", "\\")
						unescapedValue = strings.ReplaceAll(unescapedValue, "\\t", "\t")
						unescapedValue = strings.ReplaceAll(unescapedValue, "\\n", "\n")
						unescapedValue = strings.ReplaceAll(unescapedValue, "\\r", "\r")

						params.Variables[unescapedKey] = unescapedValue
					}
				}
			}
		}
	}

	return params, nil
}

// ParseLMTPXCLIENT parses forwarding parameters from LMTP XCLIENT command
func ParseLMTPXCLIENT(xclientLine string) (*ForwardingParams, error) {
	params := &ForwardingParams{
		Variables: make(map[string]string),
		ProxyTTL:  10, // Default TTL
	}

	// Split by spaces to get key=value pairs
	parts := strings.Fields(xclientLine)
	for _, part := range parts {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		key, value := keyValue[0], keyValue[1]
		switch key {
		case "ADDR":
			// Handle IPv6 prefix as per Postfix specification
			if strings.HasPrefix(value, "IPV6:") {
				params.OriginatingIP = strings.TrimPrefix(value, "IPV6:")
			} else {
				params.OriginatingIP = value
			}
		case "PORT":
			if port, err := strconv.Atoi(value); err == nil {
				params.OriginatingPort = port
			}
		case "TTL":
			if ttl, err := strconv.Atoi(value); err == nil {
				params.ProxyTTL = ttl
			}
		case "HELO":
			params.HELO = value
		case "LOGIN":
			params.Login = value
		case "TIMEOUT":
			params.Timeout = value
		case "PROTO":
			params.Protocol = value
		}
	}

	return params, nil
}

// DecrementTTL decrements the proxy TTL and returns false if TTL reaches 0 (loop detected)
func (fp *ForwardingParams) DecrementTTL() bool {
	if fp.ProxyTTL > 0 {
		fp.ProxyTTL--
		return fp.ProxyTTL > 0
	}
	return false
}

// ValidateForwarding checks if forwarding parameters are valid and TTL hasn't expired
func (fp *ForwardingParams) ValidateForwarding() error {
	if fp.ProxyTTL <= 0 {
		return fmt.Errorf("proxy TTL expired, possible forwarding loop")
	}

	// Validate IP addresses if present
	if fp.OriginatingIP != "" {
		if net.ParseIP(fp.OriginatingIP) == nil {
			return fmt.Errorf("invalid originating IP: %s", fp.OriginatingIP)
		}
	}

	if fp.ConnectedIP != "" {
		if net.ParseIP(fp.ConnectedIP) == nil {
			return fmt.Errorf("invalid connected IP: %s", fp.ConnectedIP)
		}
	}

	// Validate ports
	if fp.OriginatingPort < 0 || fp.OriginatingPort > 65535 {
		return fmt.Errorf("invalid originating port: %d", fp.OriginatingPort)
	}

	if fp.ConnectedPort < 0 || fp.ConnectedPort > 65535 {
		return fmt.Errorf("invalid connected port: %d", fp.ConnectedPort)
	}

	return nil
}

// ParseTrustedNetworks parses a slice of CIDR strings into a slice of *net.IPNet
// Automatically adds /32 for IPv4 and /128 for IPv6 addresses without subnet notation
func ParseTrustedNetworks(cidrs []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		// Try parsing as CIDR first
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// If CIDR parsing fails, try parsing as plain IP and add appropriate subnet
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted network '%s': not a valid IP address or CIDR", cidr)
			}

			// Determine if IPv4 or IPv6 and add appropriate subnet
			var cidrWithSubnet string
			if ip.To4() != nil {
				// IPv4 address
				cidrWithSubnet = cidr + "/32"
			} else {
				// IPv6 address
				cidrWithSubnet = cidr + "/128"
			}

			// Parse the corrected CIDR
			_, network, err = net.ParseCIDR(cidrWithSubnet)
			if err != nil {
				return nil, fmt.Errorf("failed to parse corrected CIDR '%s': %w", cidrWithSubnet, err)
			}
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// IsTrustedForwarding checks if the connection is from a trusted proxy
// This function should be used to validate forwarding parameters
func IsTrustedForwarding(conn net.Conn, trustedProxies []string) bool {
	remoteAddr := conn.RemoteAddr()

	var ip net.IP
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	default:
		// Try to parse as string
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	// Check against trusted proxy networks
	for _, cidr := range trustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsTrustedForwardingWithProxy checks if the connection is from a trusted proxy
// When PROXY protocol is used, it checks the proxy IP instead of the client IP
func IsTrustedForwardingWithProxy(conn net.Conn, proxyIP string, trustedProxies []string) bool {
	// When PROXY protocol is used, check the proxy's IP (not the real client IP)
	// The proxyIP contains the actual IP of the proxy server that sent the PROXY header
	if proxyIP != "" {
		ip := net.ParseIP(proxyIP)
		if ip == nil {
			return false
		}

		// Check against trusted proxy networks
		for _, cidr := range trustedProxies {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Fall back to checking the direct connection's remote address (no PROXY protocol)
	return IsTrustedForwarding(conn, trustedProxies)
}
