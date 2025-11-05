package server

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/migadu/sora/logger"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/migadu/sora/config"
)

// ErrNoProxyHeader is returned by ReadProxyHeader in optional mode when no PROXY header is found.
var ErrNoProxyHeader = errors.New("no PROXY protocol header found")

// ProxyProtocolConfig is an alias for config.ProxyProtocolConfig for compatibility
type ProxyProtocolConfig = config.ProxyProtocolConfig

// ProxyProtocolInfo contains information extracted from PROXY protocol header
type ProxyProtocolInfo struct {
	Version        int             // 1 or 2
	Command        string          // PROXY or TCP4/TCP6
	SrcIP          string          // Real client IP
	DstIP          string          // Destination IP
	SrcPort        int             // Real client port
	DstPort        int             // Destination port
	Protocol       string          // TCP4, TCP6, UDP4, UDP6
	TLVs           map[byte][]byte // PROXY v2 TLV extensions (type -> value)
	JA4Fingerprint string          // JA4 TLS fingerprint (extracted from TLV 0xE0)
	ProxySessionID string          // Proxy session ID (extracted from TLV 0xE1) - for end-to-end tracing
}

const (
	// Custom TLV types (0xE0-0xFF range is for private use per PROXY v2 spec)
	TLVTypeJA4Fingerprint byte = 0xE0 // JA4 TLS fingerprint
	TLVTypeProxySessionID byte = 0xE1 // Proxy session ID for end-to-end tracing
)

// ProxyProtocolReader handles PROXY protocol parsing
type ProxyProtocolReader struct {
	config      ProxyProtocolConfig
	trustedNets []*net.IPNet
	timeout     time.Duration
}

// NewProxyProtocolReader creates a new PROXY protocol reader
func NewProxyProtocolReader(protocol string, config ProxyProtocolConfig) (*ProxyProtocolReader, error) {
	reader := &ProxyProtocolReader{
		config:  config,
		timeout: 5 * time.Second, // default timeout
	}

	// Normalize mode
	if reader.config.Mode != "optional" {
		reader.config.Mode = "required" // Default to "required"
	}

	logger.Debug("PROXY protocol: Initializing reader", "protocol", protocol, "enabled", config.Enabled, "mode", reader.config.Mode, "trusted_proxies", config.TrustedProxies, "timeout", reader.timeout)

	// Parse timeout
	if config.Timeout != "" {
		var err error
		reader.timeout, err = time.ParseDuration(config.Timeout)
		if err != nil {
			// Log the error and use default timeout to prevent server crash
			logger.Debug("PROXY protocol: WARNING - invalid timeout, using default 5s", "protocol", protocol, "timeout", config.Timeout, "error", err)
			reader.timeout = 5 * time.Second
		}
	}

	// Parse trusted proxy CIDR blocks
	trustedNets, err := ParseTrustedNetworks(config.TrustedProxies)
	if err != nil {
		// Log the error and use empty trusted networks to prevent server crash
		logger.Debug("PROXY protocol: WARNING - failed to parse trusted networks, PROXY will be disabled", "protocol", protocol, "error", err)
		trustedNets = []*net.IPNet{}
	}
	reader.trustedNets = trustedNets

	return reader, nil
}

// IsOptionalMode returns true if the PROXY protocol is configured in "optional" mode.
func (r *ProxyProtocolReader) IsOptionalMode() bool {
	return r.config.Mode == "optional"
}

// GetTrustedProxies returns the list of trusted proxy CIDR blocks
func (r *ProxyProtocolReader) GetTrustedProxies() []string {
	if r == nil {
		return []string{}
	}
	return r.config.TrustedProxies
}

// GetTrustedProxiesForServer returns trusted proxy networks for a server with fallback defaults
// This is a shared utility function for all server types to avoid code duplication
func GetTrustedProxiesForServer(proxyReader *ProxyProtocolReader) []string {
	if proxyReader != nil {
		// Get trusted proxies from PROXY protocol configuration
		trustedProxies := proxyReader.GetTrustedProxies()
		if len(trustedProxies) > 0 {
			return trustedProxies
		}
	}

	return GetDefaultTrustedNetworks()
}

// GetTrustedProxiesWithFallback returns trusted proxy networks with explicit networks and fallback defaults
// This is for servers that have their own trustedNetworks configuration (like POP3)
func GetTrustedProxiesWithFallback(trustedNetworks []string) []string {
	if len(trustedNetworks) > 0 {
		return trustedNetworks
	}

	return GetDefaultTrustedNetworks()
}

// GetDefaultTrustedNetworks returns the default trusted proxy networks
// This centralizes the default network definitions to avoid duplication
func GetDefaultTrustedNetworks() []string {
	// Return default trusted proxy networks (RFC1918 private networks + localhost + IPv6 defaults)
	// These are safe defaults when no specific configuration is provided
	return []string{
		"127.0.0.0/8",    // IPv4 localhost
		"::1/128",        // IPv6 localhost
		"10.0.0.0/8",     // RFC1918 private networks
		"172.16.0.0/12",  // RFC1918 private networks
		"192.168.0.0/16", // RFC1918 private networks
		"fc00::/7",       // IPv6 unique local addresses (RFC4193)
		"fe80::/10",      // IPv6 link-local addresses
	}
}

// ReadProxyHeader reads and parses PROXY protocol header from connection
// Returns the real client info and a potentially wrapped connection
func (r *ProxyProtocolReader) ReadProxyHeader(conn net.Conn) (*ProxyProtocolInfo, net.Conn, error) {
	if !r.config.Enabled {
		return nil, conn, nil
	}

	if !r.isTrustedConnection(conn) {
		// If PROXY protocol is enabled, we MUST only accept connections from trusted proxies.
		// This is a critical security boundary.
		remoteAddrStr := GetAddrString(conn.RemoteAddr())
		logger.Debug("PROXY protocol: REJECTING untrusted connection", "remote", remoteAddrStr)
		return nil, conn, fmt.Errorf("connection from untrusted source %s", remoteAddrStr)
	}
	logger.Debug("PROXY protocol: Processing connection from trusted proxy", "remote", GetAddrString(conn.RemoteAddr()))

	// Set read deadline for PROXY header
	if err := conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return nil, conn, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Create buffered reader
	reader := bufio.NewReader(conn)

	// Peek at first few bytes to detect PROXY protocol
	peek, err := reader.Peek(16) // Peek more bytes to detect PROXY v2 signature
	if err != nil {
		// If peeking fails (e.g., connection closed immediately), it's not a "no header" case.
		// It's a connection error.
		conn.SetReadDeadline(time.Time{})
		// In optional mode, a quick EOF before the header can be treated as "no header".
		if r.IsOptionalMode() && errors.Is(err, io.EOF) {
			return nil, conn, ErrNoProxyHeader
		}
		// Otherwise, it's a genuine connection error.
		return nil, conn, fmt.Errorf("failed to peek connection for PROXY header: %w", err)
	}

	// Check for PROXY v1 signature
	if len(peek) >= 5 && string(peek[:5]) == "PROXY" {
		logger.Debug("PROXY protocol: Detected v1", "remote", GetAddrString(conn.RemoteAddr()))
		info, err := r.parseProxyV1(reader)
		if err != nil {
			return nil, conn, fmt.Errorf("failed to parse PROXY v1 header: %w", err)
		}

		logger.Debug("PROXY protocol: Parsed v1", "client_ip", info.SrcIP, "client_port", info.SrcPort, "server_ip", info.DstIP, "server_port", info.DstPort)

		// Clear read deadline
		conn.SetReadDeadline(time.Time{})

		// Return wrapped connection with buffered reader
		wrappedConn := &proxyProtocolConn{
			Conn:   conn,
			reader: reader,
		}

		return info, wrappedConn, nil
	}

	// Check for PROXY v2 signature (binary)
	if len(peek) >= 12 {
		// PROXY v2 signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
		v2Sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
		if len(peek) >= len(v2Sig) {
			match := true
			for i, b := range v2Sig {
				if peek[i] != b {
					match = false
					break
				}
			}
			if match {
				logger.Debug("PROXY protocol: Detected v2", "remote", GetAddrString(conn.RemoteAddr()))
				info, err := r.parseProxyV2(reader)
				if err != nil {
					return nil, conn, fmt.Errorf("failed to parse PROXY v2 header: %w", err)
				}

				if info.SrcIP != "" {
					logger.Debug("PROXY protocol: Parsed v2", "client_ip", info.SrcIP, "client_port", info.SrcPort, "server_ip", info.DstIP, "server_port", info.DstPort)
				} else {
					logger.Debug("PROXY protocol: Parsed v2 command", "command", info.Command)
				}

				// Clear read deadline
				conn.SetReadDeadline(time.Time{})

				// Return wrapped connection
				wrappedConn := &proxyProtocolConn{
					Conn:   conn,
					reader: reader,
				}

				return info, wrappedConn, nil
			}
		}
	}

	// No PROXY protocol detected, clear deadline and return original connection
	conn.SetReadDeadline(time.Time{})

	// The connection now has buffered data, so we must return a wrapped connection
	// that uses the buffer first.
	wrappedConn := &proxyProtocolConn{
		Conn:   conn,
		reader: reader,
	}

	// Check the mode to decide what to return
	if r.IsOptionalMode() {
		// In optional mode, not finding a header is not a fatal error.
		return nil, wrappedConn, ErrNoProxyHeader
	}

	return nil, wrappedConn, fmt.Errorf("PROXY protocol header missing")
}

// parseProxyV1 parses PROXY protocol version 1 header
func (r *ProxyProtocolReader) parseProxyV1(reader *bufio.Reader) (*ProxyProtocolInfo, error) {
	// Read the PROXY line (ends with \r\n)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read PROXY line: %w", err)
	}

	// Remove \r\n
	line = strings.TrimRight(line, "\r\n")

	// Parse: "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535"
	parts := strings.Split(line, " ")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid PROXY v1 format: expected 6 parts, got %d", len(parts))
	}

	if parts[0] != "PROXY" {
		return nil, fmt.Errorf("invalid PROXY v1 header: expected PROXY, got %s", parts[0])
	}

	protocol := parts[1] // TCP4, TCP6, UNKNOWN
	srcIP := parts[2]
	dstIP := parts[3]
	srcPortStr := parts[4]
	dstPortStr := parts[5]

	// Handle UNKNOWN connections
	if protocol == "UNKNOWN" {
		return &ProxyProtocolInfo{
			Version:  1,
			Command:  "UNKNOWN",
			Protocol: protocol,
		}, nil
	}

	// Parse ports
	srcPort, err := strconv.Atoi(srcPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid source port: %w", err)
	}

	dstPort, err := strconv.Atoi(dstPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid destination port: %w", err)
	}

	return &ProxyProtocolInfo{
		Version:  1,
		Command:  "PROXY",
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}, nil
}

// parseProxyV2 parses PROXY protocol version 2 header (binary format)
func (r *ProxyProtocolReader) parseProxyV2(reader *bufio.Reader) (*ProxyProtocolInfo, error) {
	// Read the 16-byte header
	header := make([]byte, 16)
	_, err := reader.Read(header)
	if err != nil {
		return nil, fmt.Errorf("failed to read PROXY v2 header: %w", err)
	}

	// Verify signature (already checked by caller, but double-check)
	v2Sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	for i, b := range v2Sig {
		if header[i] != b {
			return nil, fmt.Errorf("invalid PROXY v2 signature")
		}
	}

	// Parse version and command (byte 12)
	versionCmd := header[12]
	version := (versionCmd & 0xF0) >> 4
	command := versionCmd & 0x0F

	if version != 2 {
		return nil, fmt.Errorf("invalid PROXY version: %d", version)
	}

	// Parse address family and protocol (byte 13)
	famAndProto := header[13]
	addressFamily := (famAndProto & 0xF0) >> 4
	protocol := famAndProto & 0x0F

	// Parse length (bytes 14-15, big endian)
	length := (int(header[14]) << 8) | int(header[15])

	// Handle LOCAL command (no address info)
	if command == 0x0 {
		// LOCAL: connection established without PROXY protocol
		// Skip the remaining bytes
		if length > 0 {
			skipData := make([]byte, length)
			_, err := reader.Read(skipData)
			if err != nil {
				return nil, fmt.Errorf("failed to skip LOCAL command data: %w", err)
			}
		}
		return &ProxyProtocolInfo{
			Version: 2,
			Command: "LOCAL",
		}, nil
	}

	// Handle PROXY command (0x1)
	if command != 0x1 {
		return nil, fmt.Errorf("unsupported PROXY v2 command: %d", command)
	}

	// Read address information based on family
	var srcIP, dstIP string
	var srcPort, dstPort int
	var protocolStr string

	switch addressFamily {
	case 0x1: // AF_INET (IPv4)
		if length < 12 {
			return nil, fmt.Errorf("insufficient data for IPv4 addresses")
		}
		addrData := make([]byte, 12)
		_, err := reader.Read(addrData)
		if err != nil {
			return nil, fmt.Errorf("failed to read IPv4 address data: %w", err)
		}

		// Parse IPv4 addresses and ports
		srcIP = fmt.Sprintf("%d.%d.%d.%d", addrData[0], addrData[1], addrData[2], addrData[3])
		dstIP = fmt.Sprintf("%d.%d.%d.%d", addrData[4], addrData[5], addrData[6], addrData[7])
		srcPort = (int(addrData[8]) << 8) | int(addrData[9])
		dstPort = (int(addrData[10]) << 8) | int(addrData[11])

		switch protocol {
		case 0x1:
			protocolStr = "TCP4"
		case 0x2:
			protocolStr = "UDP4"
		}

		// Parse TLVs from remaining data
		remaining := length - 12
		tlvs, err := parseTLVs(reader, remaining)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TLVs: %w", err)
		}
		return &ProxyProtocolInfo{
			Version:        2,
			Command:        "PROXY",
			SrcIP:          srcIP,
			DstIP:          dstIP,
			SrcPort:        srcPort,
			DstPort:        dstPort,
			Protocol:       protocolStr,
			TLVs:           tlvs,
			JA4Fingerprint: extractJA4FromTLVs(tlvs),
			ProxySessionID: extractProxySessionIDFromTLVs(tlvs),
		}, nil

	case 0x2: // AF_INET6 (IPv6)
		if length < 36 {
			return nil, fmt.Errorf("insufficient data for IPv6 addresses")
		}
		addrData := make([]byte, 36)
		_, err := reader.Read(addrData)
		if err != nil {
			return nil, fmt.Errorf("failed to read IPv6 address data: %w", err)
		}

		// Parse IPv6 addresses
		srcIPBytes := addrData[0:16]
		dstIPBytes := addrData[16:32]
		srcIP = net.IP(srcIPBytes).String()
		dstIP = net.IP(dstIPBytes).String()
		srcPort = (int(addrData[32]) << 8) | int(addrData[33])
		dstPort = (int(addrData[34]) << 8) | int(addrData[35])

		switch protocol {
		case 0x1:
			protocolStr = "TCP6"
		case 0x2:
			protocolStr = "UDP6"
		}

		// Parse TLVs from remaining data
		remaining := length - 36
		tlvs, err := parseTLVs(reader, remaining)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TLVs: %w", err)
		}
		return &ProxyProtocolInfo{
			Version:        2,
			Command:        "PROXY",
			SrcIP:          srcIP,
			DstIP:          dstIP,
			SrcPort:        srcPort,
			DstPort:        dstPort,
			Protocol:       protocolStr,
			TLVs:           tlvs,
			JA4Fingerprint: extractJA4FromTLVs(tlvs),
			ProxySessionID: extractProxySessionIDFromTLVs(tlvs),
		}, nil

	case 0x0: // AF_UNSPEC (UNKNOWN)
		// Skip the data
		if length > 0 {
			skipData := make([]byte, length)
			_, err := reader.Read(skipData)
			if err != nil {
				return nil, fmt.Errorf("failed to skip UNKNOWN address data: %w", err)
			}
		}
		return &ProxyProtocolInfo{
			Version:  2,
			Command:  "UNKNOWN",
			Protocol: "UNKNOWN",
		}, nil

	default:
		return nil, fmt.Errorf("unsupported address family: %d", addressFamily)
	}
}

// parseTLVs parses PROXY v2 TLV (Type-Length-Value) extensions
func parseTLVs(reader *bufio.Reader, dataLen int) (map[byte][]byte, error) {
	tlvs := make(map[byte][]byte)

	if dataLen <= 0 {
		return tlvs, nil
	}

	tlvData := make([]byte, dataLen)
	n, err := reader.Read(tlvData)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLV data: %w", err)
	}
	if n != dataLen {
		return nil, fmt.Errorf("incomplete TLV data: expected %d bytes, got %d", dataLen, n)
	}

	// Parse TLVs
	offset := 0
	for offset < dataLen {
		if offset+3 > dataLen {
			// Not enough data for TLV header (type + 2-byte length)
			break
		}

		tlvType := tlvData[offset]
		tlvLen := (int(tlvData[offset+1]) << 8) | int(tlvData[offset+2])
		offset += 3

		if offset+tlvLen > dataLen {
			return nil, fmt.Errorf("TLV length exceeds available data: type=0x%02x, len=%d, available=%d", tlvType, tlvLen, dataLen-offset)
		}

		tlvValue := make([]byte, tlvLen)
		copy(tlvValue, tlvData[offset:offset+tlvLen])
		tlvs[tlvType] = tlvValue
		offset += tlvLen
	}

	return tlvs, nil
}

// extractJA4FromTLVs extracts the JA4 fingerprint from TLVs
func extractJA4FromTLVs(tlvs map[byte][]byte) string {
	if ja4Bytes, ok := tlvs[TLVTypeJA4Fingerprint]; ok {
		return string(ja4Bytes)
	}
	return ""
}

// extractProxySessionIDFromTLVs extracts the proxy session ID from TLVs
func extractProxySessionIDFromTLVs(tlvs map[byte][]byte) string {
	if sessionIDBytes, ok := tlvs[TLVTypeProxySessionID]; ok {
		return string(sessionIDBytes)
	}
	return ""
}

// isTrustedConnection checks if connection is from trusted proxy
func (r *ProxyProtocolReader) isTrustedConnection(conn net.Conn) bool {
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

	for _, network := range r.trustedNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// proxyProtocolConn wraps a connection with a buffered reader
type proxyProtocolConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from the buffered reader first, then from the connection
func (c *proxyProtocolConn) Read(b []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(b)
	}
	return c.Conn.Read(b)
}

// GetRealClientIP returns the real client IP from PROXY protocol info, or falls back to connection IP
func GetRealClientIP(conn net.Conn, proxyInfo *ProxyProtocolInfo) string {
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		return proxyInfo.SrcIP
	}

	// Fallback to connection remote address
	remoteAddr := conn.RemoteAddr()
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		return addr.IP.String()
	case *net.UDPAddr:
		return addr.IP.String()
	default:
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			return remoteAddr.String()
		}
		return host
	}
}

// GetConnectionIPs returns both real client IP and proxy IP (if applicable)
func GetConnectionIPs(conn net.Conn, proxyInfo *ProxyProtocolInfo) (clientIP, proxyIP string) {
	// Get the direct connection IP (proxy IP if proxied)
	remoteAddr := conn.RemoteAddr()
	var directIP string
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		directIP = addr.IP.String()
	case *net.UDPAddr:
		directIP = addr.IP.String()
	default:
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			directIP = remoteAddr.String()
		} else {
			directIP = host
		}
	}

	// If we have PROXY protocol info, use it for client IP
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		logger.Debug("PROXY protocol: Using PROXY IPs", "client", proxyInfo.SrcIP, "proxy", directIP)
		return proxyInfo.SrcIP, directIP
	}

	// No proxy, direct connection
	logger.Debug("PROXY protocol: Direct connection (no proxy)", "ip", directIP)
	return directIP, ""
}

// GenerateProxyV2HeaderWithTLVs generates a PROXY protocol v2 header with optional TLV extensions
func GenerateProxyV2HeaderWithTLVs(clientIP string, clientPort int, serverIP string, serverPort int, protocol string, tlvs map[byte][]byte) ([]byte, error) {
	// PROXY v2 signature
	header := make([]byte, 16)
	copy(header[0:12], []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A})

	// Version and Command (byte 12): version=2, command=PROXY
	header[12] = 0x21 // version=2 (bits 7-4), command=1/PROXY (bits 3-0)

	// Parse IPs to determine address family
	clientIPNet := net.ParseIP(clientIP)
	serverIPNet := net.ParseIP(serverIP)

	if clientIPNet == nil || serverIPNet == nil {
		return nil, fmt.Errorf("invalid IP addresses: client=%s, server=%s", clientIP, serverIP)
	}

	var addressData []byte
	var addressFamily byte
	var transportProtocol byte = 0x1 // TCP

	// Determine if IPv4 or IPv6
	clientIPv4 := clientIPNet.To4()
	serverIPv4 := serverIPNet.To4()

	if clientIPv4 != nil && serverIPv4 != nil {
		// IPv4
		addressFamily = 0x1 // AF_INET
		addressData = make([]byte, 12)
		copy(addressData[0:4], clientIPv4)
		copy(addressData[4:8], serverIPv4)
		// Client port (big endian)
		addressData[8] = byte(clientPort >> 8)
		addressData[9] = byte(clientPort & 0xFF)
		// Server port (big endian)
		addressData[10] = byte(serverPort >> 8)
		addressData[11] = byte(serverPort & 0xFF)
	} else {
		// IPv6
		addressFamily = 0x2 // AF_INET6
		clientIPv6 := clientIPNet.To16()
		serverIPv6 := serverIPNet.To16()
		addressData = make([]byte, 36)
		copy(addressData[0:16], clientIPv6)
		copy(addressData[16:32], serverIPv6)
		// Client port (big endian)
		addressData[32] = byte(clientPort >> 8)
		addressData[33] = byte(clientPort & 0xFF)
		// Server port (big endian)
		addressData[34] = byte(serverPort >> 8)
		addressData[35] = byte(serverPort & 0xFF)
	}

	// Address family and protocol (byte 13)
	header[13] = (addressFamily << 4) | transportProtocol

	// Encode TLVs if provided
	var tlvData []byte
	if len(tlvs) > 0 {
		for tlvType, tlvValue := range tlvs {
			tlvLen := len(tlvValue)
			// TLV format: 1 byte type + 2 bytes length (big endian) + value
			tlvHeader := []byte{
				tlvType,
				byte(tlvLen >> 8),
				byte(tlvLen & 0xFF),
			}
			tlvData = append(tlvData, tlvHeader...)
			tlvData = append(tlvData, tlvValue...)
		}
	}

	// Total length = address data + TLV data
	totalLen := len(addressData) + len(tlvData)
	header[14] = byte(totalLen >> 8)
	header[15] = byte(totalLen & 0xFF)

	// Combine header + address data + TLV data
	result := append(header, addressData...)
	result = append(result, tlvData...)

	if len(tlvData) > 0 {
		logger.Debug("PROXY protocol: Generated v2 header with TLVs", "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort, "family", addressFamily, "addr_len", len(addressData), "tlv_len", len(tlvData))
	} else {
		logger.Debug("PROXY protocol: Generated v2 header", "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort, "family", addressFamily, "addr_len", len(addressData))
	}

	return result, nil
}

// GenerateProxyV2Header generates a PROXY protocol v2 header without TLVs (backward compatibility)
func GenerateProxyV2Header(clientIP string, clientPort int, serverIP string, serverPort int, protocol string) ([]byte, error) {
	return GenerateProxyV2HeaderWithTLVs(clientIP, clientPort, serverIP, serverPort, protocol, nil)
}

// WriteProxyV2Header writes a PROXY protocol v2 header to a connection
func WriteProxyV2Header(conn net.Conn, clientIP string, clientPort int, serverIP string, serverPort int, protocol string) error {
	header, err := GenerateProxyV2Header(clientIP, clientPort, serverIP, serverPort, protocol)
	if err != nil {
		return fmt.Errorf("failed to generate PROXY v2 header: %w", err)
	}

	_, err = conn.Write(header)
	if err != nil {
		return fmt.Errorf("failed to write PROXY v2 header: %w", err)
	}

	logger.Debug("PROXY protocol: Sent v2 header", "remote", GetAddrString(conn.RemoteAddr()))
	return nil
}
