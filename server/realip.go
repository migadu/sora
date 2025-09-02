package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// RealIPConfig holds configuration for extracting real client IPs from proxy headers
type RealIPConfig struct {
	// TrustedProxies contains CIDR blocks of trusted proxies/load balancers
	TrustedProxies []string
	// HeaderNames contains ordered list of headers to check for real IP
	// Common headers: "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", etc.
	HeaderNames []string
	// Enabled controls whether real IP extraction is active
	Enabled bool
}

// DefaultRealIPConfig returns a sensible default configuration
func DefaultRealIPConfig() RealIPConfig {
	return RealIPConfig{
		TrustedProxies: []string{
			"127.0.0.0/8",    // localhost
			"10.0.0.0/8",     // RFC1918 private
			"172.16.0.0/12",  // RFC1918 private  
			"192.168.0.0/16", // RFC1918 private
			"fc00::/7",       // IPv6 unique local
			"::1/128",        // IPv6 localhost
		},
		HeaderNames: []string{
			"X-Forwarded-For",
			"X-Real-IP",
			"CF-Connecting-IP",     // Cloudflare
			"True-Client-IP",       // Akamai, Cloudflare Enterprise
			"X-Forwarded",
			"Forwarded-For",
			"Forwarded",
		},
		Enabled: false, // Disabled by default for security
	}
}

// RealIPExtractor handles extraction of real client IPs from proxy headers
type RealIPExtractor struct {
	config       RealIPConfig
	trustedNets  []*net.IPNet
}

// NewRealIPExtractor creates a new real IP extractor with the given configuration
func NewRealIPExtractor(config RealIPConfig) (*RealIPExtractor, error) {
	extractor := &RealIPExtractor{
		config: config,
	}
	
	// Parse trusted proxy CIDR blocks
	for _, cidr := range config.TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %s: %w", cidr, err)
		}
		extractor.trustedNets = append(extractor.trustedNets, network)
	}
	
	return extractor, nil
}

// ExtractRealIP extracts the real client IP from connection and HTTP headers
func (r *RealIPExtractor) ExtractRealIP(remoteAddr net.Addr, headers map[string]string) string {
	if !r.config.Enabled {
		return r.extractIPFromAddr(remoteAddr)
	}
	
	// Get the immediate connection IP
	immediateIP := r.extractIPFromAddr(remoteAddr)
	
	// Check if the immediate connection is from a trusted proxy
	if !r.isTrustedProxy(immediateIP) {
		// Not from trusted proxy, use immediate IP
		return immediateIP
	}
	
	// Look for real IP in headers (in order of preference)
	for _, headerName := range r.config.HeaderNames {
		if headerValue, exists := headers[headerName]; exists {
			if realIP := r.extractFromHeader(headerValue); realIP != "" {
				return realIP
			}
		}
	}
	
	// Fallback to immediate IP if no valid header found
	return immediateIP
}

// ExtractRealIPFromHTTPRequest is a convenience method for HTTP requests
func (r *RealIPExtractor) ExtractRealIPFromHTTPRequest(req *http.Request) string {
	if !r.config.Enabled {
		return r.extractIPFromAddr(&net.TCPAddr{
			IP:   net.ParseIP(req.RemoteAddr),
			Port: 0,
		})
	}
	
	// Convert HTTP headers to map
	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	
	// Create a pseudo address from RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	
	addr := &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: 0,
	}
	
	return r.ExtractRealIP(addr, headers)
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func (r *RealIPExtractor) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	for _, network := range r.trustedNets {
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}

// extractIPFromAddr extracts IP string from net.Addr
func (r *RealIPExtractor) extractIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		// Fallback: try to parse as "host:port"
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

// extractFromHeader extracts the first valid IP from a header value
func (r *RealIPExtractor) extractFromHeader(headerValue string) string {
	// Handle X-Forwarded-For format: "client, proxy1, proxy2"
	ips := strings.Split(headerValue, ",")
	
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		
		// Basic validation
		if ip := net.ParseIP(ipStr); ip != nil {
			// Skip private/loopback IPs in forwarded headers (usually proxies)
			if !r.isPrivateIP(ip) {
				return ipStr
			}
		}
	}
	
	// If no public IP found, return the first one (might be from internal network)
	if len(ips) > 0 {
		return strings.TrimSpace(ips[0])
	}
	
	return ""
}

// isPrivateIP checks if an IP is private/internal
func (r *RealIPExtractor) isPrivateIP(ip net.IP) bool {
	// RFC1918 private networks
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12", 
		"192.168.0.0/16",
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link local
	}
	
	for _, cidr := range private {
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

// GetConfig returns the current configuration
func (r *RealIPExtractor) GetConfig() RealIPConfig {
	return r.config
}