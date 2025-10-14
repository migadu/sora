package proxy

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
)

// AuthResult represents the result of authentication
type AuthResult int

const (
	AuthUserNotFound AuthResult = iota // User doesn't exist in prelookup - fallback allowed
	AuthSuccess                        // User found and authenticated - proceed with routing
	AuthFailed                         // User found but auth failed - reject, no fallback
)

// UserRoutingLookup interface for routing lookups
type UserRoutingLookup interface {
	LookupUserRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error)
	Close() error
}

// UserRoutingInfo contains backend routing information for a user
type UserRoutingInfo struct {
	ServerAddress          string // Backend server to connect to
	AccountID              int64  // Account ID for tracking/metrics
	IsPrelookupAccount     bool   // Whether this came from prelookup
	ActualEmail            string // Actual email address for backend impersonation
	RemoteTLS              bool   // Use TLS for backend connection
	RemoteTLSUseStartTLS   bool   // Use STARTTLS (LMTP/ManageSieve only)
	RemoteTLSVerify        bool   // Verify backend TLS certificate
	RemoteUseProxyProtocol bool   // Use PROXY protocol for backend connection
	RemoteUseIDCommand     bool   // Use IMAP ID command (IMAP only)
	RemoteUseXCLIENT       bool   // Use XCLIENT command (POP3/LMTP)
}

// normalizeHostPort normalizes a host:port address, adding a default port if missing
func normalizeHostPort(addr string, defaultPort int) string {
	if addr == "" {
		return ""
	}

	// net.SplitHostPort is the robust way to do this, as it correctly
	// handles IPv6 addresses like "[::1]:143".
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		// Address is already in a valid host:port format.
		// Re-join to ensure canonical format (e.g., for IPv6).
		return net.JoinHostPort(host, port)
	}

	// If parsing fails, it could be because:
	// 1. It's a host without a port (e.g., "localhost", "2001:db8::1").
	// 2. It's a malformed IPv6 with a port but no brackets (e.g., "2001:db8::1:143").

	// Let's test for case #2. This is a heuristic.
	// An IPv6 address will have more than one colon.
	if strings.Count(addr, ":") > 1 {
		lastColon := strings.LastIndex(addr, ":")
		// Assume the part after the last colon is the port.
		if lastColon != -1 && lastColon < len(addr)-1 {
			hostPart := addr[:lastColon]
			portPart := addr[lastColon+1:]

			// Check if the parts look like a valid IP and port.
			if net.ParseIP(hostPart) != nil {
				if _, pErr := strconv.Atoi(portPart); pErr == nil {
					// This looks like a valid but malformed IPv6:port. Fix it.
					fixedAddr := net.JoinHostPort(hostPart, portPart)
					log.Printf("[Proxy] Corrected malformed IPv6 address '%s' to '%s'", addr, fixedAddr)
					return fixedAddr
				}
			}
		}
	}

	// If we're here, it's most likely case #1: a host without a port.
	// Add the default port if one is configured.
	if defaultPort > 0 {
		return net.JoinHostPort(addr, strconv.Itoa(defaultPort))
	}

	// No default port to add, and we couldn't fix it, so return as is.
	return addr
}
