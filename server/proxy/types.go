package proxy

import (
	"context"
	"errors"
	"github.com/migadu/sora/logger"
	"net"
	"strconv"
	"strings"
)

// AuthResult represents the result of authentication
type AuthResult int

const (
	AuthUserNotFound           AuthResult = iota // User doesn't exist in remotelookup - fallback controlled by fallback_to_db
	AuthSuccess                                  // User found and authenticated - proceed with routing
	AuthFailed                                   // User found but auth failed - reject, no fallback
	AuthTemporarilyUnavailable                   // Auth service temporarily unavailable - fallback controlled by fallback_to_db
)

// String returns a human-readable representation of AuthResult
func (a AuthResult) String() string {
	switch a {
	case AuthUserNotFound:
		return "AuthUserNotFound"
	case AuthSuccess:
		return "AuthSuccess"
	case AuthFailed:
		return "AuthFailed"
	case AuthTemporarilyUnavailable:
		return "AuthTemporarilyUnavailable"
	default:
		return "AuthUnknown"
	}
}

// RemoteLookup error types for distinguishing failure modes
var (
	// ErrRemoteLookupTransient represents a transient error (network issue, 5xx, circuit breaker open)
	// Fallback behavior is controlled by fallback_to_db config
	ErrRemoteLookupTransient = errors.New("remotelookup transient error")

	// ErrRemoteLookupInvalidResponse represents an invalid 2xx response (malformed JSON, missing required fields)
	// This is a server bug - should fail hard, no fallback
	ErrRemoteLookupInvalidResponse = errors.New("remotelookup invalid response")
)

// UserRoutingLookup interface for routing lookups
// NOTE: No caching - remotelookup is just a data source, caching happens at higher level
type UserRoutingLookup interface {
	LookupUserRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error)
	LookupUserRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*UserRoutingInfo, AuthResult, error)
	LookupUserRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*UserRoutingInfo, AuthResult, error)
	Close() error
}

// UserRoutingInfo contains backend routing information for a user
type UserRoutingInfo struct {
	ServerAddress          string   // Backend server to connect to
	AccountID              int64    // Account ID for tracking/metrics
	IsRemoteLookupAccount  bool     // Whether this came from remotelookup
	ActualEmail            string   // Actual email address for backend impersonation
	FromCache              bool     // Whether this result came from remotelookup cache
	RemoteTLS              bool     // Use TLS for backend connection
	RemoteTLSUseStartTLS   bool     // Use STARTTLS (LMTP/ManageSieve only)
	RemoteTLSVerify        bool     // Verify backend TLS certificate
	RemoteUseProxyProtocol bool     // Use PROXY protocol for backend connection
	RemoteUseIDCommand     bool     // Use IMAP ID command (IMAP only)
	RemoteUseXCLIENT       bool     // Use XCLIENT command (POP3/LMTP)
	ClientConn             net.Conn // Client connection (for extracting JA4 fingerprint)
	ProxySessionID         string   // Proxy session ID for end-to-end tracing
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
					logger.Debug("Proxy: Corrected malformed IPv6 address", "original", addr, "corrected", fixedAddr)
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
