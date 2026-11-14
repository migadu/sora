package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// AuthResult represents the result of authentication
type AuthResult int

const (
	AuthUserNotFound           AuthResult = iota // User doesn't exist in remotelookup - fallback controlled by lookup_local_users
	AuthSuccess                                  // User found and authenticated - proceed with routing
	AuthFailed                                   // User found but auth failed - reject, no fallback
	AuthTemporarilyUnavailable                   // Auth service gave no verdict - temporary failure, never a fallback to the local database
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
	// ErrRemoteLookupTransient represents a transient error: the lookup service gave no
	// verdict on the user (network issue, timeout, 5xx, a 4xx other than 401/403/404, a
	// malformed 200, circuit breaker open, a request that could not be built). It is
	// never a wrong password. Every error the HTTP lookup client returns wraps it.
	ErrRemoteLookupTransient = errors.New("remotelookup transient error")

	// ErrRemoteLookupInvalidResponse represents an invalid 200 response (malformed JSON, missing
	// required fields, a password_hash sora cannot verify, which also carries
	// db.ErrUnverifiableHash): a lookup service bug. Always returned wrapped in
	// ErrRemoteLookupTransient.
	ErrRemoteLookupInvalidResponse = errors.New("remotelookup invalid response")

	// ErrRemoteLookupRefused is returned by a routing lookup (ConnectionManager.LookupUserRoute)
	// that the lookup service answered 401/403: it refused the account. Unlike a 404 the
	// account is not "unknown here", so there is no fallback to the local database
	// (lookup_local_users), and named-pool routing refuses to use the default pool.
	// Unlike an outage it is a verdict. Not wrapped in ErrRemoteLookupTransient.
	ErrRemoteLookupRefused = errors.New("remotelookup refused the account")

	// ErrUnknownPool is returned when a route names a pool this proxy does not have:
	// a lookup answer for a pool the proxy's config lacks (rollout skew, a typo in
	// the API). The connection fails; it is never spilled into another pool.
	ErrUnknownPool = errors.New("backend pool is not configured on this proxy")

	// ErrNoDefaultPool is returned when a route carries no pool name and the proxy has no
	// pool marked default: an auth-only lookup answer, or a locally found user, on a proxy
	// whose lookup API is expected to name a pool for everyone.
	ErrNoDefaultPool = errors.New("route names no pool and no pool is marked default")

	// ErrRouteLookupFailed is returned when, with named pools, the routing lookup itself
	// fails: there is no pool to route into, and the default pool is not a safe guess.
	ErrRouteLookupFailed = errors.New("routing lookup failed")

	// ErrAmbiguousBackendPool means DNS made independently configured pools share
	// a destination. Neither its owner nor its TLS trust settings can be guessed.
	ErrAmbiguousBackendPool = errors.New("backend belongs to multiple resolved pools")
	// ErrBackendOutsidePool refuses a socket whose destination no longer belongs to its route.
	ErrBackendOutsidePool = errors.New("backend is outside the routed pool")
)

// BackendSettings is the backend-leg configuration of one pool: how the proxy talks to a
// member once it has picked one. A named pool carries its own (config.PoolConfig); the
// unnamed pool a flat remote_addrs list becomes uses the proxy server's.
type BackendSettings struct {
	TLS              bool
	TLSUseStartTLS   bool // Dial plaintext; the proxy upgrades with its protocol's STARTTLS (BackendStartTLSConfig)
	TLSVerify        bool
	UseProxyProtocol bool
	UseIDCommand     bool // IMAP only
	UseXCLIENT       bool // POP3/LMTP only
	UseUTF8          bool // POP3 only
	// TLSCAFile is a PEM file of CA certificates the pool's backends are verified against
	// (private-CA or self-signed backends); "" = the system roots. Loaded once, when the
	// manager is built.
	TLSCAFile string
}

// PoolSpec is one named backend pool as a proxy server hands it to the connection
// manager. Backends may omit the port; the manager completes them with the proxy's
// remote_port, so one spec serves proxies of every protocol.
type PoolSpec struct {
	Name     string
	Backends []string
	Default  bool
	Settings BackendSettings
}

// NormalizeBackendAddr canonicalizes a backend address and completes a missing port with
// defaultPort, the way the connection manager keys its pool members.
func NormalizeBackendAddr(addr string, defaultPort int) string {
	return normalizeHostPort(addr, defaultPort)
}

// ManagerOptions is what a proxy server hands over to build its connection manager: the
// named pools when the config declares [[pool]] blocks, else the flat remote_addrs list
// with the server's own backend-leg settings.
type ManagerOptions struct {
	Pools       []PoolSpec
	RemoteAddrs []string
	RemotePort  int
	Settings    BackendSettings // flat-list settings; unused with Pools
	// RemoteTLSCAFile is the [[server]] block's remote_tls_ca_file: a PEM file of CA
	// certificates that the backends of a flat list, and with Pools any backend in no
	// pool (a lookup pin), are verified against; "" = the system roots. A pool member is
	// verified against its own pool's CA file only.
	RemoteTLSCAFile    string
	ConnectTimeout     time.Duration
	RoutingLookup      UserRoutingLookup
	ServerName         string
	DisableHealthCheck bool
}

// PoolRouteLabel is the pool label of sora_proxy_pool_route_total for a route naming name
// that ended in err: a pool name the lookup API made up is not configured anywhere, so it
// is counted under "unknown" instead of one series per name.
func PoolRouteLabel(name string, err error) string {
	if errors.Is(err, ErrUnknownPool) {
		return "unknown"
	}
	return name
}

func poolRouteOutcome(err error) string {
	if errors.Is(err, ErrAmbiguousBackendPool) {
		return "ambiguous_pool"
	}
	if errors.Is(err, ErrNoDefaultPool) {
		return "no_default"
	}
	return "unknown_pool"
}

// NewConnectionManagerFromOptions builds a pool-routing manager when Pools is set and a
// flat-list one otherwise.
func NewConnectionManagerFromOptions(o ManagerOptions) (*ConnectionManager, error) {
	var roots *x509.CertPool // nil = the system roots
	if o.RemoteTLSCAFile != "" {
		var err error
		if roots, err = loadCAFile(o.RemoteTLSCAFile); err != nil {
			return nil, fmt.Errorf("remote_tls_ca_file: %w", err)
		}
	}
	var cm *ConnectionManager
	var err error
	if len(o.Pools) > 0 {
		cm, err = NewConnectionManagerWithPools(o.Pools, o.RemotePort, o.ConnectTimeout, o.RoutingLookup, o.ServerName, o.DisableHealthCheck)
	} else {
		cm, err = NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(o.RemoteAddrs, o.RemotePort, o.Settings.TLS, o.Settings.TLSUseStartTLS, o.Settings.TLSVerify, o.Settings.UseProxyProtocol, o.ConnectTimeout, o.RoutingLookup, o.ServerName, o.DisableHealthCheck)
	}
	if err != nil {
		return nil, err
	}
	cm.SetRemoteTLSRootCAs(roots)
	return cm, nil
}

// PoolSpecsFromConfig converts the [[pool]] blocks of a config file into pool specs.
func PoolSpecsFromConfig(pools []config.PoolConfig) []PoolSpec {
	specs := make([]PoolSpec, 0, len(pools))
	for i := range pools {
		p := &pools[i]
		specs = append(specs, PoolSpec{
			Name:     p.Name,
			Backends: append([]string(nil), p.Backends...),
			Default:  p.Default,
			Settings: BackendSettings{
				TLS:              p.RemoteTLS,
				TLSUseStartTLS:   p.RemoteTLSUseStartTLS,
				TLSVerify:        p.GetRemoteTLSVerify(),
				UseProxyProtocol: p.RemoteUseProxyProtocol,
				UseIDCommand:     p.RemoteUseIDCommand,
				UseXCLIENT:       p.RemoteUseXCLIENT,
				UseUTF8:          p.RemoteUseUTF8,
				TLSCAFile:        p.RemoteTLSCAFile,
			},
		})
	}
	return specs
}

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
	backendRoute           *BackendRoute // per-request explicit-pin ownership; never persisted in the lookup cache
	ServerAddress          string        // Backend server to connect to (empty in auth-only mode or when routed by pool)
	PoolName               string        // Named pool to pick a backend from (set by the lookup answer, or by routing once resolved)
	AccountID              int64         // Account ID for tracking/metrics
	IsRemoteLookupAccount  bool          // Whether this came from remotelookup
	AuthOnlyMode           bool          // Remote API authenticated but didn't specify backend (use local selection)
	ActualEmail            string        // Actual email address for backend impersonation
	FromCache              bool          // Whether this result came from remotelookup cache
	RemoteTLS              bool          // Use TLS for backend connection
	RemoteTLSUseStartTLS   bool          // Use STARTTLS after the greeting instead of implicit TLS
	RemoteTLSVerify        bool          // Verify backend TLS certificate
	RemoteUseProxyProtocol bool          // Use PROXY protocol for backend connection
	RemoteUseIDCommand     bool          // Use IMAP ID command (IMAP only)
	RemoteUseXCLIENT       bool          // Use XCLIENT command (POP3/LMTP)
	RemoteUseUTF8          bool          // Backend supports POP3 UTF8 (RFC 6856); mirror a client's pre-auth UTF8 to it (POP3 only)
	ClientConn             net.Conn      // Client connection (for extracting JA4 fingerprint)
	ProxySessionID         string        // Proxy session ID for end-to-end tracing
}

// LookupRouted reports whether addr is the backend the remote lookup named, the only one
// its backend settings (the Remote* fields) are for. A user the proxy routes itself — in
// auth-only mode, from the database, or around a remote-lookup route in maintenance —
// reaches a pool backend, which gets the proxy server's own settings. The dial
// (dialWithProxy) and the session after it follow this one rule.
func (r *UserRoutingInfo) LookupRouted(addr string) bool {
	return r != nil && r.ServerAddress != "" && r.ServerAddress == addr
}

// UsesRouteSettings reports whether the Remote* fields are the backend-leg settings for
// addr: either the remote lookup named addr itself (LookupRouted), or routing confined the
// user to a named pool and stamped that pool's settings, which then hold for whichever
// member was picked. A user routed into the flat remote_addrs list, or around a lookup
// route in maintenance into no named pool, gets the proxy server's own settings. The dial
// (dialWithProxy) and the session after it follow this one rule.
func (r *UserRoutingInfo) UsesRouteSettings(addr string) bool {
	return r.LookupRouted(addr) || r.PoolRouted()
}

// PoolRouted reports whether routing confined this user to a named pool, whose settings
// (stamped on the Remote* fields) are then the whole backend-leg configuration: nothing
// falls back to the proxy server's own remote_* settings.
func (r *UserRoutingInfo) PoolRouted() bool {
	return r != nil && r.ServerAddress == "" && r.PoolName != ""
}

// normalizeHostPort normalizes a host:port address, adding a default port if missing
func normalizeHostPort(addr string, defaultPort int) string {
	if addr == "" {
		return ""
	}
	// A complete IPv6 literal has no port, even when its last group is decimal.
	// Trying the unbracketed host:port heuristic first silently changes the host.
	if net.ParseIP(addr) != nil {
		if defaultPort > 0 {
			return net.JoinHostPort(addr, strconv.Itoa(defaultPort))
		}
		return addr
	}

	// net.SplitHostPort is the robust way to do this, as it correctly
	// handles IPv6 addresses like "[::1]:143".
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		// Address is already in a valid host:port format. Canonicalize the host (e.g.
		// IPv6 zero-compression) so different spellings of the same address compare equal.
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		// DNS ownership is keyed by the destination actually dialed. Numeric
		// spellings such as 0143 and service names such as imap mean the same port.
		if n, err := net.LookupPort("tcp", port); err == nil {
			port = strconv.Itoa(n)
		}
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
