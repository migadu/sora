package userapiproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type contextKey string

const (
	clientIPKey      contextKey = "client-ip"
	clientPortKey    contextKey = "client-port"
	proxyProtocolKey contextKey = "proxy-protocol" // bool: whether this request's backend gets a PROXY header
	backendRouteKey  contextKey = "backend-route"
)

// JWTClaims represents the JWT token claims (must match userapi.JWTClaims)
type JWTClaims struct {
	Email     string `json:"email"`
	AccountID int64  `json:"account_id"`
	jwt.RegisteredClaims
}

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after; a request loads it once.
type reloadableSettings struct {
	jwtSecret      string   // JWT secret for token validation
	allowedOrigins []string // CORS policy of the responses the proxy writes itself (writeError)
}

// Server represents a User API proxy server
type Server struct {
	name                       string
	hostname                   string // labels the metrics, like every other server's hostname
	addr                       string
	connManager                *proxy.ConnectionManager
	remoteUseProxyProtocol     bool // the server's own PROXY-header setting; a named pool's setting overrides it per route
	remoteTLS                  bool // the server's own backend TLS setting; a named pool's setting overrides it per route
	remoteTLSVerify            bool // the server's own backend certificate check; likewise
	lookupLocalUsers           bool // a user the remote lookup does not know is routed into the default pool
	rdb                        *resilient.ResilientDatabase
	routingLookup              proxy.UserRoutingLookup  // RemoteLookup client for user routing (optional)
	affinityManager            *server.AffinityManager  // Affinity manager for sticky routing (optional)
	lookupCache                *lookupcache.LookupCache // Route lookup cache (optional)
	positiveRevalidationWindow time.Duration            // Revalidation window for cached routes
	tls                        bool
	tlsCertFile                string
	tlsKeyFile                 string
	tlsVerify                  bool
	tlsConfig                  *tls.Config // Global TLS config from TLS manager (optional)
	trustedProxies             []string    // CIDR blocks for trusted proxies
	limiter                    *server.ConnectionLimiter
	authLimiter                *server.AuthRateLimiter // login rate limit (auth_rate_limit); nil when off
	// connReleases holds the connection-limiter release callback for each live
	// connection, keyed by net.Conn, so the slot is freed on StateClosed/
	// StateHijacked. Without this the limiter counter only ever increments and
	// the proxy eventually refuses every connection (permanent DoS).
	connReleases   map[net.Conn]func()
	connReleasesMu sync.Mutex
	httpServer     *http.Server
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup

	// Base transports retain the server's dial policy. Proxied requests use a
	// bounded cache partitioned by pool, verification policy and DNS snapshot;
	// no reused connection can silently acquire another pool's trust identity.
	transport         *http.Transport
	transports        map[bool]*http.Transport
	newTransport      func(bool) *http.Transport
	transportMu       sync.Mutex
	poolTransports    map[backendTransportKey]*http.Transport
	transportSnapshot uint64

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader

	// The settings ReloadConfig replaces; see reloadableSettings.
	settings atomic.Pointer[reloadableSettings]
}

// ServerOptions holds configuration options for the User API proxy server
type ServerOptions struct {
	Name                     string
	Addr                     string
	RemoteAddrs              []string
	Pools                    []proxy.PoolSpec // Named backend pools ([[pool]] blocks); when set, RemoteAddrs is unused and each pool brings its own backend-leg settings
	RemotePort               int              // Default port for backends if not in address
	JWTSecret                string           // JWT secret for token validation
	AllowedOrigins           []string         // CORS allowed origins (allowed_origins) of the responses the proxy writes itself
	TLS                      bool
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS                bool
	RemoteTLSVerify          bool
	RemoteTLSCAFile          string // PEM file with CA certs for backend verification (private-CA / self-signed backends); empty = system roots
	ConnectTimeout           time.Duration
	EnableBackendHealthCheck bool                       // Enable backend health checking (default: true)
	RemoteDNSRefresh         *time.Duration             // Backend DNS re-resolution interval; nil = default, 0 = pin to the startup resolution
	MaxConnections           int                        // Maximum total connections per instance (0 = unlimited, local only)
	MaxConnectionsPerIP      int                        // Maximum connections per client IP (0 = unlimited, cluster-wide if ClusterManager provided)
	TrustedNetworks          []string                   // CIDR blocks for trusted networks that bypass per-IP limits
	TrustedProxies           []string                   // CIDR blocks for trusted proxies
	RemoteLookup             *config.RemoteLookupConfig // RemoteLookup configuration for user routing
	LookupCache              *config.LookupCacheConfig  // Route lookup cache configuration
	AffinityManager          *server.AffinityManager    // Affinity manager for sticky routing (optional)
	ClusterManager           *cluster.Manager           // Optional: enables cluster-wide per-IP limiting

	// Rate limit of every login through the proxy (auth_rate_limit); see admitLogin.
	AuthRateLimit server.AuthRateLimiterConfig

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol          bool   // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout   string // Timeout for reading PROXY protocol headers (e.g., "5s")
	RemoteUseProxyProtocol bool   // Use PROXY protocol for backend connections
}

// checkJWTSecret refuses a JWT secret the proxy must not validate with, at start-up and
// on a config reload alike.
func checkJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT secret is required for User API proxy")
	}
	if len(secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 bytes for HS256 (RFC 7518 §3.2); got %d", len(secret))
	}
	if secret == "your-secret-jwt-signing-key-here" {
		return fmt.Errorf("JWT secret is the placeholder value from config.toml.example — set a real, random jwt_secret")
	}
	return nil
}

// New creates a new User API proxy server
func New(appCtx context.Context, rdb *resilient.ResilientDatabase, opts ServerOptions) (*Server, error) {
	ctx, cancel := context.WithCancel(appCtx)

	if len(opts.RemoteAddrs) == 0 && len(opts.Pools) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses or backend pools configured")
	}

	if err := checkJWTSecret(opts.JWTSecret); err != nil {
		cancel()
		return nil, err
	}

	// Set default timeout if not specified
	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Initialize remotelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.RemoteLookup != nil && opts.RemoteLookup.Enabled {
		remotelookupClient, err := proxy.InitializeRemoteLookup("userapi", opts.RemoteLookup, opts.RemotePort)
		if err != nil {
			// Also with lookup_local_users, which adds the database for the users the
			// lookup does not know and does not make the lookup optional.
			cancel()
			return nil, fmt.Errorf("remotelookup initialization failed: %w", err)
		}
		routingLookup = remotelookupClient
		logger.Info("User API Proxy: RemoteLookup enabled", "name", opts.Name)
	}

	// Create connection manager with routing lookup
	connManager, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		Pools:              opts.Pools,
		RemoteAddrs:        opts.RemoteAddrs,
		RemotePort:         opts.RemotePort,
		Settings:           proxy.BackendSettings{TLS: opts.RemoteTLS, TLSVerify: opts.RemoteTLSVerify},
		RemoteTLSCAFile:    opts.RemoteTLSCAFile,
		ConnectTimeout:     connectTimeout,
		RoutingLookup:      routingLookup,
		ServerName:         opts.Name,
		DisableHealthCheck: !opts.EnableBackendHealthCheck,
	})
	if err != nil {
		if routingLookup != nil {
			// Close remotelookup client on error
			if closer, ok := routingLookup.(interface{ Close() error }); ok {
				closer.Close()
			}
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// SSRF defense: when enabled, refuse remote-lookup backends not in the configured pool.
	connManager.SetRestrictRemoteLookupToPool(opts.RemoteLookup != nil && opts.RemoteLookup.RestrictToPool)

	// Backend hostnames are re-resolved periodically so an address change is picked
	// up without a restart; remote_dns_refresh tunes or disables that.
	if opts.RemoteDNSRefresh != nil {
		connManager.SetResolveRefreshInterval(*opts.RemoteDNSRefresh)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Warn("User API Proxy: Failed to resolve addresses", "name", opts.Name, "error", err)
	}

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		if opts.ClusterManager != nil {
			// Cluster mode: use cluster-wide per-IP limiting
			instanceID := fmt.Sprintf("user-api-proxy-%s-%d", opts.Name, time.Now().UnixNano())
			limiter = server.NewConnectionLimiterWithCluster("USER-API-PROXY", instanceID, opts.ClusterManager, opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
		} else {
			// Local mode: use local-only limiting
			limiter = server.NewConnectionLimiterWithTrustedNets("USER-API-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
		}
	}

	// Dial callbacks use each request's immutable route binding. Connection reuse
	// is separately partitioned by pool and DNS snapshot in transportFor.
	dialBackend := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dial := (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
			// Routing skips backends in maintenance; this refuses the address
			// actually dialed, whatever name led to it.
			Control: connManager.RefuseMaintenanceDial,
		}).DialContext
		if route, ok := ctx.Value(backendRouteKey).(*proxy.BackendRoute); ok {
			dial = route.DialContext
		}
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The route decides whether this backend gets a PROXY header: a named pool's
		// own setting, else the server's. proxyRequest puts it on the context.
		useProxyProtocol := opts.RemoteUseProxyProtocol
		if v, ok := ctx.Value(proxyProtocolKey).(bool); ok {
			useProxyProtocol = v
		}
		if useProxyProtocol {
			// Retrieve client IP and port from context
			if cIP, ok := ctx.Value(clientIPKey).(string); ok {
				if cPort, ok := ctx.Value(clientPortKey).(int); ok {
					// Retrieve local IP/port from conn to use as server IP/port in PROXY header
					var serverIP string = "127.0.0.1"
					var serverPort int = 0
					if localAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
						serverIP = localAddr.IP.String()
						serverPort = localAddr.Port
					}
					// Write PROXY v2 header
					if err := server.WriteProxyV2Header(conn, cIP, cPort, serverIP, serverPort, "tcp"); err != nil {
						conn.Close()
						return nil, fmt.Errorf("failed to write PROXY v2 header: %w", err)
					}
				}
			}
		}
		return conn, nil
	}
	// Each connection's outcome, once it is usable or has failed (after the TLS handshake
	// if there is one), is recorded against the backend the request was routed to:
	// routing passes over a backend that failed three connections in a row, as on the
	// other proxies, instead of sending its users there for a 502 while it is down.
	// http.Transport dials with a context detached from the request's cancellation: a
	// dial outlives a client that went away, and counts when it fails on its own; only a
	// dial CloseIdleConnections cancels once no request waits for it goes uncounted.
	recordDial := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if route, ok := ctx.Value(backendRouteKey).(*proxy.BackendRoute); ok {
				route.RecordDialOutcome(ctx, err)
			}
			return conn, err
		}
	}
	// The TLS leg is set up here rather than by the transport, with the connection
	// manager's config for the address dialed (proxy.BackendClientTLS): a pool member is
	// verified against its pool's CA file, and by the name it was configured with although
	// the transport dials the address that name resolved to.
	newTransport := func(verify bool) *http.Transport {
		return &http.Transport{
			DialContext: recordDial(dialBackend),
			DialTLSContext: recordDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialBackend(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				cfg := connManager.BackendClientTLSForConn(verify, addr, conn)
				if route, ok := ctx.Value(backendRouteKey).(*proxy.BackendRoute); ok {
					cfg = route.TLSConfig(verify, conn)
				}
				tlsConn := tls.Client(conn, cfg)
				handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			}),
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	transports := map[bool]*http.Transport{true: newTransport(true), false: newTransport(false)}
	transport := transports[opts.RemoteTLSVerify]

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if opts.ProxyProtocol {
		// Build config from flat fields (matching backend format)
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Timeout:        opts.ProxyProtocolTimeout,
			TrustedProxies: opts.TrustedNetworks, // Proxies always use trusted_networks
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("USER-API-PROXY", proxyConfig)
		if err != nil {
			if routingLookup != nil {
				// Close remotelookup client on error
				if closer, ok := routingLookup.(interface{ Close() error }); ok {
					closer.Close()
				}
			}
			cancel()
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "proxy", opts.Name)
	}

	// Initialize route lookup cache if configured
	var lookupCache *lookupcache.LookupCache
	var positiveRevalidationWindow time.Duration
	if opts.LookupCache != nil && opts.LookupCache.Enabled && !proxy.RemoteLookupUsesClientIP(opts.RemoteLookup) {
		lookupCacheConfig := opts.LookupCache

		positiveTTL := lookupCacheConfig.GetPositiveTTLWithDefault(opts.Name)
		negativeTTL := lookupCacheConfig.GetNegativeTTLWithDefault(opts.Name)
		cleanupInterval := lookupCacheConfig.GetCleanupIntervalWithDefault(opts.Name)

		maxSize := lookupCacheConfig.GetMaxSize()

		positiveRevalidationWindow = lookupCacheConfig.GetPositiveRevalidationWindowWithDefault(opts.Name)

		lookupCache = lookupcache.New("userapi_proxy", opts.Name, positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("User API Proxy: Route lookup cache enabled", "name", opts.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	// Every login passes the proxy and some reach no backend (routeAuthRequest), so the
	// proxy is where logins are rate limited, as on the other proxies.
	hostname := config.ResolveMailHostname()
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("USER-API-PROXY", opts.Name, hostname, opts.AuthRateLimit, opts.TrustedNetworks)
	if authLimiter != nil {
		server.RegisterRateLimiter("userapi_proxy", opts.Name, authLimiter)
		go func() {
			<-ctx.Done()
			server.UnregisterRateLimiter("userapi_proxy", opts.Name)
			authLimiter.Stop()
		}()
	}

	s := &Server{
		name:                       opts.Name,
		hostname:                   hostname,
		addr:                       opts.Addr,
		connManager:                connManager,
		remoteUseProxyProtocol:     opts.RemoteUseProxyProtocol,
		remoteTLS:                  opts.RemoteTLS,
		remoteTLSVerify:            opts.RemoteTLSVerify,
		lookupLocalUsers:           opts.RemoteLookup != nil && opts.RemoteLookup.ShouldLookupLocalUsers(),
		rdb:                        rdb,
		routingLookup:              routingLookup,
		affinityManager:            opts.AffinityManager,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		tls:                        opts.TLS,
		tlsCertFile:                opts.TLSCertFile,
		tlsKeyFile:                 opts.TLSKeyFile,
		tlsVerify:                  opts.TLSVerify,
		tlsConfig:                  opts.TLSConfig,
		trustedProxies:             opts.TrustedProxies,
		limiter:                    limiter,
		authLimiter:                authLimiter,
		transport:                  transport,
		transports:                 transports,
		newTransport:               newTransport,
		poolTransports:             make(map[backendTransportKey]*http.Transport),
		proxyReader:                proxyReader,
		ctx:                        ctx,
		cancel:                     cancel,
		connReleases:               make(map[net.Conn]func()),
	}
	connManager.OnMaintenanceChange(s.closeBackendIdleConnections)
	s.settings.Store(&reloadableSettings{jwtSecret: opts.JWTSecret, allowedOrigins: opts.AllowedOrigins})
	return s, nil
}

// Start starts the User API proxy server
func (s *Server) Start() error {
	// Setup HTTP handler (with PROXY protocol support if enabled)
	handler := s.setupHandler()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: writeTimeout,
		IdleTimeout:  120 * time.Second,
		ConnState:    s.connStateHandler,
	}

	// Note: PROXY protocol is handled by wrapping the listener in Start(),
	// not via ConnContext, because we need to replace the connection before HTTP server sees it

	// Configure TLS: the certificate source and tls_verify follow the rule
	// every listener shares (server.ListenerTLS).
	if s.tls {
		tlsConfig, err := server.ListenerTLS{
			Protocol: "User API proxy", Name: s.name,
			CertFile: s.tlsCertFile, KeyFile: s.tlsKeyFile, Verify: s.tlsVerify,
			Global: s.tlsConfig,
		}.Config()
		if err != nil {
			s.cancel()
			return err
		}
		s.httpServer.TLSConfig = tlsConfig
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	// Graceful shutdown
	go func() {
		<-s.ctx.Done()
		logger.Info("User API Proxy: Shutting down server", "name", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("User API Proxy: Error shutting down server", "name", s.name, "error", err)
		}
	}()

	// Start server
	protocol := "HTTP"
	if s.tls {
		protocol = "HTTPS"
	}
	logger.Info("User API Proxy: Starting server", "name", s.name, "protocol", protocol, "addr", s.addr)

	// Create listener
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	// Wrap listener with PROXY protocol support if enabled. The shared
	// listener parses headers per-connection off the accept path and never
	// surfaces per-connection PROXY errors to http.Server.Serve (the old
	// inline listener returned them, and net/http treats non-temporary
	// Accept errors as fatal — one malformed header killed the listener).
	// The HTTP variant makes RemoteAddr() report the forwarded client IP,
	// which is what the per-IP connection limit counts and what the
	// backends are told the client is.
	listener = server.WrapProxyProtocolHTTP(listener, s.proxyReader, "USER-API-PROXY")

	// Start serving. The certificate is in TLSConfig already: certificate
	// files passed here would be loaded again, on top of the global one.
	if s.tls {
		return s.httpServer.ServeTLS(listener, "", "")
	}
	return s.httpServer.Serve(listener)
}

// setupHandler creates the HTTP handler with reverse proxy logic
func (s *Server) setupHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The client's IP travels with the request: routeUser fills the remote lookup's
		// $ip with it.
		r = r.WithContext(context.WithValue(r.Context(), clientIPKey, s.getRealClientIP(r)))

		// Track metrics
		metrics.ConnectionsTotal.WithLabelValues("userapi_proxy", s.name, s.hostname).Inc()
		metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, s.hostname).Inc()
		defer metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, s.hostname).Dec()

		// Fail closed until the backend maintenance list has been read: any backend
		// might be in maintenance (proxy.Maintenance.Loaded).
		if !s.connManager.MaintenanceLoaded() {
			logger.Error("User API Proxy: backend maintenance list not loaded yet - refusing request", "name", s.name)
			s.writeError(w, r, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Check if this is an authentication endpoint (no JWT required)
		isAuthEndpoint := strings.HasPrefix(r.URL.Path, "/user/auth/")

		if !isAuthEndpoint && !isCORSPreflight(r) {
			// Validate JWT token and extract claims for non-auth endpoints
			claims, err := s.extractAndValidateToken(r)
			if err != nil {
				logger.Warn("User API Proxy: Authentication failed", "name", s.name, "path", r.URL.Path, "error", err)
				s.writeUnauthorized(w, r, err)
				return
			}

			// Get backend for this user
			route, err := s.getBackendForUser(r.Context(), claims.Email, claims.AccountID)
			if err != nil {
				logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "user", claims.Email, "error", err)
				s.writeError(w, r, "Service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Proxy authenticated request to the user's backend
			s.proxyRequest(w, r, route, nil)
			return
		}

		// Auth endpoints and CORS preflights carry no JWT. A login names its user in the
		// body and a refresh carries the user's token, so both are routed like any other
		// request for that user: the account lives on a backend of the user's pool. A
		// refresh whose token the proxy refuses is answered here, as on every other
		// endpoint. A preflight, and an auth request that names nobody otherwise, reaches
		// no account: see routeNameless. Logins are rate limited here (admitLogin).
		var route backendRoute
		var login *loginAttempt
		var err error
		if isCORSPreflight(r) {
			route, err = s.routeNameless(r)
		} else {
			route, login, err = s.routeAuthRequest(r)
		}
		if err != nil {
			if errors.Is(err, errAuthBodyTooLarge) {
				s.writeError(w, r, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if errors.Is(err, errRefreshTokenRefused) {
				logger.Warn("User API Proxy: Authentication failed", "name", s.name, "path", r.URL.Path, "error", err)
				s.writeError(w, r, "Invalid or expired token", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, errLoginRefused) {
				s.writeLoginRefused(w, r)
				return
			}
			if errors.Is(err, server.ErrDelayQueueFull) {
				// The answer of a backend's limiter (userapi handleLogin).
				s.writeUserAPIError(w, r, "Too many concurrent authentication attempts. Please try again later.", http.StatusTooManyRequests)
				return
			}
			logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "path", r.URL.Path, "error", err)
			s.writeError(w, r, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Proxy unauthenticated request
		s.proxyRequest(w, r, route, login)
	})
}

// writeError answers r with an error the proxy writes itself, no backend having answered.
// The body is the User API's error, {"error": msg} as application/json (the backend's
// writeError, docs/USER_API.md section 4, "Requests, responses and errors"), so a client reads it as it reads
// the backend's. It carries the CORS headers of the proxy's allowed_origins, as the
// backend's own errors carry the backend's: without them a browser hands the page a
// network error instead of the status, and a web client cannot tell an expired token from
// an outage. A forwarded response carries the backend's CORS headers and must get none here.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.writeUserAPIError(w, r, msg, code)
}

// writeLoginRefused answers a login the proxy refuses itself (errLoginRefused) as a
// backend answers a wrong password (userapi handleLogin): 401 {"error": "Invalid
// credentials"} with the backend's headers. Unlike writeError it sets no
// X-Content-Type-Options, which the backend's answer lacks: a header only the proxy sets
// would show that no backend was asked, and so what the lookup said of the address.
func (s *Server) writeLoginRefused(w http.ResponseWriter, r *http.Request) {
	s.writeUserAPIError(w, r, "Invalid credentials", http.StatusUnauthorized)
}

// writeUserAPIError writes {"error": msg} as application/json with the CORS headers of
// the proxy's allowed_origins: what a backend's writeError writes behind its CORS
// middleware.
func (s *Server) writeUserAPIError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	h := w.Header()
	server.SetCORSHeaders(h, r.Header.Get("Origin"), s.settings.Load().allowedOrigins)
	h.Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		logger.Debug("User API Proxy: Failed to write error response", "name", s.name, "status", code, "error", err)
	}
}

// isCORSPreflight reports whether r is a CORS-preflight request: an OPTIONS request with
// Access-Control-Request-Method (Fetch Standard, "HTTP requests"). A browser sends one
// before a cross-origin call that carries Authorization and never puts credentials on it,
// so it cannot be held to the JWT check; the backend answers it without touching any
// account, as it does when it is reached directly.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// routeNameless picks the backend that answers a request naming no user: a CORS
// preflight, or an auth request whose body names nobody (see peekAuthIdentity). A backend
// answers a preflight in its CORS middleware (with its allowed_origins) before any
// handler, and such an auth request from the request alone (400 for a login without an
// email or a refresh without a token, 404, 405), so it reaches no account. Unlike a
// request that names a user it is therefore not confined to one pool: it goes to the
// default pool (the one pool of a flat remote_addrs list), and failing that (no default
// pool, or no backend of it available) to the first pool in configuration order with a
// backend available (neither in maintenance nor marked unhealthy). Which pool answers
// decides whose allowed_origins applies, so every pool's backends should share them.
func (s *Server) routeNameless(r *http.Request) (backendRoute, error) {
	tried := ""
	if pool, err := s.connManager.ResolvePool(""); err == nil {
		if addr := s.connManager.GetBackendByConsistentHashInPool(pool.Name, r.URL.Path); addr != "" {
			return s.poolRoute(addr, pool), nil
		}
		tried = pool.Name
	}
	for _, name := range s.connManager.PoolNames() {
		if name == tried {
			continue
		}
		pool, err := s.connManager.ResolvePool(name)
		if err != nil {
			continue // refused while its backends collide with another pool's
		}
		if addr := s.connManager.GetBackendByConsistentHashInPool(name, r.URL.Path); addr != "" {
			return s.poolRoute(addr, pool), nil
		}
	}
	return backendRoute{}, fmt.Errorf("no backend available for a request naming no user")
}

// writeTimeout is the proxy's http.Server WriteTimeout: no answer later than this after a
// request was read reaches its client.
const writeTimeout = 30 * time.Second

// maxAuthBodyBytes bounds how much of an auth request body the proxy reads to find the
// user it is for; a login or refresh body is a few hundred bytes.
const maxAuthBodyBytes = 64 << 10

var errAuthBodyTooLarge = errors.New("auth request body too large")

// errRefreshTokenRefused is a refresh whose token the proxy refuses (invalid, expired,
// or lacking usable account identity). It is answered 401 and never
// forwarded: a backend whose clock is behind the proxy's could accept the token, and its
// refresh would then look up the token's email in its own pool's database, which need
// not be the user's pool.
var errRefreshTokenRefused = errors.New("refresh token refused")

// errUserRefused is a user the remote lookup does not know (404/3xx) while
// lookup_local_users is off, or one whose account it refuses (401/403): a verdict on the
// user, not an outage. No backend may answer for that user, with named pools or a flat
// remote_addrs list, so routeUser routes the request nowhere.
var errUserRefused = errors.New("user refused by the remote lookup")

// errLoginRefused is a login the proxy refuses itself: one for an errUserRefused user, at
// the cost of a password verification, or one the rate limit blocks (admitLogin). It is
// answered as a backend answers a wrong password (writeLoginRefused).
var errLoginRefused = errors.New("login refused")

// routeAuthRequest picks the backend for an unauthenticated auth request, and returns
// the login attempt the rate limit counts by the backend's answer (nil for a refresh, or
// without a rate limit). A login is admitted by the rate limit first (admitLogin). A
// login for a user the lookup does not know or refuses reaches no backend, which would
// verify the password before answering 401: the proxy verifies it against a dummy hash
// instead, counts it as a failure and returns errLoginRefused, so that neither the
// answer, nor its timing, nor the rate limit shows what the lookup said of the address.
// A refresh for such a user carries a token the proxy accepted, so its caller learns
// nothing from the refusal and it stays a temporary one.
func (s *Server) routeAuthRequest(r *http.Request) (backendRoute, *loginAttempt, error) {
	id, err := s.peekAuthIdentity(r)
	if err != nil {
		return backendRoute{}, nil, err
	}
	if id.email == "" {
		route, err := s.routeNameless(r)
		return route, nil, err
	}
	var login *loginAttempt
	if id.password != "" && s.authLimiter != nil {
		login = &loginAttempt{addr: &server.StringAddr{Addr: s.getRealClientIP(r)}, key: server.AuthRateLimitKey(id.email)}
		if err := s.admitLogin(r.Context(), login); err != nil {
			return backendRoute{}, nil, err
		}
	}
	route, err := s.routeUser(r.Context(), id.email, id.accountID, true)
	if errors.Is(err, errUserRefused) && id.password != "" {
		logger.Info("User API Proxy: Login refused", "name", s.name, "user", id.email, "error", err)
		db.DummyVerifyPassword(id.password)
		s.recordLogin(r.Context(), login, false)
		return backendRoute{}, nil, fmt.Errorf("%w: %w", errLoginRefused, err)
	}
	if err != nil {
		return backendRoute{}, nil, err
	}
	return route, login, nil
}

// loginAttempt is a login the rate limit counts: the client's address, and the address
// it logs in as keyed as a backend keys it (server.AuthRateLimitKey).
type loginAttempt struct {
	addr net.Addr
	key  string
}

// admitLogin applies the rate limit to a login before it is routed, as a backend applies
// its own before it verifies the password (userapi handleLogin): the client's progressive
// delay, then the blocks of its IP and of its IP and address. A blocked login is
// errLoginRefused, answered at once like a wrong password, without a verification that
// would let a blocked client spend the proxy's CPU. One limiter counts every login
// through the proxy, those a backend answers (proxyRequest) and those the proxy refuses
// itself, so neither a delay nor a block depends on whether the lookup knows the address.
// A login delay that cannot be served is server.ErrDelayQueueFull.
func (s *Server) admitLogin(ctx context.Context, login *loginAttempt) error {
	if err := server.ApplyAuthenticationDelay(ctx, s.authLimiter, login.addr, "userapi_proxy"); err != nil {
		return fmt.Errorf("login delay: %w", err)
	}
	if err := s.authLimiter.CanAttemptAuth(ctx, login.addr, login.key); err != nil {
		return fmt.Errorf("%w: %w", errLoginRefused, err)
	}
	return nil
}

// recordLogin counts the outcome of login; a nil login (no rate limit) counts nothing.
func (s *Server) recordLogin(ctx context.Context, login *loginAttempt, success bool) {
	if login != nil {
		s.authLimiter.RecordAuthAttempt(ctx, login.addr, login.key, success)
	}
}

// authIdentity is the user an auth request is for (see peekAuthIdentity).
type authIdentity struct {
	email     string
	password  string // a login's, never empty; "" for a refresh
	accountID int64  // a refresh token's; 0 for a login
}

// peekAuthIdentity reads the user an auth request is for without consuming the request: the
// email and password of a login body, or the subject of the (valid) token a refresh body
// carries. The body is put back for the backend, and read as the backend reads it (the
// first JSON value, into the fields the endpoint decodes) so the two cannot disagree on
// whose request it is. No email when the request names nobody the proxy can route by: no
// body, a body the backend refuses before looking anyone up (not JSON, a field of the
// wrong type, no email, a login without a password, a refresh without a token), another
// path, or a method other than POST, which the backend answers 405 before reading the
// body. A backend then answers it from the request alone, whatever the lookup knows of
// the address. A refresh token the proxy refuses is errRefreshTokenRefused. A refresh also
// carries its token's account ID, for local-fallback ownership checks.
func (s *Server) peekAuthIdentity(r *http.Request) (authIdentity, error) {
	if r.Method != http.MethodPost || r.Body == nil || r.Body == http.NoBody {
		return authIdentity{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAuthBodyBytes+1))
	r.Body.Close()
	if err != nil {
		return authIdentity{}, fmt.Errorf("reading auth request body: %w", err)
	}
	if len(body) > maxAuthBodyBytes {
		return authIdentity{}, errAuthBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	switch r.URL.Path {
	case "/user/auth/login":
		// Decode only fields the login endpoint uses (userapi.LoginRequest). A
		// refresh-only field must stay unknown here, just as it is to the backend's
		// login decoder.
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if json.NewDecoder(bytes.NewReader(body)).Decode(&req) != nil || req.Password == "" {
			return authIdentity{}, nil
		}
		return authIdentity{email: strings.TrimSpace(req.Email), password: req.Password}, nil
	case "/user/auth/refresh":
		var req struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(bytes.NewReader(body)).Decode(&req) != nil || req.Token == "" {
			return authIdentity{}, nil
		}
		claims, err := s.validateToken(req.Token)
		if err != nil {
			return authIdentity{}, fmt.Errorf("%w: %w", errRefreshTokenRefused, err)
		}
		if claims.AccountID <= 0 {
			return authIdentity{}, fmt.Errorf("%w: refresh token has no valid account ID", errRefreshTokenRefused)
		}
		if strings.TrimSpace(claims.Email) == "" {
			return authIdentity{}, fmt.Errorf("%w: refresh token has no usable email", errRefreshTokenRefused)
		}
		return authIdentity{email: claims.Email, accountID: claims.AccountID}, nil
	}
	return authIdentity{}, nil
}

// backendRoute is where a request goes and how its backend leg is spoken: with named
// pools a pool route uses that pool's settings; every other route (a lookup pin, a flat
// remote_addrs list) uses the proxy server's own, as before pools.
type backendRoute struct {
	addr          string
	pool          string
	tls           bool
	tlsVerify     bool
	proxyProtocol bool
}

// poolRoute is a route to addr, a member of pool.
func (s *Server) poolRoute(addr string, pool proxy.PoolInfo) backendRoute {
	if !pool.Named {
		return s.serverRoute(addr)
	}
	return backendRoute{addr: addr, pool: pool.Name, tls: pool.Settings.TLS, tlsVerify: pool.Settings.TLSVerify, proxyProtocol: pool.Settings.UseProxyProtocol}
}

// serverRoute is a route to addr with the proxy server's own backend-leg settings.
func (s *Server) serverRoute(addr string) backendRoute {
	pool := ""
	if s.connManager != nil {
		pool = s.connManager.PoolOfBackend(addr)
	}
	return backendRoute{addr: addr, pool: pool, tls: s.remoteTLS, tlsVerify: s.remoteTLSVerify, proxyProtocol: s.remoteUseProxyProtocol}
}

// transportFor is the shared transport that checks a route's backend certificate as the
// route's remote_tls_verify says (roots and name follow the backend dialed).
func (s *Server) legacyTransportFor(route backendRoute) http.RoundTripper {
	if t, ok := s.transports[route.tlsVerify]; ok {
		return t
	}
	return s.transport
}

// getBackendForUser determines the backend for a request carrying the user's token.
// ctx should be the request context so a hung remotelookup cannot outlive the request;
// it is additionally bounded by the remotelookup timeout.
func (s *Server) getBackendForUser(ctx context.Context, email string, accountID int64) (backendRoute, error) {
	return s.routeUser(ctx, email, accountID, false)
}

// routeUser determines the backend for a user: the pool the lookup answered with (cached
// for positive_ttl), then affinity inside that pool, then consistent hash inside it. An
// explicit server in the lookup answer is a hard pin, as on every other proxy; an affinity
// entry outside the user's pool is dropped, which is how a user the lookup moved to another
// pool lands there.
//
// With named pools, routing never guesses: a lookup that fails, or answers nothing usable,
// is refused rather than routed into the default pool, because the backends trust the
// token's account ID and a backend of another pool holds another tenant's account under
// it. With lookup_local_users, a JWT request the lookup does not know also has to
// identify an active local account before it can enter the default pool.
//
// A user the lookup does not know (without lookup_local_users) or refuses is
// errUserRefused, with named pools or a flat remote_addrs list. A flat list is one pool:
// a lookup that fails still routes into it, as before pools.
//
// A backend in maintenance is never picked. A pin to one routes the user among that
// backend's own siblings (refused if its named pool cannot be identified) without
// setting affinity, so the pin takes the user back when maintenance ends; an affinity to
// one is dropped and the user routed afresh, so the new affinity keeps them there after it.
// A backend marked unhealthy (three failed connections in a row) is passed over the same
// way by affinity and consistent hash, but not by a pin: the lookup's answer is
// definitive, as on the other proxies.
//
// forAuth is set for a login or refresh, which carries no token yet: anyone can name any
// user in one, so it reads affinity but never writes it (no gossip per made-up user).
func (s *Server) routeUser(ctx context.Context, email string, accountID int64, forAuth bool) (backendRoute, error) {
	named := s.connManager.HasNamedPools()
	poolName := ""
	havePool := false
	notFound := false         // the lookup does not know this user
	pinInMaintenance := false // the lookup pins a backend in maintenance: routed among its siblings below

	// 1. Lookup cache: an explicit server, the pool the lookup named, or "not found".
	if s.lookupCache != nil {
		cached, found := s.lookupCache.Get(s.name, email)
		switch {
		case !found:
		case cached.IsNegative:
			logger.Debug("User API Proxy: Cached: not known to the remote lookup", "name", s.name, "user", email)
			notFound, havePool = true, true
		case cached.ServerAddress == "":
			logger.Debug("User API Proxy: Using cached pool", "name", s.name, "user", email, "pool", cached.PoolName, "age", time.Since(cached.CreatedAt))
			poolName, havePool = cached.PoolName, true
		case !s.connManager.AllowRemoteLookupBackend(cached.ServerAddress):
			if named {
				return backendRoute{}, fmt.Errorf("%w: cached pin is outside the configured pools", proxy.ErrRouteLookupFailed)
			}
			// restrict_to_pool re-validates the cached address against the pool (a stale
			// entry surviving a pool shrink); a passthrough when the feature is off.
			// Refused: ask the lookup again below.
		case s.connManager.InMaintenance(cached.ServerAddress):
			logger.Debug("User API Proxy: Cached backend in maintenance - routing among its siblings", "name", s.name, "user", email, "backend", cached.ServerAddress)
			poolName, havePool, pinInMaintenance = s.connManager.PoolOfBackend(cached.ServerAddress), true, true
			if named && poolName == "" {
				return backendRoute{}, fmt.Errorf("%w: cached pin in maintenance has no pool", proxy.ErrRouteLookupFailed)
			}
		default:
			// NOTE: We do NOT refresh routing cache. Entries should expire after
			// positive_ttl to allow periodic revalidation via remotelookup, so that when
			// a domain moves backends, active users eventually pick up the new backend.
			logger.Debug("User API Proxy: Using cached route", "name", s.name, "user", email, "backend", cached.ServerAddress, "age", time.Since(cached.CreatedAt))
			metrics.LookupCacheResults.WithLabelValues("userapi_proxy", "hit").Inc()
			return s.serverRoute(cached.ServerAddress), nil
		}
		if havePool {
			metrics.LookupCacheResults.WithLabelValues("userapi_proxy", "hit").Inc()
		} else {
			if found {
				logger.Debug("User API Proxy: Cache miss (refused entry)", "name", s.name, "user", email)
			}
			metrics.LookupCacheResults.WithLabelValues("userapi_proxy", "miss").Inc()
		}
	}

	// 2. Remote lookup, route-only: the JWT, or the backend's own login, authenticates.
	if !havePool && s.routingLookup != nil {
		// Bound the lookup: a hung remotelookup service must not block the request handler
		// until (and unless) the HTTP client's own timeout fires.
		lookupCtx, lookupCancel := context.WithTimeout(ctx, s.connManager.GetRemoteLookupTimeout())
		defer lookupCancel()

		clientIP, _ := ctx.Value(clientIPKey).(string) // set by the handler; "" when unknown
		routingInfo, result, err := s.routingLookup.LookupUserRouteWithClientIP(lookupCtx, email, "", clientIP, true)
		switch {
		case err != nil:
			logger.Warn("User API Proxy: RemoteLookup failed", "name", s.name, "user", email, "error", err)
			if named {
				return backendRoute{}, fmt.Errorf("%w: %w", proxy.ErrRouteLookupFailed, err)
			}
			// A flat list is one pool: route into it, as before pools; nothing is cached.
		case routingInfo == nil && result == proxy.AuthUserNotFound:
			s.cacheRoute(email, &lookupcache.CacheEntry{AccountID: accountID, IsNegative: true})
			notFound = true
		case routingInfo == nil && result == proxy.AuthFailed:
			// 401/403: the lookup refuses the account, a verdict and not an outage, with
			// no fallback, a flat list included. Not cached, as the lookup client caches
			// no refusal.
			return backendRoute{}, fmt.Errorf("%w: %w", errUserRefused, proxy.ErrRemoteLookupRefused)
		case routingInfo == nil:
			logger.Warn("User API Proxy: RemoteLookup gave no route", "name", s.name, "user", email, "result", result)
			if named {
				return backendRoute{}, fmt.Errorf("%w: no route in the answer", proxy.ErrRouteLookupFailed)
			}
		case routingInfo.ServerAddress != "":
			// restrict_to_pool (SSRF defense): AllowRemoteLookupBackend logs and returns
			// false for an out-of-pool address, which then falls through to in-pool routing
			// below — the bad address is never dialed.
			if !s.connManager.AllowRemoteLookupBackend(routingInfo.ServerAddress) {
				if named {
					return backendRoute{}, fmt.Errorf("%w: pin is outside the configured pools", proxy.ErrRouteLookupFailed)
				}
				break
			}
			// The answer is cached as given, in maintenance or not: routing decides each
			// time, so the pin returns the user to its backend once maintenance ends.
			s.cacheRoute(email, &lookupcache.CacheEntry{AccountID: accountID, ServerAddress: routingInfo.ServerAddress})
			if s.connManager.InMaintenance(routingInfo.ServerAddress) {
				logger.Info("User API Proxy: Remote lookup backend in maintenance - routing among its siblings", "name", s.name, "user", email, "backend", routingInfo.ServerAddress)
				poolName, havePool, pinInMaintenance = s.connManager.PoolOfBackend(routingInfo.ServerAddress), true, true
				if named && poolName == "" {
					return backendRoute{}, fmt.Errorf("%w: pin in maintenance has no pool", proxy.ErrRouteLookupFailed)
				}
				break
			}
			logger.Debug("User API Proxy: Using remotelookup backend", "name", s.name, "user", email, "backend", routingInfo.ServerAddress)
			if s.affinityManager != nil && !forAuth {
				s.affinityManager.SetBackend(email, routingInfo.ServerAddress, "userapi")
			}
			return s.serverRoute(routingInfo.ServerAddress), nil
		default:
			poolName, havePool = routingInfo.PoolName, true
			s.cacheRoute(email, &lookupcache.CacheEntry{AccountID: accountID, PoolName: routingInfo.PoolName})
		}
	}
	if notFound && !s.lookupLocalUsers {
		// With a flat list too: its backends would log the user in from their database.
		return backendRoute{}, fmt.Errorf("%w: not known to the remote lookup, and lookup_local_users is off", errUserRefused)
	}
	if notFound && named {
		// A valid JWT from another pool may carry the ID of an unrelated local
		// account. A lookup miss is not evidence that its owner is a local user.
		// Logins are authenticated by the backend. Requests carrying a token,
		// including refreshes, need this check on every fallback, including
		// negative-cache hits; the routing cache cannot establish local ownership.
		if !forAuth || accountID != 0 {
			if s.rdb == nil {
				return backendRoute{}, fmt.Errorf("cannot verify local token ownership without a local database")
			}
			localCtx, cancel := context.WithTimeout(ctx, s.rdb.GetQueryTimeout())
			defer cancel()
			localID, err := s.rdb.GetActiveAccountIDByAddressWithRetry(localCtx, email)
			if err != nil || accountID <= 0 || localID != accountID {
				return backendRoute{}, fmt.Errorf("token does not identify an active local account")
			}
		}
	}

	// 3. Inside the pool: affinity, then consistent hash.
	pool, err := s.connManager.ResolvePool(poolName)
	if err != nil {
		outcome := "unknown_pool"
		if errors.Is(err, proxy.ErrNoDefaultPool) {
			outcome = "no_default"
		} else if errors.Is(err, proxy.ErrAmbiguousBackendPool) {
			outcome = "ambiguous_pool"
		}
		metrics.ProxyPoolRoute.WithLabelValues("userapi", proxy.PoolRouteLabel(poolName, err), outcome).Inc()
		logger.Error("User API Proxy: No backend pool for route - refusing to route elsewhere", "name", s.name, "user", email, "pool", poolName, "error", err)
		return backendRoute{}, err
	}
	if pool.Named {
		metrics.ProxyPoolRoute.WithLabelValues("userapi", pool.Name, "routed").Inc()
	}

	if s.affinityManager != nil {
		if backend, found := s.affinityManager.GetBackend(email, "userapi"); found {
			// Affinity is gossip-synced and persisted: honor it only inside the user's pool
			// (a user the lookup moved to another pool must not follow a stale entry), only
			// when restrict_to_pool allows it (a poisoned entry from another node), never
			// to a backend in maintenance, and never to one marked unhealthy. Health is read
			// without auto-recovery, as the other proxies' affinity does: a user who failed
			// over stays on the new backend when the old one comes back.
			if s.connManager.PoolHasBackend(pool.Name, backend) && s.connManager.AllowRemoteLookupBackend(backend) &&
				!s.connManager.InMaintenance(backend) && s.connManager.IsBackendHealthyForAffinity(backend) {
				logger.Debug("User API Proxy: Using affinity backend", "name", s.name, "user", email, "backend", backend, "pool", pool.Name)
				return s.poolRoute(backend, pool), nil
			}
			if !forAuth {
				logger.Info("User API Proxy: Affinity backend not in the user's pool, in maintenance or unhealthy - deleting affinity", "name", s.name, "user", email, "backend", backend, "pool", pool.Name)
				s.affinityManager.DeleteBackend(email, "userapi")
			}
		}
	}

	backendAddr := s.connManager.GetBackendByConsistentHashInPool(pool.Name, email)
	if backendAddr == "" {
		return backendRoute{}, fmt.Errorf("no backend available in pool %q", pool.Name)
	}
	logger.Debug("User API Proxy: Using consistent hash backend", "name", s.name, "user", email, "backend", backendAddr, "pool", pool.Name)

	// Set affinity for future requests. Not for a detour around a remote-lookup pin in
	// maintenance: the pin, not affinity, is what routes that user once maintenance ends.
	// Not for a login either: it is not yet anyone's request (see forAuth).
	if s.affinityManager != nil && !pinInMaintenance && !forAuth {
		s.affinityManager.SetBackend(email, backendAddr, "userapi")
	}
	return s.poolRoute(backendAddr, pool), nil
}

// cacheRoute remembers a lookup answer for the configured positive TTL (negative TTL for
// a user the lookup does not know), if the lookup cache is enabled.
func (s *Server) cacheRoute(email string, entry *lookupcache.CacheEntry) {
	if s.lookupCache == nil {
		return
	}
	// ExpiresAt left zero: Set applies the configured TTL
	s.lookupCache.Set(s.name, email, entry)
}

// proxyRequest proxies the request to the backend. login is the login attempt r is, if
// the rate limit counts it (routeAuthRequest), else nil.
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, route backendRoute, login *loginAttempt) {
	binding, err := s.connManager.BindBackendRoute(route.pool, route.addr)
	if err != nil {
		s.writeError(w, r, "Backend route unavailable", http.StatusServiceUnavailable)
		return
	}
	transport, err := s.transportFor(route, binding)
	if err != nil {
		s.writeError(w, r, "Backend route unavailable", http.StatusServiceUnavailable)
		return
	}
	// Create reverse proxy to backend
	scheme := "http"
	if route.tls {
		scheme = "https"
	}

	// A backend without a port takes the scheme's port. A bare IPv6 literal must then be
	// bracketed, or the URL reads its last group as the port.
	host := route.addr
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		host = "[" + host + "]"
	}
	target, err := url.Parse(fmt.Sprintf("%s://%s", scheme, host))
	if err != nil {
		logger.Warn("User API Proxy: Failed to parse backend URL", "name", s.name, "error", err)
		s.writeError(w, r, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy with shared transport (prevents connection pool leaks)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	// The backend did not answer (the default handler's bare 502): ReverseProxy calls this
	// before it has copied any backend header, so the response is the proxy's own.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Warn("User API Proxy: Backend request failed", "name", s.name, "backend", route.addr, "error", err)
		s.writeError(w, r, "Bad gateway", http.StatusBadGateway)
	}
	// A login's verdict is the backend's answer: 200 a success, 401 a wrong password or an
	// address without an account. Any other answer (a malformed request, a temporary
	// failure) says nothing of the password and is not counted, as on a backend.
	if login != nil {
		proxy.ModifyResponse = func(resp *http.Response) error {
			switch resp.StatusCode {
			case http.StatusOK:
				s.recordLogin(resp.Request.Context(), login, true)
			case http.StatusUnauthorized:
				s.recordLogin(resp.Request.Context(), login, false)
			}
			return nil
		}
	}

	// Modify request. Capture the original Host BEFORE overwriting r.Host:
	// the Host of an incoming request lives in r.Host, not in r.Header
	// ("Host" is never present in r.Header), so the previous
	// r.Header.Get("Host") always produced an empty X-Forwarded-Host.
	originalHost := r.Host
	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.Header.Set("X-Forwarded-Host", originalHost)
	r.Host = target.Host

	// Get real client IP (from PROXY protocol or RemoteAddr)
	realClientIP := s.getRealClientIP(r)

	// Forward real client IP to backend in X-Forwarded-For and X-Real-IP headers.
	// The sora User API backend does not read them: it learns the client address
	// only from the PROXY protocol header (remote_use_proxy_protocol).
	r.Header.Set("X-Real-IP", realClientIP)
	r.Header.Set("X-Forwarded-For", realClientIP)

	// Inject client IP and port into context for transport.DialContext to pick up
	ctx := r.Context()
	ctx = context.WithValue(ctx, backendRouteKey, binding)
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			ctx = context.WithValue(ctx, clientIPKey, host)
			ctx = context.WithValue(ctx, clientPortKey, port)
		}
	}
	ctx = context.WithValue(ctx, proxyProtocolKey, route.proxyProtocol)
	if login != nil {
		// The backend's answer is counted whether or not the client waits for it, as the
		// proxy's own refusal of a login is (routeAuthRequest): cancelled with the client,
		// a login that left before the backend answered went uncounted, and the rate limit
		// alone showed which addresses the lookup knows. Bounded by writeTimeout, past
		// which no answer reaches a client. (Without a deadline the context could never
		// be done, and ReverseProxy would cancel it on the client's close itself.)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
	}
	r = r.WithContext(ctx)

	// Keep Authorization header for backend JWT validation
	// Backend always validates the JWT token

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// validateToken validates a JWT token and returns the claims
func (s *Server) validateToken(tokenString string) (*JWTClaims, error) {
	// Pin the algorithm to HS256 and require an exp claim. Issuer validation is left
	// to the backend (authoritative), which has the configured issuer; the proxy only
	// validates enough to route.
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.settings.Load().jwtSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// The refusals of extractAndValidateToken that writeUnauthorized tells apart.
var (
	errNoAuthHeader  = errors.New("authorization header required")
	errNotBearerAuth = errors.New("authorization header must be 'Bearer <token>'")
)

// writeUnauthorized answers r, whose token extractAndValidateToken refused with err, as
// the User API answers the same refusal (userapi jwtAuthMiddleware), so a token the proxy
// refuses is answered as a backend answers it: the same message and the same Bearer
// challenge, which RFC 9110 section 15.5.2 requires on every 401. A request without a
// bearer token gets the challenge without an error code, a refused token
// error="invalid_token" (RFC 6750 section 3.1).
func (s *Server) writeUnauthorized(w http.ResponseWriter, r *http.Request, err error) {
	msg, tokenRefused := "Invalid or expired token", true
	switch {
	case errors.Is(err, errNoAuthHeader):
		msg, tokenRefused = "Authorization header required", false
	case errors.Is(err, errNotBearerAuth):
		msg, tokenRefused = "Authorization header must be 'Bearer <token>'", false
	}
	server.SetBearerChallenge(w.Header(), server.UserAPIRealm, tokenRefused)
	s.writeError(w, r, msg, http.StatusUnauthorized)
}

// extractAndValidateToken extracts and validates JWT token from request
func (s *Server) extractAndValidateToken(r *http.Request) (*JWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errNoAuthHeader
	}

	// Extract token from "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, errNotBearerAuth
	}

	tokenString := parts[1]

	// Validate token
	claims, err := s.validateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}

// getRealClientIP extracts the real client IP from the request.
// When PROXY protocol is enabled, the shared HTTP PROXY listener conn overrides RemoteAddr()
// with the real client address, so r.RemoteAddr already carries it here.
func (s *Server) getRealClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If splitting fails, return as-is
		return r.RemoteAddr
	}
	return host
}

// connStateHandler handles connection state changes for tracking
func (s *Server) connStateHandler(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		// Check connection limits
		if s.limiter != nil {
			release, err := s.limiter.AcceptWithRealIP(conn.RemoteAddr(), "")
			if err != nil {
				logger.Info("User API Proxy: Connection rejected", "name", s.name, "error", err)
				conn.Close()
				return
			}
			// Remember the release callback so the limiter slot is freed when the
			// connection closes (see connReleases doc). Previously the callback was
			// discarded, leaking a slot per connection.
			s.connReleasesMu.Lock()
			s.connReleases[conn] = release
			s.connReleasesMu.Unlock()
		}
	case http.StateClosed, http.StateHijacked:
		// Connection is gone — free the limiter slot. StateHijacked is also
		// terminal for the ConnState hook, so release here too to avoid a leak.
		// release() is sync.Once-guarded, so calling it once here is safe.
		s.connReleasesMu.Lock()
		release := s.connReleases[conn]
		delete(s.connReleases, conn)
		s.connReleasesMu.Unlock()
		if release != nil {
			release()
		}
	}
}

// GetConnectionManager returns the connection manager for health checks
func (s *Server) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

// Stop stops the User API proxy server
// ReloadConfig updates runtime-configurable settings from new config.
func (s *Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string
	var refused error
	next := *s.settings.Load()

	if cfg.JWTSecret != "" && cfg.JWTSecret != next.jwtSecret {
		if err := checkJWTSecret(cfg.JWTSecret); err != nil {
			// The rest still reloads. The error has the caller log a failed reload, so an
			// operator rotating a leaked secret learns that the old one is still live.
			refused = fmt.Errorf("jwt_secret refused, the previous one stays in use: %w", err)
		} else {
			next.jwtSecret = cfg.JWTSecret
			reloaded = append(reloaded, "jwt_secret")
		}
	}
	// Reload receives the complete config, so an empty or removed list means what it does
	// at startup: the proxy's own responses authorize no origin.
	if !slices.Equal(cfg.AllowedOrigins, next.allowedOrigins) {
		next.allowedOrigins = slices.Clone(cfg.AllowedOrigins)
		reloaded = append(reloaded, "allowed_origins")
	}

	if len(reloaded) > 0 {
		s.settings.Store(&next)
		logger.Info("User API proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return refused
}

func (s *Server) Stop() error {
	logger.Info("User API Proxy: Stopping", "name", s.name)

	s.cancel()
	s.closeBackendIdleConnections()

	// HTTP server shutdown is handled by the graceful shutdown goroutine
	// Wait for it to complete
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("User API Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Warn("User API Proxy: Server stop timeout", "name", s.name)
	}

	return nil
}
