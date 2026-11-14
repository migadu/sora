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
			logger.Warn("User API Proxy: Failed to initialize remotelookup client", "name", opts.Name, "error", err)
			if len(opts.Pools) > 0 || !opts.RemoteLookup.ShouldLookupLocalUsers() {
				cancel()
				return nil, fmt.Errorf("remotelookup initialization failed: %w", err)
			}
			logger.Info("User API Proxy: Continuing with consistent hash fallback", "name", opts.Name)
		} else {
			routingLookup = remotelookupClient
			logger.Info("User API Proxy: RemoteLookup enabled", "name", opts.Name)
		}
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
	// The TLS leg is set up here rather than by the transport, with the connection
	// manager's config for the address dialed (proxy.BackendClientTLS): a pool member is
	// verified against its pool's CA file, and by the name it was configured with although
	// the transport dials the address that name resolved to.
	newTransport := func(verify bool) *http.Transport {
		return &http.Transport{
			DialContext: dialBackend,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
			},
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

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("User API Proxy: Route lookup cache enabled", "name", opts.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	s := &Server{
		name:                       opts.Name,
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
		WriteTimeout: 30 * time.Second,
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
	// which is what allowed_hosts and rate limiting read via r.RemoteAddr.
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
		metrics.ConnectionsTotal.WithLabelValues("userapi_proxy", s.name, "").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, "").Inc()
		defer metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, "").Dec()

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
				s.writeError(w, r, "Unauthorized", http.StatusUnauthorized)
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
			s.proxyRequest(w, r, route)
			return
		}

		// Auth endpoints and CORS preflights carry no JWT. A login names its user in the
		// body and a refresh carries the user's token, so both are routed like any other
		// request for that user: the account lives on a backend of the user's pool. A
		// request that names nobody, such as a preflight, goes to the default pool by path
		// hash, as before pools; without a default pool it is refused. The backend handles
		// rate limiting, and answers a preflight with its CORS policy (allowed_origins).
		route, err := s.routeAuthRequest(r)
		if err != nil {
			if errors.Is(err, errAuthBodyTooLarge) {
				s.writeError(w, r, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "path", r.URL.Path, "error", err)
			s.writeError(w, r, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Proxy unauthenticated request
		s.proxyRequest(w, r, route)
	})
}

// writeError answers r with an error the proxy writes itself, no backend having answered.
// It carries the CORS headers of the proxy's allowed_origins, as the backend's own errors
// carry the backend's: without them a browser hands the page a network error instead of
// the status, and a web client cannot tell an expired token from an outage. A forwarded
// response carries the backend's CORS headers and must get none here.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	server.SetCORSHeaders(w.Header(), r.Header.Get("Origin"), s.settings.Load().allowedOrigins)
	http.Error(w, msg, code)
}

// isCORSPreflight reports whether r is a CORS-preflight request: an OPTIONS request with
// Access-Control-Request-Method (Fetch Standard, "HTTP requests"). A browser sends one
// before a cross-origin call that carries Authorization and never puts credentials on it,
// so it cannot be held to the JWT check; the backend answers it without touching any
// account, as it does when it is reached directly.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// maxAuthBodyBytes bounds how much of an auth request body the proxy reads to find the
// user it is for; a login or refresh body is a few hundred bytes.
const maxAuthBodyBytes = 64 << 10

var errAuthBodyTooLarge = errors.New("auth request body too large")

// routeAuthRequest picks the backend for an unauthenticated auth request.
func (s *Server) routeAuthRequest(r *http.Request) (backendRoute, error) {
	email, tokenAccountID, err := s.peekAuthIdentity(r)
	if err != nil {
		return backendRoute{}, err
	}
	if email != "" {
		return s.routeUser(r.Context(), email, tokenAccountID, true)
	}
	// Names nobody: the backend answers the malformed request itself, wherever it lands.
	pool, err := s.connManager.ResolvePool("")
	if err != nil {
		return backendRoute{}, err
	}
	addr := s.connManager.GetBackendByConsistentHashInPool(pool.Name, r.URL.Path)
	if addr == "" {
		return backendRoute{}, fmt.Errorf("no backend available")
	}
	return s.poolRoute(addr, pool), nil
}

// peekAuthIdentity reads the user an auth request is for without consuming the request: the
// email of a login body, or the subject of the (valid) token a refresh body carries. The
// body is put back for the backend, and read as the backend reads it (the first JSON value)
// so the two cannot disagree on whose request it is. "" when the body names nobody the
// proxy can route by; the backend then answers the malformed request itself.
// A refresh also carries its token's account ID, for local-fallback ownership checks.
func (s *Server) peekAuthIdentity(r *http.Request) (string, int64, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", 0, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAuthBodyBytes+1))
	r.Body.Close()
	if err != nil {
		return "", 0, fmt.Errorf("reading auth request body: %w", err)
	}
	if len(body) > maxAuthBodyBytes {
		return "", 0, errAuthBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	switch r.URL.Path {
	case "/user/auth/login":
		// Decode only fields the login endpoint uses. A refresh-only field must
		// stay unknown here, just as it is to the backend's login decoder.
		var req struct {
			Email string `json:"email"`
		}
		if json.NewDecoder(bytes.NewReader(body)).Decode(&req) != nil {
			return "", 0, nil
		}
		return strings.TrimSpace(req.Email), 0, nil
	case "/user/auth/refresh":
		var req struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(bytes.NewReader(body)).Decode(&req) != nil {
			return "", 0, nil
		}
		if claims, err := s.validateToken(req.Token); err == nil {
			if claims.AccountID <= 0 {
				return "", 0, fmt.Errorf("refresh token has no valid account ID")
			}
			return claims.Email, claims.AccountID, nil
		}
	}
	return "", 0, nil
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
// A backend in maintenance is never picked. A pin to one routes the user among that
// backend's own siblings (refused if its named pool cannot be identified) without
// setting affinity, so the pin takes the user back when maintenance ends; an affinity to
// one is dropped and the user routed afresh, so the new affinity keeps them there after it.
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
			metrics.LookupCacheHitsTotal.Inc()
			return s.serverRoute(cached.ServerAddress), nil
		}
		if havePool {
			metrics.LookupCacheHitsTotal.Inc()
		} else {
			if found {
				logger.Debug("User API Proxy: Cache miss (refused entry)", "name", s.name, "user", email)
			}
			metrics.LookupCacheMissesTotal.Inc()
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
	if notFound && named {
		if !s.lookupLocalUsers {
			return backendRoute{}, fmt.Errorf("user is not known to the remote lookup, and lookup_local_users is off")
		}
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
			// when restrict_to_pool allows it (a poisoned entry from another node), and
			// never to a backend in maintenance.
			if s.connManager.PoolHasBackend(pool.Name, backend) && s.connManager.AllowRemoteLookupBackend(backend) && !s.connManager.InMaintenance(backend) {
				logger.Debug("User API Proxy: Using affinity backend", "name", s.name, "user", email, "backend", backend, "pool", pool.Name)
				return s.poolRoute(backend, pool), nil
			}
			if !forAuth {
				logger.Info("User API Proxy: Affinity backend not in the user's pool or in maintenance - deleting affinity", "name", s.name, "user", email, "backend", backend, "pool", pool.Name)
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

// proxyRequest proxies the request to the backend
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, route backendRoute) {
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

	// Forward real client IP to backend in X-Forwarded-For and X-Real-IP headers
	// Backend should trust these headers from trusted proxy networks
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

// extractAndValidateToken extracts and validates JWT token from request
func (s *Server) extractAndValidateToken(r *http.Request) (*JWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header required")
	}

	// Extract token from "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, fmt.Errorf("authorization header must be 'Bearer <token>'")
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
