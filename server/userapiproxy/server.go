package userapiproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
	clientIPKey   contextKey = "client-ip"
	clientPortKey contextKey = "client-port"
)

// JWTClaims represents the JWT token claims (must match userapi.JWTClaims)
type JWTClaims struct {
	Email     string `json:"email"`
	AccountID int64  `json:"account_id"`
	jwt.RegisteredClaims
}

// Server represents a User API proxy server
type Server struct {
	name                       string
	addr                       string
	connManager                *proxy.ConnectionManager
	rdb                        *resilient.ResilientDatabase
	routingLookup              proxy.UserRoutingLookup  // RemoteLookup client for user routing (optional)
	affinityManager            *server.AffinityManager  // Affinity manager for sticky routing (optional)
	lookupCache                *lookupcache.LookupCache // Route lookup cache (optional)
	positiveRevalidationWindow time.Duration            // Revalidation window for cached routes
	jwtSecret                  string                   // JWT secret for token validation
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

	// Shared HTTP transport (prevents connection pool leaks)
	transport *http.Transport

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader
}

// ServerOptions holds configuration options for the User API proxy server
type ServerOptions struct {
	Name                     string
	Addr                     string
	RemoteAddrs              []string
	RemotePort               int    // Default port for backends if not in address
	JWTSecret                string // JWT secret for token validation
	TLS                      bool
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS                bool
	RemoteTLSVerify          bool
	ConnectTimeout           time.Duration
	EnableBackendHealthCheck bool                       // Enable backend health checking (default: true)
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

// New creates a new User API proxy server
func New(appCtx context.Context, rdb *resilient.ResilientDatabase, opts ServerOptions) (*Server, error) {
	ctx, cancel := context.WithCancel(appCtx)

	if len(opts.RemoteAddrs) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses configured")
	}

	if opts.JWTSecret == "" {
		cancel()
		return nil, fmt.Errorf("JWT secret is required for User API proxy")
	}
	if len(opts.JWTSecret) < 32 {
		cancel()
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes for HS256 (RFC 7518 §3.2); got %d", len(opts.JWTSecret))
	}
	if opts.JWTSecret == "your-secret-jwt-signing-key-here" {
		cancel()
		return nil, fmt.Errorf("JWT secret is the placeholder value from config.toml.example — set a real, random jwt_secret")
	}

	// Set default timeout if not specified
	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Initialize remotelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.RemoteLookup != nil && opts.RemoteLookup.Enabled {
		remotelookupClient, err := proxy.InitializeRemoteLookup("userapi", opts.RemoteLookup)
		if err != nil {
			logger.Warn("User API Proxy: Failed to initialize remotelookup client", "name", opts.Name, "error", err)
			if !opts.RemoteLookup.ShouldLookupLocalUsers() {
				cancel()
				return nil, fmt.Errorf("remotelookup initialization failed and local lookup disabled: %w", err)
			}
			logger.Info("User API Proxy: Continuing with consistent hash fallback", "name", opts.Name)
		} else {
			routingLookup = remotelookupClient
			logger.Info("User API Proxy: RemoteLookup enabled", "name", opts.Name)
		}
	}

	// Create connection manager with routing lookup
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, false, opts.RemoteTLSVerify, false, connectTimeout, routingLookup, opts.Name, !opts.EnableBackendHealthCheck)
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

	// Create shared HTTP transport (reused for all proxied requests to prevent connection pool leaks)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !opts.RemoteTLSVerify,
			Renegotiation:      tls.RenegotiateNever,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{
				Timeout:   connectTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if opts.RemoteUseProxyProtocol {
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
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

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
	if opts.LookupCache != nil && opts.LookupCache.Enabled {
		lookupCacheConfig := opts.LookupCache

		positiveTTL, err := time.ParseDuration(lookupCacheConfig.PositiveTTL)
		if err != nil || lookupCacheConfig.PositiveTTL == "" {
			logger.Info("User API Proxy: Using default positive TTL (5m)", "name", opts.Name)
			positiveTTL = 5 * time.Minute
		}

		negativeTTL, err := time.ParseDuration(lookupCacheConfig.NegativeTTL)
		if err != nil || lookupCacheConfig.NegativeTTL == "" {
			logger.Info("User API Proxy: Using default negative TTL (1m)", "name", opts.Name)
			negativeTTL = 1 * time.Minute
		}

		cleanupInterval, err := time.ParseDuration(lookupCacheConfig.CleanupInterval)
		if err != nil || lookupCacheConfig.CleanupInterval == "" {
			logger.Info("User API Proxy: Using default cleanup interval (5m)", "name", opts.Name)
			cleanupInterval = 5 * time.Minute
		}

		maxSize := lookupCacheConfig.MaxSize
		if maxSize == 0 {
			maxSize = 10000
		}

		positiveRevalidationWindow, err = lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("User API Proxy: Invalid positive revalidation window in lookup cache config, using default (30s)", "name", opts.Name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("User API Proxy: Route lookup cache enabled", "name", opts.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	return &Server{
		name:                       opts.Name,
		addr:                       opts.Addr,
		connManager:                connManager,
		rdb:                        rdb,
		routingLookup:              routingLookup,
		affinityManager:            opts.AffinityManager,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		jwtSecret:                  opts.JWTSecret,
		tls:                        opts.TLS,
		tlsCertFile:                opts.TLSCertFile,
		tlsKeyFile:                 opts.TLSKeyFile,
		tlsVerify:                  opts.TLSVerify,
		tlsConfig:                  opts.TLSConfig,
		trustedProxies:             opts.TrustedProxies,
		limiter:                    limiter,
		transport:                  transport,
		proxyReader:                proxyReader,
		ctx:                        ctx,
		cancel:                     cancel,
		connReleases:               make(map[net.Conn]func()),
	}, nil
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

	// Configure TLS
	if s.tls && s.tlsCertFile != "" && s.tlsKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		clientAuth := tls.NoClientCert
		if s.tlsVerify {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		s.httpServer.TLSConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			PreferServerCipherSuites: true,
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if s.tls && s.tlsConfig != nil {
		// Scenario 2: Global TLS manager
		s.httpServer.TLSConfig = s.tlsConfig
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for User API proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
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

	// Wrap listener with PROXY protocol support if enabled
	if s.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: s.proxyReader,
		}
	}

	// Start serving
	if s.tls {
		return s.httpServer.ServeTLS(listener, s.tlsCertFile, s.tlsKeyFile)
	}
	return s.httpServer.Serve(listener)
}

// setupHandler creates the HTTP handler with reverse proxy logic
func (s *Server) setupHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track metrics
		metrics.ConnectionsTotal.WithLabelValues("userapi_proxy", s.name, "").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, "").Inc()
		defer metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy", s.name, "").Dec()

		// Check if this is an authentication endpoint (no JWT required)
		isAuthEndpoint := strings.HasPrefix(r.URL.Path, "/user/auth/")

		if !isAuthEndpoint {
			// Validate JWT token and extract claims for non-auth endpoints
			claims, err := s.extractAndValidateToken(r)
			if err != nil {
				logger.Warn("User API Proxy: Authentication failed", "name", s.name, "path", r.URL.Path, "error", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get backend for this user
			backendAddr, err := s.getBackendForUser(r.Context(), claims.Email, claims.AccountID)
			if err != nil {
				logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "user", claims.Email, "error", err)
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Proxy authenticated request to the user's backend
			s.proxyRequest(w, r, backendAddr)
			return
		}

		// For auth endpoints (login/refresh), use consistent hash with path as key
		// This provides some distribution without needing user info
		// Backend will handle rate limiting
		backendAddr := s.connManager.GetBackendByConsistentHash(r.URL.Path)
		if backendAddr == "" {
			logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "path", r.URL.Path)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Proxy unauthenticated request
		s.proxyRequest(w, r, backendAddr)
	})
}

// getBackendForUser determines the backend server for a user using cache, affinity and remotelookup.
// ctx should be the request context so a hung remotelookup cannot outlive the request;
// it is additionally bounded by the remotelookup timeout below.
func (s *Server) getBackendForUser(ctx context.Context, email string, accountID int64) (string, error) {

	// 1. Check lookup cache first (if enabled)
	if s.lookupCache != nil {
		cached, found := s.lookupCache.Get(s.name, email)
		// AllowRemoteLookupBackend re-validates the cached address against the pool when
		// restrict_to_pool is on (defends against a stale entry surviving a pool shrink);
		// it is a passthrough when the feature is off.
		if found && !cached.IsNegative && s.connManager.AllowRemoteLookupBackend(cached.ServerAddress) {
			// Positive cache entry - use cached route
			// NOTE: We do NOT refresh routing cache. Entries should expire after
			// positive_ttl to allow periodic revalidation via remotelookup.
			// This ensures that when a domain moves backends, active users
			// eventually pick up the new backend.
			logger.Debug("User API Proxy: Using cached route", "name", s.name, "user", email, "backend", cached.ServerAddress, "age", time.Since(cached.CreatedAt))
			metrics.LookupCacheHitsTotal.Inc()
			return cached.ServerAddress, nil
		}
		// Cache miss or negative entry - fall through to lookup
		if found {
			logger.Debug("User API Proxy: Cache miss (negative entry)", "name", s.name, "user", email)
		}
		metrics.LookupCacheMissesTotal.Inc()
	}

	// 2. Check affinity (if configured)
	if s.affinityManager != nil {
		// AllowRemoteLookupBackend gates the affinity address too: affinity is gossip-synced
		// and persisted, so a poisoned/out-of-pool entry from another node must not be dialed
		// when restrict_to_pool is on. Passthrough when the feature is off. On refusal this
		// falls through to consistent hash below.
		if backend, found := s.affinityManager.GetBackend(email, "userapi"); found && s.connManager.AllowRemoteLookupBackend(backend) {
			logger.Debug("User API Proxy: Using affinity backend", "name", s.name, "user", email, "backend", backend)
			// Cache the route if lookup cache is enabled
			if s.lookupCache != nil {
				entry := &lookupcache.CacheEntry{
					AccountID:     accountID,
					ServerAddress: backend,
					CreatedAt:     time.Now(),
					ExpiresAt:     time.Now().Add(5 * time.Minute), // Use positive TTL from cache
				}
				s.lookupCache.Set(s.name, email, entry)
			}
			return backend, nil
		}
	}

	// 3. Use remotelookup if configured
	if s.routingLookup != nil {
		// Bound the lookup: previously this used context.Background() with no
		// timeout, so a hung remotelookup service blocked the request handler
		// until (and unless) the HTTP client's own timeout fired.
		lookupCtx, lookupCancel := context.WithTimeout(ctx, s.connManager.GetRemoteLookupTimeout())
		defer lookupCancel()

		// Use routeOnly=true since user is already authenticated via JWT
		routingInfo, _, err := s.routingLookup.LookupUserRouteWithOptions(lookupCtx, email, "", true)
		if err != nil {
			logger.Warn("User API Proxy: RemoteLookup failed", "name", s.name, "user", email, "error", err)
			// Fall through to consistent hash
		} else if routingInfo != nil && routingInfo.ServerAddress != "" && s.connManager.AllowRemoteLookupBackend(routingInfo.ServerAddress) {
			// restrict_to_pool (SSRF defense): AllowRemoteLookupBackend logs and returns
			// false for an out-of-pool address, so this branch is skipped and routing
			// falls through to consistent hash below — the bad address is never dialed.
			logger.Debug("User API Proxy: Using remotelookup backend", "name", s.name, "user", email, "backend", routingInfo.ServerAddress)

			// Set affinity for future requests
			if s.affinityManager != nil {
				s.affinityManager.SetBackend(email, routingInfo.ServerAddress, "userapi")
			}

			// Cache the route if lookup cache is enabled
			if s.lookupCache != nil {
				entry := &lookupcache.CacheEntry{
					AccountID:     accountID,
					ServerAddress: routingInfo.ServerAddress,
					CreatedAt:     time.Now(),
					ExpiresAt:     time.Now().Add(5 * time.Minute), // Use positive TTL from cache
				}
				s.lookupCache.Set(s.name, email, entry)
			}

			return routingInfo.ServerAddress, nil
		}
	}

	// 4. Fall back to consistent hash
	backendAddr := s.connManager.GetBackendByConsistentHash(email)
	if backendAddr == "" {
		return "", fmt.Errorf("no backend available")
	}

	logger.Debug("User API Proxy: Using consistent hash backend", "name", s.name, "user", email, "backend", backendAddr)

	// Set affinity for future requests
	if s.affinityManager != nil {
		s.affinityManager.SetBackend(email, backendAddr, "userapi")
	}

	// Cache the route if lookup cache is enabled
	if s.lookupCache != nil {
		entry := &lookupcache.CacheEntry{
			AccountID:     accountID,
			ServerAddress: backendAddr,
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(5 * time.Minute), // Use positive TTL from cache
		}
		s.lookupCache.Set(s.name, email, entry)
	}

	return backendAddr, nil
}

// proxyRequest proxies the request to the backend
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, backendAddr string) {
	// Create reverse proxy to backend
	scheme := "http"
	if s.connManager.IsRemoteTLS() {
		scheme = "https"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s", scheme, backendAddr))
	if err != nil {
		logger.Warn("User API Proxy: Failed to parse backend URL", "name", s.name, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy with shared transport (prevents connection pool leaks)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = s.transport

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
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			ctx = context.WithValue(ctx, clientIPKey, host)
			ctx = context.WithValue(ctx, clientPortKey, port)
		}
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
		return []byte(s.jwtSecret), nil
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
// When PROXY protocol is enabled, proxyProtocolConn overrides RemoteAddr()
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

	if cfg.JWTSecret != "" && cfg.JWTSecret != s.jwtSecret {
		s.jwtSecret = cfg.JWTSecret
		reloaded = append(reloaded, "jwt_secret")
	}

	if len(reloaded) > 0 {
		logger.Info("User API proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

func (s *Server) Stop() error {
	logger.Info("User API Proxy: Stopping", "name", s.name)

	s.cancel()

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

// proxyProtocolListener wraps a net.Listener to read PROXY protocol headers
type proxyProtocolListener struct {
	net.Listener
	proxyReader *server.ProxyProtocolReader
}

// Accept wraps the underlying Accept to read PROXY protocol headers
func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Read PROXY protocol header (this validates the connection is from trusted proxy)
	proxyInfo, wrappedConn, err := l.proxyReader.ReadProxyHeader(conn)
	if err != nil {
		// Log with original connection's remote address (the proxy's IP)
		logger.Error("PROXY protocol error", "proxy", "userapi_proxy", "remote", server.GetAddrString(conn.RemoteAddr()), "error", err)
		conn.Close()
		return nil, err
	}

	// Only wrap if we got proxy info - this preserves the real client IP in RemoteAddr()
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		return &proxyProtocolConn{
			Conn:      wrappedConn,
			proxyInfo: proxyInfo,
		}, nil
	}

	// No proxy info, return wrapped connection as-is
	return wrappedConn, nil
}

// proxyProtocolConn wraps a net.Conn to carry PROXY protocol info
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *server.ProxyProtocolInfo
}

// RemoteAddr returns the real client address from PROXY protocol if available
func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	if c.proxyInfo != nil && c.proxyInfo.SrcIP != "" {
		// Return a custom address with the real client IP
		return &net.TCPAddr{
			IP:   net.ParseIP(c.proxyInfo.SrcIP),
			Port: c.proxyInfo.SrcPort,
		}
	}
	return c.Conn.RemoteAddr()
}
