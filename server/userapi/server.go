package userapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after: a request loads it once and
// uses that copy throughout, so it never mixes the values of two reloads.
type reloadableSettings struct {
	jwtSecret      string
	allowedOrigins []string
	allowedHosts   []string
}

// Server represents the HTTP Mail API server for user operations
type Server struct {
	name                       string
	addr                       string
	settings                   atomic.Pointer[reloadableSettings] // the settings ReloadConfig replaces
	tokenDuration              time.Duration
	tokenIssuer                string
	maxConnections             int // Max concurrent connections; 0 -> unlimited
	rdb                        *resilient.ResilientDatabase
	storage                    *storage.S3Storage
	rs3                        *resilient.ResilientS3Storage // storage behind retries + breaker; nil when storage is
	uploader                   *uploader.UploadWorker
	cache                      *cache.Cache
	authCache                  *lookupcache.LookupCache
	positiveRevalidationWindow time.Duration
	authLimiter                *server.AuthRateLimiter
	server                     *http.Server
	tls                        bool
	tlsConfig                  *tls.Config // TLS config from manager (takes precedence) or nil
	tlsCertFile                string
	tlsKeyFile                 string
	tlsVerify                  bool
	proxyReader                *server.ProxyProtocolReader
	sieveExtensions            []string
}

// ServerOptions holds configuration options for the HTTP Mail API server
type ServerOptions struct {
	Name           string
	Addr           string
	JWTSecret      string
	TokenDuration  time.Duration
	TokenIssuer    string
	MaxConnections int // Max concurrent connections; 0 -> unlimited
	AllowedOrigins []string
	AllowedHosts   []string
	Storage        *storage.S3Storage
	Cache          *cache.Cache
	// Uploader is this node's upload worker: bodies not yet in S3 are read from its
	// staging spool, and its max_attempts tells a body still on its way from one the
	// worker has given up on (see loadMessageBody). Optional.
	Uploader                    *uploader.UploadWorker
	AuthRateLimit               server.AuthRateLimiterConfig
	LookupCache                 *config.LookupCacheConfig // Authentication cache configuration
	TLS                         bool
	TLSConfig                   *tls.Config // TLS config from manager (takes precedence over cert files)
	TLSCertFile                 string
	TLSKeyFile                  string
	TLSVerify                   bool
	ProxyProtocol               bool
	ProxyProtocolTimeout        string
	ProxyProtocolTrustedProxies []string
	TrustedNetworks             []string // Fallback if trusted proxies empty
	// SieveExtensions is the configured [sieve] enabled_extensions set (empty = the
	// default set), the one delivery compiles a user's script with. The capabilities
	// endpoint reports it, so a client offers only rules that will run.
	SieveExtensions []string
}

// minJWTSecretLength is the minimum accepted JWT signing secret length. RFC 7518
// §3.2 requires an HS256 key of at least 256 bits (32 bytes); a weaker secret is
// brute-forceable offline, allowing token forgery for any account.
const minJWTSecretLength = 32

// maxTokenDuration caps how long a User API JWT may live. JWTs are validated
// statelessly, so a token cannot be revoked before it expires — a password change
// or account deletion only stops *renewal* at refresh time. Clamping the duration
// bounds the window in which a leaked or post-revocation token remains usable.
// Seven days is generous for an access token while keeping that window finite.
const maxTokenDuration = 7 * 24 * time.Hour

// checkJWTSecret refuses a JWT secret the server must not sign with, at start-up and
// on a config reload alike.
func checkJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT secret is required for Mail API server")
	}
	if len(secret) < minJWTSecretLength {
		return fmt.Errorf("JWT secret must be at least %d bytes for HS256 (RFC 7518 §3.2); got %d", minJWTSecretLength, len(secret))
	}
	if secret == "your-secret-jwt-signing-key-here" {
		return fmt.Errorf("JWT secret is the placeholder value from config.toml.example — set a real, random jwt_secret")
	}
	return nil
}

// New creates a new HTTP Mail API server
func New(rdb *resilient.ResilientDatabase, options ServerOptions) (*Server, error) {
	if err := checkJWTSecret(options.JWTSecret); err != nil {
		return nil, err
	}

	if options.TokenDuration == 0 {
		options.TokenDuration = 24 * time.Hour // Default to 24 hours
	}
	if options.TokenDuration > maxTokenDuration {
		logger.Warn("User API: token_duration exceeds maximum; clamping",
			"name", options.Name, "configured", options.TokenDuration.String(), "max", maxTokenDuration.String())
		options.TokenDuration = maxTokenDuration
	}

	if options.TokenIssuer == "" {
		options.TokenIssuer = "sora-mail-api"
	}

	// Validate TLS configuration
	if options.TLS {
		// If TLSConfig is provided (from manager), use it. Otherwise require cert files.
		if options.TLSConfig == nil {
			if options.TLSCertFile == "" || options.TLSKeyFile == "" {
				return nil, fmt.Errorf("TLS certificate and key files are required when TLS is enabled (or use TLS manager)")
			}
		}
	}

	// Create auth rate limiter
	authLimiter := server.NewAuthRateLimiter("user-api", options.Name, "", options.AuthRateLimit)
	server.RegisterRateLimiter("userapi", options.Name, authLimiter)

	// Initialize authentication cache if configured
	var authCache *lookupcache.LookupCache
	var positiveRevalidationWindow time.Duration
	if options.LookupCache != nil && options.LookupCache.Enabled {
		// Parse TTL and other config values
		lookupCacheConfig := options.LookupCache

		positiveTTL, err := time.ParseDuration(lookupCacheConfig.PositiveTTL)
		if err != nil || lookupCacheConfig.PositiveTTL == "" {
			logger.Info("User API: Using default positive TTL (5m)", "name", options.Name)
			positiveTTL = 5 * time.Minute
		}

		negativeTTL, err := time.ParseDuration(lookupCacheConfig.NegativeTTL)
		if err != nil || lookupCacheConfig.NegativeTTL == "" {
			logger.Info("User API: Using default negative TTL (1m)", "name", options.Name)
			negativeTTL = 1 * time.Minute
		}

		cleanupInterval, err := time.ParseDuration(lookupCacheConfig.CleanupInterval)
		if err != nil || lookupCacheConfig.CleanupInterval == "" {
			logger.Info("User API: Using default cleanup interval (5m)", "name", options.Name)
			cleanupInterval = 5 * time.Minute
		}

		maxSize := lookupCacheConfig.MaxSize
		if maxSize == 0 {
			maxSize = 10000
		}

		positiveRevalidationWindow, err = lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("User API: Invalid positive revalidation window in auth cache config, using default (30s)", "name", options.Name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		authCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("User API: Lookup cache enabled", "name", options.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Timeout:        options.ProxyProtocolTimeout,
			TrustedProxies: getProxyProtocolTrustedProxies(options.ProxyProtocolTrustedProxies, options.TrustedNetworks),
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("USER-API", proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "server", options.Name)
	}

	s := &Server{
		name:                       options.Name,
		addr:                       options.Addr,
		sieveExtensions:            sieveengine.EffectiveExtensions(options.SieveExtensions),
		maxConnections:             options.MaxConnections,
		tokenDuration:              options.TokenDuration,
		tokenIssuer:                options.TokenIssuer,
		rdb:                        rdb,
		storage:                    options.Storage,
		rs3:                        newResilientStorage(options.Storage),
		cache:                      options.Cache,
		uploader:                   options.Uploader,
		authCache:                  authCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		authLimiter:                authLimiter,
		tls:                        options.TLS,
		tlsConfig:                  options.TLSConfig,
		tlsCertFile:                options.TLSCertFile,
		tlsKeyFile:                 options.TLSKeyFile,
		tlsVerify:                  options.TLSVerify,
		proxyReader:                proxyReader,
	}
	s.settings.Store(&reloadableSettings{
		jwtSecret:      options.JWTSecret,
		allowedOrigins: options.AllowedOrigins,
		allowedHosts:   options.AllowedHosts,
	})

	return s, nil
}

// Start starts the HTTP Mail API server
// ReloadConfig updates runtime-configurable settings from new config.
func (s *Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string
	var refused error
	next := *s.settings.Load()

	if cfg.JWTSecret != "" && cfg.JWTSecret != next.jwtSecret {
		// Tokens signed with the previous secret stop validating, as on the User API
		// proxy, which reloads it too.
		if err := checkJWTSecret(cfg.JWTSecret); err != nil {
			// The rest still reloads. The error has the caller log a failed reload, so an
			// operator rotating a leaked secret learns that the old one is still live.
			refused = fmt.Errorf("jwt_secret refused, the previous one stays in use: %w", err)
		} else {
			next.jwtSecret = cfg.JWTSecret
			reloaded = append(reloaded, "jwt_secret")
		}
	}
	// Reload receives the complete config, so an empty or removed list means what
	// it does at startup: no origin is authorized, and every host is allowed.
	if !slices.Equal(cfg.AllowedOrigins, next.allowedOrigins) {
		next.allowedOrigins = slices.Clone(cfg.AllowedOrigins)
		reloaded = append(reloaded, "allowed_origins")
	}
	if !slices.Equal(cfg.AllowedHosts, next.allowedHosts) {
		next.allowedHosts = slices.Clone(cfg.AllowedHosts)
		reloaded = append(reloaded, "allowed_hosts")
	}

	if len(reloaded) > 0 {
		s.settings.Store(&next)
		logger.Info("User API config reloaded", "name", s.name, "updated", reloaded)
	}
	return refused
}

func Start(ctx context.Context, rdb *resilient.ResilientDatabase, options ServerOptions, errChan chan error) *Server {
	server, err := New(rdb, options)
	if err != nil {
		errChan <- fmt.Errorf("failed to create HTTP Mail API server: %w", err)
		return nil
	}

	protocol := "HTTP"
	if options.TLS {
		protocol = "HTTPS"
	}
	serverName := options.Name
	if serverName == "" {
		serverName = "default"
	}
	logger.Info("HTTP Mail API: Starting server", "name", serverName, "protocol", protocol, "addr", options.Addr)
	go func() {
		if err := server.start(ctx); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			errChan <- fmt.Errorf("HTTP Mail API server failed: %w", err)
		}
	}()
	return server
}

// start initializes and starts the HTTP server
func (s *Server) start(ctx context.Context) error {
	router := s.SetupRoutes()

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second, // slowloris-on-headers defense
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		logger.Info("HTTP Mail API: Shutting down server...", "name", s.name)
		server.UnregisterRateLimiter("userapi", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP Mail API: Error shutting down server", "name", s.name, "error", err)
		}
	}()

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
	listener = server.WrapProxyProtocolHTTP(listener, s.proxyReader, "USER-API")

	// Cap concurrent connections (0 = unlimited, like the other server types) to
	// prevent connection/goroutine exhaustion on the HTTP API.
	if s.maxConnections > 0 {
		listener = netutil.LimitListener(listener, s.maxConnections)
	}

	// Start server with or without TLS
	if s.tls {
		// Use TLS config from manager if provided, otherwise create one for static certs
		var tlsConfig *tls.Config
		if s.tlsConfig != nil {
			// Clone the manager's TLS config
			tlsConfig = s.tlsConfig.Clone()
		} else {
			// Create new TLS config for static certificates
			tlsConfig = &tls.Config{
				MinVersion:    tls.VersionTLS12,
				Renegotiation: tls.RenegotiateNever,
			}
		}

		// Apply client verification settings
		if s.tlsVerify {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.NoClientCert
		}
		s.server.TLSConfig = tlsConfig

		// If using TLS manager (tlsConfig from manager), pass empty cert files
		// The GetCertificate callback in the config will handle certificate retrieval
		if s.tlsConfig != nil {
			return s.server.ServeTLS(listener, "", "")
		}
		// Otherwise use static certificate files
		return s.server.ServeTLS(listener, s.tlsCertFile, s.tlsKeyFile)
	}
	return s.server.Serve(listener)
}

// SetupRoutes configures all HTTP routes and middleware
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/user/auth/login", routeHandler("POST", s.handleLogin))
	mux.HandleFunc("/user/auth/refresh", routeHandler("POST", s.handleRefreshToken))

	// Mailbox operations
	mux.Handle("/user/mailboxes", s.jwtAuthMiddleware(multiMethodHandler(map[string]http.HandlerFunc{
		"GET":  s.handleListMailboxes,
		"POST": s.handleCreateMailbox,
	})))
	mux.Handle("/user/mailboxes/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleMailboxWithName)))

	// Message operations
	mux.Handle("/user/messages/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleMessageOperations)))

	// Sieve filter operations
	mux.Handle("/user/filters", s.jwtAuthMiddleware(routeHandler("GET", s.handleListFilters)))
	mux.Handle("/user/filters/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleFilterOperations)))

	// Wrap with middleware (in reverse order - last applied is outermost)
	handler := s.loggingMiddleware(mux)
	handler = s.corsMiddleware(handler)
	handler = s.allowedHostsMiddleware(handler)

	return handler
}

// handleMailboxWithName routes mailbox operations that include a mailbox name
func (s *Server) handleMailboxWithName(w http.ResponseWriter, r *http.Request) {
	// The endpoint is picked by what follows the name, in the escaped path (an
	// encoded "/" belongs to the name, see pathName) and only after a name: a
	// DELETE of the top-level mailbox "search" deletes that mailbox.
	path := strings.TrimPrefix(escapedRoutingPath(r), "/user/mailboxes/")

	// Check for subscribe/unsubscribe operations
	if strings.HasSuffix(path, "/subscribe") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSubscribeMailbox(w, r)
		return
	}
	if strings.HasSuffix(path, "/unsubscribe") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleUnsubscribeMailbox(w, r)
		return
	}

	// Check for message listing/search
	if strings.HasSuffix(path, "/messages") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListMessages(w, r)
		return
	}
	if strings.HasSuffix(path, "/search") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSearchMessages(w, r)
		return
	}

	// Otherwise it's a delete operation on the mailbox itself
	if r.Method == "DELETE" {
		s.handleDeleteMailbox(w, r)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleMessageOperations routes message operations
func (s *Server) handleMessageOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for body/raw endpoints
	if strings.HasSuffix(path, "/body") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetMessageBody(w, r)
		return
	}
	if strings.HasSuffix(path, "/raw") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetMessageRaw(w, r)
		return
	}

	// Otherwise it's a basic message operation
	switch r.Method {
	case "GET":
		s.handleGetMessage(w, r)
	case "PATCH":
		s.handleUpdateMessage(w, r)
	case "DELETE":
		s.handleDeleteMessage(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFilterOperations routes Sieve filter operations
func (s *Server) handleFilterOperations(w http.ResponseWriter, r *http.Request) {
	// As in handleMailboxWithName: /activate is matched only after a script
	// name, so a script named "activate" is addressed by that name.
	path := strings.TrimPrefix(escapedRoutingPath(r), "/user/filters/")

	// Check for capabilities endpoint
	if path == "capabilities" {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetCapabilities(w, r)
		return
	}

	// Check for activate endpoint
	if strings.HasSuffix(path, "/activate") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleActivateFilter(w, r)
		return
	}

	// Otherwise it's a CRUD operation on the filter itself
	switch r.Method {
	case "GET":
		s.handleGetFilter(w, r)
	case "PUT":
		s.handlePutFilter(w, r)
	case "DELETE":
		s.handleDeleteFilter(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Debug("HTTP Mail API: request", "name", s.name, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
		logger.Debug("HTTP Mail API: request completed", "name", s.name, "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowedOrigins := s.settings.Load().allowedOrigins
		if origin != "" && len(allowedOrigins) > 0 {
			allowed := false
			wildcard := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" {
					allowed = true
					wildcard = true
					break
				}
				if allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "3600")
				if wildcard {
					// A wildcard origin must NOT be combined with credentials (CORS spec):
					// reflecting a concrete origin + Allow-Credentials lets any site make
					// credentialed cross-origin reads. Emit literal "*" without credentials.
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					// Specific configured origin: safe to reflect and allow credentials.
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHostsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedHosts := s.settings.Load().allowedHosts
		if len(allowedHosts) == 0 {
			// No restrictions, allow all hosts
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)
		if !isIPAllowed(clientIP, allowedHosts) {
			s.writeError(w, http.StatusForbidden, "Host not allowed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Utility functions

func getClientIP(r *http.Request) string {
	// Extract IP from RemoteAddr (which may be set by PROXY protocol or real TCP peer)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If splitting fails, return as-is (already an IP without port)
		return r.RemoteAddr
	}
	return host
}

func isIPAllowed(clientIP string, allowedHosts []string) bool {
	networks, err := helpers.ParseTrustedNetworks(allowedHosts)
	if err != nil {
		logger.Warn("userapi: failed to parse allowed hosts as CIDR, falling back to literal matching", "error", err)
		for _, allowedHost := range allowedHosts {
			if allowedHost == clientIP {
				return true
			}
		}
		return false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Warn("HTTP Mail API: Error encoding JSON response", "name", s.name, "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}
