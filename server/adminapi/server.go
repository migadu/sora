package adminapi

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after: a request loads it once and
// uses that copy throughout, so it never mixes the values of two reloads.
type reloadableSettings struct {
	apiKey         string
	readOnlyAPIKey string // optional second key, accepted for GET requests only
	allowedHosts   []string
}

// Server represents the HTTP API server
type Server struct {
	name           string
	addr           string
	settings       atomic.Pointer[reloadableSettings] // the settings ReloadConfig replaces
	rdb            *resilient.ResilientDatabase
	cache          *cache.Cache
	uploader       *uploader.UploadWorker
	storage        *storage.S3Storage
	purgeWorker    *cleaner.PurgeWorker // this node's purge worker, nil on a node without object storage
	relayQueue     delivery.RelayQueue  // Global relay queue for mail delivery
	maxMessageSize int64                // Max accepted mail-injection body size (bytes); 0 -> default
	maxConnections int                  // Max concurrent connections; 0 -> unlimited
	server         *http.Server
	tls            bool
	tlsConfig      *tls.Config // TLS config from manager (takes precedence) or nil
	tlsCertFile    string
	tlsKeyFile     string
	tlsVerify      bool
	hostname       string
	// instanceID is the upload-lease key (pending_uploads.instance_id), distinct from
	// hostname, which is the SMTP-visible name stamped into Received headers.
	instanceID         string
	uploadMaxAttempts  int // [uploader] max_attempts: the uploader endpoints' default failure threshold
	ftsRetention       time.Duration
	affinityManager    AffinityManager
	validBackends      map[string][]string
	connectionTrackers func() map[string]*server.ConnectionTracker // snapshot: protocol -> tracker
	proxyServers       func() map[string]ProxyServer               // snapshot: proxy name -> proxy server
	proxyReader        *server.ProxyProtocolReader                 // PROXY protocol support
	authCache          AuthCacheStats                              // persistent auth cache (optional)
	redirectRateLimit  int                                         // Max redirects per account
	redirectRateWindow time.Duration                               // Window for redirect limit
	maxRedirectHops    int                                         // Max redirect hops per message (mail-loop backstop)
	sieveExtensions    []string                                    // [sieve] enabled_extensions, shared with the LMTP path
	sharedMailboxes    config.SharedMailboxesConfig                // [shared_mailboxes], which ACL grants honour

	// Mail deliveries in flight, reported as this server's drain sessions, admitted by the
	// maintenance gate, which refuses new ones while this backend is in maintenance.
	deliveriesOpen  atomic.Int64
	maintenanceGate *server.MaintenanceGate
}

// DrainSessions reports the mail deliveries (/admin/mail/deliver), which stage uploads:
// how many are in flight. See imap.IMAPServer.DrainSessions.
func (s *Server) DrainSessions() int64 {
	return s.deliveriesOpen.Load()
}

// ServerOptions holds configuration options for the HTTP API server
type ServerOptions struct {
	Name               string
	Addr               string
	APIKey             string
	ReadOnlyAPIKey     string // optional; grants only GET requests
	AllowedHosts       []string
	Cache              *cache.Cache
	Uploader           *uploader.UploadWorker
	UploadMaxAttempts  int // [uploader] max_attempts, when the uploader endpoints count an upload as failed; 0 -> config default
	Storage            *storage.S3Storage
	PurgeWorker        *cleaner.PurgeWorker // woken when a purge is requested on this node; nil without object storage
	RelayQueue         delivery.RelayQueue  // Global relay queue for mail delivery
	MaxMessageSize     int64                // Max accepted mail-injection body size (bytes); 0 -> 50MB default
	MaxConnections     int                  // Max concurrent connections; 0 -> unlimited
	TLS                bool
	TLSConfig          *tls.Config // TLS config from manager (takes precedence over cert files)
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	Hostname           string
	InstanceID         string
	MaintenanceGate    *server.MaintenanceGate // admits mail deliveries; refuses them while this backend is in maintenance (nil admits all)
	FTSRetention       time.Duration
	AffinityManager    AffinityManager
	ValidBackends      map[string][]string                         // Map of protocol -> valid backend addresses
	ConnectionTrackers func() map[string]*server.ConnectionTracker // snapshot of protocol -> tracker (for gossip-based kick), see Server.trackers
	ProxyServers       func() map[string]ProxyServer               // snapshot of proxy name -> proxy server (for backend health), see Server.trackers
	AuthCache          AuthCacheStats                              // persistent auth cache (optional)
	RedirectRateLimit  int
	RedirectRateWindow time.Duration
	MaxRedirectHops    int
	SieveExtensions    []string                     // [sieve] enabled_extensions (empty = default set)
	SharedMailboxes    config.SharedMailboxesConfig // [shared_mailboxes]; allow_anyone_identifier gates ACL grants to "anyone"

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol               bool     // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout        string   // Timeout for reading PROXY protocol headers (e.g., "5s")
	ProxyProtocolTrustedProxies []string // CIDR blocks for PROXY protocol validation (defaults to trusted_networks if empty)
	TrustedNetworks             []string // CIDR blocks for trusted networks (for PROXY protocol validation)
}

// AffinityManager interface for managing user-to-backend affinity
type AffinityManager interface {
	SetBackend(username, backend, protocol string)
	GetBackend(username, protocol string) (string, bool)
	DeleteBackend(username, protocol string)
	GetStats(ctx context.Context) map[string]any
}

// ProxyServer interface for accessing proxy backend health information
type ProxyServer interface {
	GetConnectionManager() *proxy.ConnectionManager
}

// AuthCacheStats interface for accessing auth cache statistics
type AuthCacheStats interface {
	Stats(ctx context.Context) (totalEntries, lifetimeHits int64, hits, misses int64, hitRate float64, err error)
}

// BackendHealthInfo represents backend health status (mirrors proxy.BackendHealthInfo)
type BackendHealthInfo struct {
	Address            string    `json:"address"`
	Pool               string    `json:"pool,omitempty"` // Named pool the backend belongs to ("" for a flat remote_addrs list)
	IsHealthy          bool      `json:"is_healthy"`
	FailureCount       int       `json:"failure_count"`
	ConsecutiveFails   int       `json:"consecutive_fails"`
	LastFailure        time.Time `json:"last_failure,omitempty"`
	LastSuccess        time.Time `json:"last_success,omitempty"`
	HealthCheckEnabled bool      `json:"health_check_enabled"`
	IsRemoteLookup     bool      `json:"is_remote_lookup"` // True if backend from remote_lookup (not in pool)
	InMaintenance      bool      `json:"in_maintenance"`   // True if this proxy honors maintenance for the backend
}

// ProxyBackendsResponse is the response structure for /admin/proxy/backends
type ProxyBackendsResponse struct {
	Proxies   []ProxyBackendInfo `json:"proxies"`
	Timestamp time.Time          `json:"timestamp"`
}

// ProxyBackendInfo contains information about a proxy server and its backends
type ProxyBackendInfo struct {
	ProxyName string              `json:"proxy_name"`
	Backends  []BackendHealthInfo `json:"backends"`
}

// minAPIKeyLength is the minimum accepted Admin API key length. The key is the
// primary gate for the Admin API (account CRUD, kick, mail injection), so a short
// key is a real brute-force risk; reject it at startup rather than run with it.
const minAPIKeyLength = 16

// checkAPIKey refuses an API key the server must not run with, at start-up and on
// a config reload alike.
func checkAPIKey(key string) error {
	if key == "" {
		return fmt.Errorf("API key is required for HTTP API server")
	}
	if len(key) < minAPIKeyLength {
		return fmt.Errorf("API key must be at least %d characters (got %d) — use a long, random value", minAPIKeyLength, len(key))
	}
	switch key {
	case "your-api-key-here", "your-secret-api-key-here":
		return fmt.Errorf("API key is the placeholder value from config.toml.example — set a real, random api_key")
	}
	return nil
}

// checkReadOnlyAPIKey refuses a read-only API key the server must not run with. It is
// optional, so empty is fine; otherwise it is held to the same strength rules as
// api_key and must differ from it, or every read-only client would hold full access.
func checkReadOnlyAPIKey(key, apiKey string) error {
	if key == "" {
		return nil
	}
	if err := checkAPIKey(key); err != nil {
		return fmt.Errorf("read-only %w", err)
	}
	if key == apiKey {
		return fmt.Errorf("read-only API key must differ from the API key")
	}
	return nil
}

// New creates a new HTTP API server
func New(rdb *resilient.ResilientDatabase, options ServerOptions) (*Server, error) {
	if err := checkAPIKey(options.APIKey); err != nil {
		return nil, err
	}
	if err := checkReadOnlyAPIKey(options.ReadOnlyAPIKey, options.APIKey); err != nil {
		return nil, err
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

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Timeout:        options.ProxyProtocolTimeout,
			TrustedProxies: getProxyProtocolTrustedProxies(options.ProxyProtocolTrustedProxies, options.TrustedNetworks),
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("ADMIN-API", proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "server", options.Name)
	}

	s := &Server{
		name:               options.Name,
		addr:               options.Addr,
		rdb:                rdb,
		cache:              options.Cache,
		uploader:           options.Uploader,
		storage:            options.Storage,
		purgeWorker:        options.PurgeWorker,
		relayQueue:         options.RelayQueue,
		maxMessageSize:     options.MaxMessageSize,
		maxConnections:     options.MaxConnections,
		tls:                options.TLS,
		tlsConfig:          options.TLSConfig,
		tlsCertFile:        options.TLSCertFile,
		tlsKeyFile:         options.TLSKeyFile,
		tlsVerify:          options.TLSVerify,
		hostname:           options.Hostname,
		instanceID:         options.InstanceID,
		uploadMaxAttempts:  options.UploadMaxAttempts,
		maintenanceGate:    options.MaintenanceGate,
		ftsRetention:       options.FTSRetention,
		affinityManager:    options.AffinityManager,
		validBackends:      options.ValidBackends,
		connectionTrackers: options.ConnectionTrackers,
		proxyServers:       options.ProxyServers,
		proxyReader:        proxyReader,
		authCache:          options.AuthCache,
		redirectRateLimit:  options.RedirectRateLimit,
		redirectRateWindow: options.RedirectRateWindow,
		maxRedirectHops:    options.MaxRedirectHops,
		sieveExtensions:    sieveengine.EffectiveExtensions(options.SieveExtensions),
		sharedMailboxes:    options.SharedMailboxes,
	}
	if s.uploadMaxAttempts <= 0 {
		s.uploadMaxAttempts = config.DefaultUploaderMaxAttempts
	}
	s.settings.Store(&reloadableSettings{
		apiKey:         options.APIKey,
		readOnlyAPIKey: options.ReadOnlyAPIKey,
		allowedHosts:   options.AllowedHosts,
	})

	return s, nil
}

// SetAuthCache sets the persistent authentication cache for stats reporting.
func (s *Server) SetAuthCache(ac AuthCacheStats) {
	s.authCache = ac
}

// Start starts the HTTP API server
// ReloadConfig updates runtime-configurable settings from new config.
func (s *Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string
	var refused error
	next := *s.settings.Load()
	nextAPIKey := cfg.APIKey
	if nextAPIKey == "" {
		nextAPIKey = next.apiKey
	}

	// Validate both keys before changing either. A refused reload must preserve
	// the live keys used by the guards, even when the same config is retried.
	if nextAPIKey != next.apiKey {
		if nextAPIKey == next.readOnlyAPIKey {
			// Read-only clients already hold this value; taking it as api_key would
			// hand them full access.
			refused = fmt.Errorf("api_key refused, both previous API keys stay in use: it equals the current read_only_api_key")
		} else if err := checkAPIKey(nextAPIKey); err != nil {
			// The error has the caller log a failed reload, so an operator rotating
			// a leaked key learns that the old one is still live.
			refused = fmt.Errorf("api_key refused, both previous API keys stay in use: %w", err)
		}
	}
	// read_only_api_key is optional, so unlike api_key an empty value is applied: it
	// revokes the read-only key.
	if cfg.ReadOnlyAPIKey != next.readOnlyAPIKey {
		if err := checkReadOnlyAPIKey(cfg.ReadOnlyAPIKey, nextAPIKey); err != nil {
			refused = errors.Join(refused, fmt.Errorf("read_only_api_key refused, both previous API keys stay in use: %w", err))
		} else if cfg.ReadOnlyAPIKey != "" && cfg.ReadOnlyAPIKey == next.apiKey {
			// The api_key being rotated out may be a leaked one; it must not live on as a read key.
			refused = errors.Join(refused, fmt.Errorf("read_only_api_key refused, both previous API keys stay in use: it equals the api_key this reload replaces"))
		}
	}
	if refused == nil {
		if nextAPIKey != next.apiKey {
			next.apiKey = nextAPIKey
			reloaded = append(reloaded, "api_key")
		}
		if cfg.ReadOnlyAPIKey != next.readOnlyAPIKey {
			next.readOnlyAPIKey = cfg.ReadOnlyAPIKey
			reloaded = append(reloaded, "read_only_api_key")
		}
	}
	// Reload receives the complete config, so an empty or removed list means what
	// it does at startup: every host is allowed.
	if !slices.Equal(cfg.AllowedHosts, next.allowedHosts) {
		next.allowedHosts = slices.Clone(cfg.AllowedHosts)
		reloaded = append(reloaded, "allowed_hosts")
	}

	if len(reloaded) > 0 {
		s.settings.Store(&next)
		logger.Info("Admin API config reloaded", "name", s.name, "updated", reloaded)
	}
	return refused
}

func Start(ctx context.Context, rdb *resilient.ResilientDatabase, options ServerOptions, errChan chan error) *Server {
	server, err := New(rdb, options)
	if err != nil {
		errChan <- fmt.Errorf("failed to create HTTP API server: %w", err)
		return nil
	}
	server.Serve(ctx, errChan)
	return server
}

// Serve starts the server in the background; a failure to serve is sent to errChan.
func (s *Server) Serve(ctx context.Context, errChan chan error) {
	protocol := "HTTP"
	if s.tls {
		protocol = "HTTPS"
	}
	serverName := s.name
	if serverName == "" {
		serverName = "default"
	}
	logger.Info("HTTP API: Starting server", "name", serverName, "protocol", protocol, "addr", s.addr)
	go func() {
		if err := s.start(ctx); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			errChan <- fmt.Errorf("HTTP API server failed: %w", err)
		}
	}()
}

// start initializes and starts the HTTP server
func (s *Server) start(ctx context.Context) error {
	router := s.setupRoutes()

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: router,
		// ReadHeaderTimeout bounds slowloris-on-headers. Read/Write are generous on
		// purpose: the mail-injection endpoint accepts bodies up to max_message_size
		// (the body SIZE is bounded by MaxBytesReader in handleDeliverMail), so a tight
		// whole-request limit would cut off large legitimate uploads.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		logger.Info("HTTP API: Shutting down server", "name", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP API: Error shutting down server", "name", s.name, "error", err)
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
	// which is what allowed_hosts reads via r.RemoteAddr.
	listener = server.WrapProxyProtocolHTTP(listener, s.proxyReader, "ADMIN-API")

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

		// Serve with TLS using the listener
		return s.server.ServeTLS(listener, s.tlsCertFile, s.tlsKeyFile)
	}
	return s.server.Serve(listener)
}

// setupRoutes configures all HTTP routes and middleware
func (s *Server) setupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Account management routes. {email} is one segment of the escaped path, which
	// r.PathValue decodes once: a "/" in a local part (atext, RFC 5322 §3.2.3)
	// arrives as %2F and is part of the address, never a separator (RFC 3986 §2.4).
	mux.HandleFunc("/admin/accounts", routeHandler("POST", s.handleCreateAccount))
	mux.HandleFunc("/admin/accounts/{email}", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":    s.handleGetAccount,
		"PUT":    s.handleUpdateAccount,
		"DELETE": s.handleDeleteAccount,
	}))
	mux.HandleFunc("/admin/accounts/{email}/exists", routeHandler("GET", s.handleAccountExists))
	mux.HandleFunc("/admin/accounts/{email}/restore", routeHandler("POST", s.handleRestoreAccount))
	mux.HandleFunc("/admin/accounts/{email}/credentials", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":  s.handleListCredentials,
		"POST": s.handleAddCredential,
	}))
	mux.HandleFunc("/admin/accounts/{email}/messages/deleted", routeHandler("GET", s.handleListDeletedMessages))
	mux.HandleFunc("/admin/accounts/{email}/messages/restore", routeHandler("POST", s.handleRestoreMessages))

	// Domain-scoped account management routes
	mux.HandleFunc("/admin/domains/", s.handleDomainOperations)

	// Usage: every account's storage, page by page
	mux.HandleFunc("/admin/usage/accounts", routeHandler("GET", s.handleAccountUsage))

	// Credential management routes
	mux.HandleFunc("/admin/credentials/{email}", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":    s.handleGetCredential,
		"DELETE": s.handleDeleteCredential,
	}))

	// Connection management routes
	mux.HandleFunc("/admin/connections", routeHandler("GET", s.handleListConnections))
	mux.HandleFunc("/admin/connections/stats", routeHandler("GET", s.handleConnectionStats))
	mux.HandleFunc("/admin/connections/kick", routeHandler("POST", s.handleKickConnections))
	mux.HandleFunc("/admin/connections/user/{email}", routeHandler("GET", s.handleGetUserConnections))

	// Cache management routes
	mux.HandleFunc("/admin/cache/stats", routeHandler("GET", s.handleCacheStats))
	mux.HandleFunc("/admin/cache/metrics", routeHandler("GET", s.handleCacheMetrics))
	mux.HandleFunc("/admin/cache/purge", routeHandler("POST", s.handleCachePurge))

	// Uploader routes
	mux.HandleFunc("/admin/uploader/status", routeHandler("GET", s.handleUploaderStatus))
	mux.HandleFunc("/admin/uploader/failed", routeHandler("GET", s.handleFailedUploads))

	// Authentication statistics routes
	mux.HandleFunc("/admin/auth/stats", routeHandler("GET", s.handleAuthStats))
	mux.HandleFunc("/admin/auth/blocked", routeHandler("GET", s.handleAuthBlocked))
	mux.HandleFunc("/admin/auth-cache/stats", routeHandler("GET", s.handleAuthCacheStats))

	// Health monitoring routes
	mux.HandleFunc("/admin/health/overview", routeHandler("GET", s.handleHealthOverview))
	mux.HandleFunc("/admin/health/servers/", s.handleHealthOperations)

	// Proxy backend health routes
	mux.HandleFunc("/admin/proxy/backends", routeHandler("GET", s.handleProxyBackends))

	// System configuration and status routes
	mux.HandleFunc("/admin/config", routeHandler("GET", s.handleConfigInfo))

	// Mail delivery route
	mux.HandleFunc("/admin/mail/deliver", routeHandler("POST", s.handleDeliverMail))

	// ACL management routes
	mux.HandleFunc("/admin/mailboxes/acl/grant", routeHandler("POST", s.handleACLGrant))
	mux.HandleFunc("/admin/mailboxes/acl/revoke", routeHandler("POST", s.handleACLRevoke))
	mux.HandleFunc("/admin/mailboxes/acl", routeHandler("GET", s.handleACLList))

	// Affinity management routes
	mux.HandleFunc("/admin/affinity", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":    s.handleAffinityGet,
		"POST":   s.handleAffinitySet,
		"DELETE": s.handleAffinityDelete,
	}))
	mux.HandleFunc("/admin/affinity/list", routeHandler("GET", s.handleAffinityList))
	mux.HandleFunc("/admin/affinity/stats", routeHandler("GET", s.handleAffinityStats))

	// Wrap with middleware (in reverse order - last applied is outermost).
	// The host allowlist is outermost so off-allowlist clients are rejected before
	// the bearer-token comparison runs at all.
	handler := s.loggingMiddleware(mux)
	handler = s.authMiddleware(handler)
	handler = s.allowedHostsMiddleware(handler)

	return handler
}

// handleDomainOperations routes domain-scoped operations
func (s *Server) handleDomainOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for /admin/domains/{domain}/accounts
	if strings.Contains(path, "/accounts") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListAccountsByDomain(w, r)
		return
	}

	// Unknown domain operation
	http.Error(w, "Not found", http.StatusNotFound)
}

// handleHealthOperations routes health monitoring operations
func (s *Server) handleHealthOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check if it's a component-specific operation
	if strings.Contains(path, "/components/") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleHealthStatusByComponent(w, r)
		return
	}

	// Otherwise it's a host-level operation
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleHealthStatusByHost(w, r)
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Debug("HTTP API: Request", "name", s.name, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
		logger.Debug("HTTP API: Request completed", "name", s.name, "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
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

		// Single shared check: allowedHosts entries may be CIDRs or bare IPs (incl. IPv6,
		// matched by value rather than string form). See helpers.IPInNetworks.
		allowed := helpers.IPInNetworks(net.ParseIP(clientIP), allowedHosts)

		if !allowed {
			s.writeError(w, http.StatusForbidden, "Host not allowed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header must be 'Bearer <token>'")
			return
		}

		settings := s.settings.Load()
		token := []byte(parts[1])
		if subtle.ConstantTimeCompare(token, []byte(settings.apiKey)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		if settings.readOnlyAPIKey == "" || subtle.ConstantTimeCompare(token, []byte(settings.readOnlyAPIKey)) != 1 {
			s.writeError(w, http.StatusForbidden, "Invalid API key")
			return
		}
		// The read-only key: every GET route only reads, and every write is a
		// POST, PUT or DELETE.
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusForbidden, "API key is read-only")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Utility functions

func getClientIP(r *http.Request) string {
	// Extract IP from RemoteAddr (which may be set by PROXY protocol or real TCP peer)
	// Never trust X-Forwarded-For or X-Real-IP headers as they are attacker-controlled
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If splitting fails, return as-is (already an IP without port)
		return r.RemoteAddr
	}
	return host
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Warn("HTTP API: Error encoding JSON response", "name", s.name, "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// Request/Response types

type CreateAccountRequest struct {
	Email        string                 `json:"email"`
	Password     string                 `json:"password"`
	PasswordHash string                 `json:"password_hash"`
	Credentials  []CreateCredentialSpec `json:"credentials,omitempty"`
}

type CreateCredentialSpec struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
	IsPrimary    bool   `json:"is_primary"`
	HashType     string `json:"hash_type"`
}

type UpdateAccountRequest struct {
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
}

type AddCredentialRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
}

type KickConnectionsRequest struct {
	UserEmail  string `json:"user_email,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
	ClientAddr string `json:"client_addr,omitempty"`
}

// Import/Export request types removed - these operations are not suitable
// for HTTP API as they are long-running processes

// Handler functions

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ctx := r.Context()

	// Check if credentials array is provided for multi-credential creation
	if len(req.Credentials) > 0 {
		// Multi-credential creation
		if req.Email != "" || req.Password != "" || req.PasswordHash != "" {
			s.writeError(w, http.StatusBadRequest, "Cannot specify email, password, or password_hash when using credentials array")
			return
		}

		// Convert API types to database types
		dbCredentials := make([]db.CredentialSpec, len(req.Credentials))
		for i, cred := range req.Credentials {
			if cred.Email == "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: email is required", i+1))
				return
			}
			if cred.Password == "" && cred.PasswordHash == "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: either password or password_hash is required", i+1))
				return
			}
			if cred.Password != "" && cred.PasswordHash != "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: cannot specify both password and password_hash", i+1))
				return
			}

			hashType := cred.HashType
			if hashType == "" {
				hashType = "bcrypt"
			}
			if cred.Password != "" {
				if err := db.ValidateNewHashType(hashType); err != nil {
					s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: %v", i+1, err))
					return
				}
			}

			dbCredentials[i] = db.CredentialSpec{
				Email:        cred.Email,
				Password:     cred.Password,
				PasswordHash: cred.PasswordHash,
				IsPrimary:    cred.IsPrimary,
				HashType:     hashType,
			}
		}

		// Create account with multiple credentials
		createReq := db.CreateAccountWithCredentialsRequest{
			Credentials: dbCredentials,
		}

		accountID, err := s.rdb.CreateAccountWithCredentialsWithRetry(ctx, createReq)
		if err != nil {
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				s.writeError(w, http.StatusConflict, "One or more email addresses already exist")
				return
			}
			logger.Warn("HTTP API: Error creating account with credentials", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to create account with credentials")
			return
		}

		// Prepare response with all created credentials
		var createdCredentials []string
		for _, cred := range req.Credentials {
			createdCredentials = append(createdCredentials, cred.Email)
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"account_id":  accountID,
			"credentials": createdCredentials,
			"message":     "Account created successfully with multiple credentials",
		})
	} else {
		if req.Email == "" {
			s.writeError(w, http.StatusBadRequest, "Email is required")
			return
		}

		if req.Password == "" && req.PasswordHash == "" {
			s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
			return
		}

		if req.Password != "" && req.PasswordHash != "" {
			s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
			return
		}

		// Create account using the existing single-credential method
		createReq := db.CreateAccountRequest{
			Email:        req.Email,
			Password:     req.Password,
			PasswordHash: req.PasswordHash,
			IsPrimary:    true,
			HashType:     "bcrypt",
		}

		accountID, err := s.rdb.CreateAccountWithRetry(ctx, createReq)
		if err != nil {
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				s.writeError(w, http.StatusConflict, "Account already exists")
				return
			}
			logger.Warn("HTTP API: Error creating account", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to create account")
			return
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"account_id": accountID,
			"email":      req.Email,
			"message":    "Account created successfully",
		})
	}
}

func (s *Server) handleListAccountsByDomain(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path: /admin/domains/{domain}/accounts
	domain := extractPathParam(r.URL.Path, "/admin/domains/", "/accounts")
	ctx := r.Context()

	if domain == "" {
		s.writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	summaries, err := s.rdb.ListAccountsByDomainWithRetry(ctx, domain)
	if err != nil {
		logger.Warn("HTTP API: Error listing accounts by domain", "name", s.name, "domain", domain, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing accounts by domain")
		return
	}

	// Convert []AccountSummary to []*AccountSummary for consistent response format
	accounts := make([]*db.AccountSummary, len(summaries))
	for i := range summaries {
		accounts[i] = &summaries[i]
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"domain":   domain,
		"accounts": accounts,
		"total":    len(accounts),
	})
}

// defaultAccountsPage is the page size of /admin/usage/accounts without ?limit.
const defaultAccountsPage = 1000

// handleAccountUsage lists every account with its usage, one bounded page at a
// time: GET /admin/usage/accounts?after={account_id}&limit={n}. next_after is
// the after of the next page, absent on the last one.
func (s *Server) handleAccountUsage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var after int64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest, "after must be an account id (0 or more)")
			return
		}
		after = n
	}
	limit := defaultAccountsPage
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > db.MaxAccountsPage {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be between 1 and %d", db.MaxAccountsPage))
			return
		}
		limit = n
	}

	accounts, err := s.rdb.ListAccountsPageWithRetry(r.Context(), after, limit)
	if err != nil {
		logger.Warn("HTTP API: Error listing accounts page", "name", s.name, "after", after, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing accounts")
		return
	}
	resp := map[string]any{"accounts": accounts}
	if len(accounts) == limit {
		resp["next_after"] = accounts[len(accounts)-1].AccountID
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAccountExists(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	ctx := r.Context()

	result, err := s.rdb.AccountExistsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		logger.Warn("HTTP API: Error checking account existence", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error checking account existence")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"exists":  result.Exists,
		"deleted": result.Deleted,
		"status":  result.Status,
	})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	ctx := r.Context()

	accountDetails, err := s.rdb.GetAccountDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error getting account details", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get account details")
		return
	}

	s.writeJSON(w, http.StatusOK, accountDetails)
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	email := r.PathValue("email")

	var req UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Password == "" && req.PasswordHash == "" {
		s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
		return
	}

	if req.Password != "" && req.PasswordHash != "" {
		s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
		return
	}

	ctx := r.Context()

	// Update account using the database's method
	updateReq := db.UpdateAccountRequest{
		Email:        email,
		Password:     req.Password,
		PasswordHash: req.PasswordHash,
		HashType:     "bcrypt",
	}

	err := s.rdb.UpdateAccountWithRetry(ctx, updateReq)
	if err != nil {
		logger.Warn("HTTP API: Error updating account", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update account")
		return
	}

	// The old password stops working now, not when a cached login expires.
	s.forgetAccountLogins(s.trackedAccountID(ctx, email), email)

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "Account updated successfully",
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	ctx := r.Context()

	if r.URL.Query().Get("purge") == "true" {
		s.handlePurgeAccount(w, r, email)
		return
	}

	accountID := s.trackedAccountID(ctx, email)
	err := s.rdb.DeleteAccountWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountAlreadyDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			logger.Warn("HTTP API: Error deleting account", "name", s.name, "email", email, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Error deleting account")
			return
		}
	}

	// A deleted account is signed out everywhere, and cannot sign back in from a
	// cached login.
	s.endAccountSessions(accountID, email)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Account soft-deleted successfully. It will be permanently removed after the grace period.",
	})
}

func (s *Server) handleRestoreAccount(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	ctx := r.Context()

	err := s.rdb.RestoreAccountWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountNotDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			logger.Warn("HTTP API: Error restoring account", "name", s.name, "email", email, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Error restoring account")
			return
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Account restored successfully.",
	})
}

func (s *Server) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	primaryEmail := r.PathValue("email")

	var req AddCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Email == "" {
		s.writeError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.Password == "" && req.PasswordHash == "" {
		s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
		return
	}

	if req.Password != "" && req.PasswordHash != "" {
		s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
		return
	}

	ctx := r.Context()

	// 1. Get the account ID for the primary email address in the path.
	accountID, err := s.rdb.GetActiveAccountIDByAddressWithRetry(ctx, primaryEmail)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found for the specified primary email")
			return
		}
		logger.Warn("HTTP API: Error getting account ID", "name", s.name, "email", primaryEmail, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to find account")
		return
	}

	// 2. Add the new credential to the existing account.
	// This assumes a new database method `AddCredential` exists.
	addReq := db.AddCredentialRequest{
		AccountID:       accountID,
		NewEmail:        req.Email,
		NewPassword:     req.Password,
		NewPasswordHash: req.PasswordHash,
		NewHashType:     "bcrypt",
	}

	err = s.rdb.AddCredentialWithRetry(ctx, addReq)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.writeError(w, http.StatusConflict, "Credential with this email already exists")
			return
		}
		logger.Warn("HTTP API: Error adding credential", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to add credential")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"new_email": req.Email,
		"message":   "Credential added successfully",
	})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	ctx := r.Context()

	credentials, err := s.rdb.ListCredentialsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error listing credentials", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list credentials")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":       email,
		"credentials": credentials,
		"count":       len(credentials),
	})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	ctx := r.Context()

	// Get detailed credential information using the same logic as CLI
	credentialDetails, err := s.rdb.GetCredentialDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		logger.Warn("HTTP API: Error getting credential details", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get credential details")
		return
	}

	s.writeJSON(w, http.StatusOK, credentialDetails)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	ctx := r.Context()

	// Resolved first: once the credential is gone, the address names no account.
	accountID := s.trackedAccountID(ctx, email)
	err := s.rdb.DeleteCredentialWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, server.ErrInvalidAddress) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Check for specific user-facing errors from the DB layer
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrCannotDeleteLastCredential) || errors.Is(err, db.ErrCannotDeletePrimaryCredential) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Generic server error for other issues
		logger.Warn("HTTP API: Error deleting credential", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete credential")
		return
	}

	// The address stops signing in now, not when a cached login expires.
	s.forgetAccountLogins(accountID, email)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Credential deleted successfully",
	})
}

// trackers returns a copy of this node's connection trackers (nil without any). The
// node's servers register their trackers and proxies from their own start goroutines
// while the Admin API already serves, so the maps are only read through the
// ConnectionTrackers / ProxyServers accessors, which copy them under the lock their
// owner writes them under.
func (s *Server) trackers() map[string]*server.ConnectionTracker {
	if s.connectionTrackers == nil {
		return nil
	}
	return s.connectionTrackers()
}

// trackedAccountID resolves the account an account change applies to, for
// endAccountSessions and forgetAccountLogins. It is zero when this node has no
// servers to tell, or when the address names no account.
func (s *Server) trackedAccountID(ctx context.Context, address string) int64 {
	if len(s.trackers()) == 0 {
		return 0
	}
	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, address)
	if err != nil {
		if !errors.Is(err, consts.ErrUserNotFound) {
			logger.Warn("HTTP API: Cannot resolve account; its sessions and cached logins are left as they are",
				"name", s.name, "email", address, "error", err)
		}
		return 0
	}
	return accountID
}

// endAccountSessions closes the account's sessions on this node's servers and,
// through the trackers that gossip, on their cluster peers. A kick also drops the
// account's cached logins.
func (s *Server) endAccountSessions(accountID int64, address string) {
	if accountID == 0 {
		return
	}
	for key, tracker := range s.trackers() {
		if tracker == nil {
			continue
		}
		if err := tracker.KickUser(accountID, key); err != nil {
			logger.Warn("HTTP API: Error ending sessions", "name", s.name, "email", address, "tracker", key, "error", err)
		}
	}
}

// forgetAccountLogins drops the account's cached logins on this node's servers
// and, through the trackers that gossip, on their cluster peers, so that its next
// login is checked against the database. Its sessions are left alone.
func (s *Server) forgetAccountLogins(accountID int64, address string) {
	if accountID == 0 {
		return
	}
	for key, tracker := range s.trackers() {
		if tracker == nil {
			continue
		}
		if err := tracker.ForgetLogins(accountID, address); err != nil {
			logger.Warn("HTTP API: Error dropping cached logins", "name", s.name, "email", address, "tracker", key, "error", err)
		}
	}
}

// extractProtocolFromKey extracts the protocol name from a tracker key.
// Examples:
//
//	"LMTP-host1-lmtp-proxy" -> "LMTP"
//	"IMAP-backend1" -> "IMAP"
//	"POP3-host2-pop3-proxy" -> "POP3"
func extractProtocolFromKey(key string) string {
	// Find first dash
	dashIdx := -1
	for i, c := range key {
		if c == '-' {
			dashIdx = i
			break
		}
	}
	if dashIdx > 0 {
		return key[:dashIdx]
	}
	// No dash found, return as-is
	return key
}

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	trackers := s.trackers()
	if len(trackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"connections": []any{},
			"count":       0,
			"note":        "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	// Collect connections from all trackers
	// Only report connections where this tracker instance has actual local connections
	// This prevents duplicate entries where trackers report gossip data from other instances
	allConnections := make([]map[string]any, 0)
	for trackerKey, tracker := range trackers {
		if tracker == nil {
			continue
		}
		instanceID := tracker.GetInstanceID()
		conns := tracker.GetAllConnections()
		for _, connInfo := range conns {
			// Only report if this tracker instance has local connections for this user
			// Skip entries that are purely gossip data from other instances
			localCount := connInfo.GetLocalCount(instanceID)
			if localCount == 0 {
				continue // Skip - this is only gossip data, not an actual connection on this instance
			}

			// Extract protocol from tracker key
			// Key format: "PROTOCOL-node-servername" (proxies) or "PROTOCOL-servername"
			// Display: Just "PROTOCOL" for simplicity
			protocol := extractProtocolFromKey(trackerKey)

			allConnections = append(allConnections, map[string]any{
				"protocol":    protocol,
				"instance":    trackerKey, // Full key for debugging/filtering
				"account_id":  connInfo.AccountID,
				"local_count": localCount,
				"total_count": connInfo.GetTotalCount(),
				"last_update": connInfo.LastUpdate,
				"email":       connInfo.Username,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"connections": allConnections,
		"count":       len(allConnections),
		"source":      "in-memory connection tracker",
	})
}

func (s *Server) handleKickConnections(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req KickConnectionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ctx := r.Context()

	// Require user email for gossip-based kick
	if req.UserEmail == "" {
		s.writeError(w, http.StatusBadRequest, "user_email is required for kick operation")
		return
	}

	// Get account ID from email
	// Try database first (for local accounts)
	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, req.UserEmail)
	if err != nil {
		// User not found in database - could be a remotelookup account
		// Derive accountID from email (same logic as remotelookup)
		accountID = proxy.DeriveAccountIDFromEmail(req.UserEmail)
		logger.Info("HTTP API: User not in database, using derived accountID for kick", "name", s.name, "email", req.UserEmail, "derived_account_id", accountID)
	}

	trackers := s.trackers()
	if len(trackers) == 0 {
		// No connection trackers available (not running in cluster/proxy mode)
		logger.Debug("HTTP API: No connection trackers available - gossip-based kick requires cluster mode", "name", s.name)
		s.writeError(w, http.StatusServiceUnavailable, "Connection tracking not available (requires cluster mode)")
		return
	}

	// Determine which trackers to kick
	// If protocol is specified, match trackers by prefix (e.g., "IMAP" matches "IMAP-*")
	// If not specified, kick all trackers
	var trackersToKick []struct {
		key     string
		tracker *server.ConnectionTracker
	}

	if req.Protocol != "" {
		// Find all trackers that match the protocol prefix
		normalizedProtocol := strings.ToUpper(req.Protocol)
		for trackerKey, tracker := range trackers {
			// Extract protocol from tracker key (format: "PROTOCOL-node-servername")
			trackerProtocol := extractProtocolFromKey(trackerKey)
			if strings.ToUpper(trackerProtocol) == normalizedProtocol {
				trackersToKick = append(trackersToKick, struct {
					key     string
					tracker *server.ConnectionTracker
				}{trackerKey, tracker})
			}
		}
	} else {
		// Kick all trackers if no protocol specified
		for trackerKey, tracker := range trackers {
			trackersToKick = append(trackersToKick, struct {
				key     string
				tracker *server.ConnectionTracker
			}{trackerKey, tracker})
		}
	}

	if len(trackersToKick) == 0 {
		if req.Protocol != "" {
			s.writeError(w, http.StatusNotFound, fmt.Sprintf("No connection trackers found for protocol: %s", req.Protocol))
		} else {
			s.writeError(w, http.StatusInternalServerError, "No connection trackers available")
		}
		return
	}

	// Kick user on all matching trackers
	kickedProtocols := []string{}
	for _, item := range trackersToKick {
		if item.tracker == nil {
			logger.Debug("HTTP API: Nil tracker", "name", s.name, "tracker_key", item.key)
			continue
		}

		if err := item.tracker.KickUser(accountID, item.key); err != nil {
			logger.Warn("HTTP API: Error kicking user on tracker", "name", s.name, "email", req.UserEmail, "tracker", item.key, "error", err)
			continue
		}

		kickedProtocols = append(kickedProtocols, item.key)
		logger.Info("HTTP API: Kicked user on tracker", "name", s.name, "email", req.UserEmail, "account_id", accountID, "tracker", item.key)
	}

	if len(kickedProtocols) == 0 {
		s.writeError(w, http.StatusInternalServerError, "Failed to kick user on any protocol")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":   "User kicked successfully via gossip protocol",
		"user":      req.UserEmail,
		"protocols": kickedProtocols,
		"note":      "Kick event broadcast to cluster. Connections will be terminated within seconds.",
	})
}

func (s *Server) handleConnectionStats(w http.ResponseWriter, r *http.Request) {
	trackers := s.trackers()
	if len(trackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"total_connections":       0,
			"connections_by_protocol": map[string]int{},
			"note":                    "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	// Aggregate stats from all trackers
	totalConnections := 0
	byProtocol := make(map[string]int)

	for protocol, tracker := range trackers {
		if tracker == nil {
			continue
		}
		// Connections on this node, as GET /admin/connections lists them: not the
		// number of accounts, and not what other nodes report through gossip.
		count := tracker.GetLocalConnectionTotal()
		totalConnections += count
		byProtocol[protocol] = count
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"total_connections":       totalConnections,
		"connections_by_protocol": byProtocol,
		"source":                  "in-memory connection tracker",
	})
}

func (s *Server) handleGetUserConnections(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	trackers := s.trackers()
	if len(trackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"email":       email,
			"connections": []any{},
			"count":       0,
			"note":        "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	// Collect connections for this user from all trackers
	// Filter by email string matching (case-insensitive) - no database lookup needed
	// The connection tracker already stores the username (email) via gossip
	userConnections := make([]map[string]any, 0)
	emailLower := strings.ToLower(email)

	for protocol, tracker := range trackers {
		if tracker == nil {
			continue
		}
		instanceID := tracker.GetInstanceID()
		conns := tracker.GetAllConnections()
		for _, connInfo := range conns {
			// Match email case-insensitively
			if strings.ToLower(connInfo.Username) == emailLower {
				userConnections = append(userConnections, map[string]any{
					"protocol":    protocol,
					"account_id":  connInfo.AccountID,
					"email":       connInfo.Username,
					"local_count": connInfo.GetLocalCount(instanceID),
					"total_count": connInfo.GetTotalCount(),
					"last_update": connInfo.LastUpdate,
				})
			}
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":       email,
		"connections": userConnections,
		"count":       len(userConnections),
		"source":      "in-memory connection tracker",
	})
}

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats")
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleCacheMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	instanceID := r.URL.Query().Get("instance_id")
	sinceParam := r.URL.Query().Get("since")
	limitParam := r.URL.Query().Get("limit")
	latest := r.URL.Query().Get("latest") == "true"

	limit := 100
	if limitParam != "" {
		if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
			limit = l
		}
	}

	if latest {
		// Get latest metrics
		metrics, err := s.rdb.GetLatestCacheMetricsWithRetry(ctx)
		if err != nil {
			logger.Warn("HTTP API: Error getting latest cache metrics", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get latest cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"metrics": metrics,
			"count":   len(metrics),
		})
	} else {
		// Get historical metrics
		var since time.Time
		if sinceParam != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceParam)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "Invalid since parameter format (use RFC3339)")
				return
			}
		} else {
			since = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
		}

		metrics, err := s.rdb.GetCacheMetricsWithRetry(ctx, instanceID, since, limit)
		if err != nil {
			logger.Warn("HTTP API: Error getting cache metrics", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"metrics":     metrics,
			"count":       len(metrics),
			"instance_id": instanceID,
			"since":       since,
		})
	}
}

func (s *Server) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	ctx := r.Context()

	// Get stats before purge
	statsBefore, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats before purge", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats before purge")
		return
	}

	// Purge cache
	err = s.cache.PurgeAll(ctx)
	if err != nil {
		logger.Warn("HTTP API: Error purging cache", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to purge cache")
		return
	}

	// Get stats after purge
	statsAfter, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats after purge", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats after purge")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":      "Cache purged successfully",
		"stats_before": statsBefore,
		"stats_after":  statsAfter,
	})
}

func (s *Server) handleHealthOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get query parameter for hostname, default to empty for system-wide
	hostname := r.URL.Query().Get("hostname")

	overview, err := s.rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		logger.Warn("HTTP API: Error getting health overview", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health overview")
		return
	}

	s.writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleHealthStatusByHost(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from path: /admin/health/servers/{hostname}
	hostname := extractPathParam(r.URL.Path, "/admin/health/servers/", "")

	ctx := r.Context()

	statuses, err := s.rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
	if err != nil {
		logger.Warn("HTTP API: Error getting health statuses for host", "name", s.name, "hostname", hostname, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health statuses for host")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"hostname": hostname,
		"statuses": statuses,
		"count":    len(statuses),
	})
}

func (s *Server) handleHealthStatusByComponent(w http.ResponseWriter, r *http.Request) {
	// Extract hostname and component from path: /admin/health/servers/{hostname}/components/{component}
	path := r.URL.Path
	// Remove prefix to get "{hostname}/components/{component}"
	remaining := strings.TrimPrefix(path, "/admin/health/servers/")
	// Split by "/components/"
	parts := strings.Split(remaining, "/components/")
	if len(parts) != 2 {
		s.writeError(w, http.StatusBadRequest, "Invalid path format")
		return
	}
	hostname := parts[0]
	component := parts[1]

	ctx := r.Context()

	// Parse query parameters for history
	showHistory := r.URL.Query().Get("history") == "true"
	sinceParam := r.URL.Query().Get("since")
	limitParam := r.URL.Query().Get("limit")

	if showHistory {
		// Get historical health status
		var since time.Time
		if sinceParam != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceParam)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "Invalid since parameter format (use RFC3339)")
				return
			}
		} else {
			since = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
		}

		limit := 100
		if limitParam != "" {
			if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
				limit = l
			}
		}

		history, err := s.rdb.GetHealthHistoryWithRetry(ctx, hostname, component, since, limit)
		if err != nil {
			logger.Warn("HTTP API: Error getting health history", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get health history")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"hostname":  hostname,
			"component": component,
			"history":   history,
			"count":     len(history),
			"since":     since,
		})
	} else {
		// Get current health status
		status, err := s.rdb.GetHealthStatusWithRetry(ctx, hostname, component)
		if err != nil {
			// This could be a normal "not found" case, so don't log as a server error
			s.writeError(w, http.StatusNotFound, "Health status not found")
			return
		}
		s.writeJSON(w, http.StatusOK, status)
	}
}

// handleProxyBackends returns backend health status for all proxy servers
func (s *Server) handleProxyBackends(w http.ResponseWriter, r *http.Request) {
	response := ProxyBackendsResponse{
		Timestamp: time.Now(),
		Proxies:   make([]ProxyBackendInfo, 0),
	}

	// Iterate through all registered proxy servers
	if s.proxyServers != nil {
		for proxyName, proxyServer := range s.proxyServers() {
			if proxyServer == nil {
				continue
			}

			connMgr := proxyServer.GetConnectionManager()
			if connMgr == nil {
				continue
			}

			// Get backend health statuses from the connection manager
			backendStatuses := connMgr.GetBackendHealthStatuses()

			// Convert proxy.BackendHealthInfo to adminapi.BackendHealthInfo
			backends := make([]BackendHealthInfo, len(backendStatuses))
			for i, status := range backendStatuses {
				backends[i] = BackendHealthInfo{
					Address:            status.Address,
					Pool:               status.Pool,
					IsHealthy:          status.IsHealthy,
					FailureCount:       status.FailureCount,
					ConsecutiveFails:   status.ConsecutiveFails,
					LastFailure:        status.LastFailure,
					LastSuccess:        status.LastSuccess,
					HealthCheckEnabled: status.HealthCheckEnabled,
					IsRemoteLookup:     status.IsRemoteLookup,
					InMaintenance:      status.InMaintenance,
				}
			}

			response.Proxies = append(response.Proxies, ProxyBackendInfo{
				ProxyName: proxyName,
				Backends:  backends,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUploaderStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	showFailedStr := r.URL.Query().Get("show_failed")
	maxAttemptsStr := r.URL.Query().Get("max_attempts")

	maxAttempts := s.uploadMaxAttempts // the uploader gives up after this many
	if maxAttemptsStr != "" {
		if ma, err := strconv.Atoi(maxAttemptsStr); err == nil && ma > 0 {
			maxAttempts = ma
		}
	}

	// Get uploader stats
	stats, err := s.rdb.GetUploaderStatsWithRetry(ctx, maxAttempts)
	if err != nil {
		logger.Warn("HTTP API: Error getting uploader stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get uploader stats")
		return
	}

	response := map[string]any{
		"stats": stats,
	}

	// Include failed uploads if requested
	if showFailedStr == "true" {
		failedLimitStr := r.URL.Query().Get("failed_limit")
		failedLimit := 10
		if failedLimitStr != "" {
			if fl, err := strconv.Atoi(failedLimitStr); err == nil && fl > 0 {
				failedLimit = fl
			}
		}

		failedUploads, err := s.rdb.GetFailedUploadsWithRetry(ctx, maxAttempts, failedLimit)
		if err != nil {
			logger.Warn("HTTP API: Error getting failed uploads", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get failed uploads")
			return
		}

		response["failed_uploads"] = failedUploads
		response["failed_count"] = len(failedUploads)
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFailedUploads(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	maxAttemptsStr := r.URL.Query().Get("max_attempts")
	limitStr := r.URL.Query().Get("limit")

	maxAttempts := s.uploadMaxAttempts // the uploader gives up after this many
	if maxAttemptsStr != "" {
		if ma, err := strconv.Atoi(maxAttemptsStr); err == nil && ma > 0 {
			maxAttempts = ma
		}
	}

	limit := 50 // Default value
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	failedUploads, err := s.rdb.GetFailedUploadsWithRetry(ctx, maxAttempts, limit)
	if err != nil {
		logger.Warn("HTTP API: Error getting failed uploads", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get failed uploads")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"failed_uploads": failedUploads,
		"count":          len(failedUploads),
		"max_attempts":   maxAttempts,
		"limit":          limit,
	})
}

func (s *Server) handleAuthStats(w http.ResponseWriter, r *http.Request) {
	// Auth statistics are tracked in-memory via the rate limiter.
	// The window parameter is accepted for backwards compatibility but ignored.
	s.writeJSON(w, http.StatusOK, map[string]any{
		"implementation": "in-memory",
		"tracking_mode":  "per-address rate limiting with automatic expiry",
		"available_stats": map[string]string{
			"blocked_entries": "GET /admin/auth/blocked",
		},
		"access_methods": map[string]string{
			"blocked_list": "GET /admin/auth/blocked - list currently blocked addresses",
		},
	})
}

func (s *Server) handleAuthCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.authCache == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"note":    "Auth cache is not enabled. Enable it in [auth_cache] config section.",
		})
		return
	}

	ctx := r.Context()
	totalEntries, lifetimeHits, hits, misses, hitRate, err := s.authCache.Stats(ctx)
	if err != nil {
		logger.Warn("HTTP API: Error getting auth cache stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get auth cache stats")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"enabled":            true,
		"total_entries":      totalEntries,
		"session_hits":       hits,
		"session_misses":     misses,
		"hit_rate_percent":   hitRate,
		"lifetime_hit_count": lifetimeHits,
	})
}

func (s *Server) handleAuthBlocked(w http.ResponseWriter, r *http.Request) {
	// Get optional protocol filter from query parameter
	protocol := r.URL.Query().Get("protocol")

	var entries []server.BlockedEntry
	if protocol != "" {
		entries = server.GetBlockedEntriesByProtocol(protocol)
	} else {
		entries = server.GetAllBlockedEntries()
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"blocked_entries": entries,
		"count":           len(entries),
	})
}

// Message restoration handlers

func (s *Server) handleListDeletedMessages(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}/messages/deleted
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/messages/deleted")
	ctx := r.Context()

	// Parse query parameters
	mailboxPath := r.URL.Query().Get("mailbox")
	since := r.URL.Query().Get("since")
	until := r.URL.Query().Get("until")
	limitStr := r.URL.Query().Get("limit")

	// Build parameters
	params := db.ListDeletedMessagesParams{
		Email: email,
		Limit: 100, // default limit
	}

	if mailboxPath != "" {
		params.MailboxPath = &mailboxPath
	}

	if since != "" {
		sinceTime, err := parseTimeParam(since)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid since parameter: %v", err))
			return
		}
		params.Since = &sinceTime
	}

	if until != "" {
		untilTime, err := parseTimeParam(until)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid until parameter: %v", err))
			return
		}
		params.Until = &untilTime
	}

	// Validate time range: since must be before or equal to until
	if params.Since != nil && params.Until != nil && params.Since.After(*params.Until) {
		s.writeError(w, http.StatusBadRequest, "Invalid time range: 'since' must be before or equal to 'until'")
		return
	}

	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			s.writeError(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		params.Limit = limit
	}

	// List deleted messages
	messages, err := s.rdb.ListDeletedMessagesWithRetry(ctx, params)
	if err != nil {
		if errors.Is(err, db.ErrAccountNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error listing deleted messages", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing deleted messages")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":    email,
		"messages": messages,
		"total":    len(messages),
	})
}

func (s *Server) handleRestoreMessages(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Extract email from path: /admin/accounts/{email}/messages/restore
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/messages/restore")
	ctx := r.Context()

	var req struct {
		MessageIDs  []int64 `json:"message_ids,omitempty"`
		MailboxPath *string `json:"mailbox,omitempty"`
		Since       *string `json:"since,omitempty"`
		Until       *string `json:"until,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	// Validate that at least one filter is provided
	hasFilter := len(req.MessageIDs) > 0 || req.MailboxPath != nil || req.Since != nil || req.Until != nil
	if !hasFilter {
		s.writeError(w, http.StatusBadRequest, "At least one filter is required (message_ids, mailbox, since, or until)")
		return
	}

	// Validate message IDs are positive
	for _, id := range req.MessageIDs {
		if id <= 0 {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid message_id: %d (must be positive)", id))
			return
		}
	}

	// Build parameters
	params := db.RestoreMessagesParams{
		Email:       email,
		MessageIDs:  req.MessageIDs,
		MailboxPath: req.MailboxPath,
	}

	if req.Since != nil {
		sinceTime, err := parseTimeParam(*req.Since)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid since parameter: %v", err))
			return
		}
		params.Since = &sinceTime
	}

	if req.Until != nil {
		untilTime, err := parseTimeParam(*req.Until)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid until parameter: %v", err))
			return
		}
		params.Until = &untilTime
	}

	// Validate time range: since must be before or equal to until
	if params.Since != nil && params.Until != nil && params.Since.After(*params.Until) {
		s.writeError(w, http.StatusBadRequest, "Invalid time range: 'since' must be before or equal to 'until'")
		return
	}

	// Restore messages. Chunked: a failure part-way leaves already-restored chunks
	// committed; the caller can simply repeat the request to restore the remainder.
	count, err := s.rdb.RestoreMessagesWithRetry(ctx, params)
	if err != nil {
		if errors.Is(err, db.ErrAccountNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error restoring messages", "name", s.name, "restored", count, "error", err)
		if count > 0 {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Error restoring messages: %d message(s) restored before the failure; repeat the request to restore the rest", count))
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Error restoring messages")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":    email,
		"restored": count,
		"message":  fmt.Sprintf("Successfully restored %d message(s)", count),
	})
}

// parseTimeParam parses a time string in YYYY-MM-DD or RFC3339 format
func parseTimeParam(value string) (time.Time, error) {
	// Try parsing as YYYY-MM-DD first
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid date format (use YYYY-MM-DD or RFC3339)")
}

func (s *Server) handleConfigInfo(w http.ResponseWriter, r *http.Request) {
	// Return basic configuration information (non-sensitive)
	// This is useful for debugging and system information

	s.writeJSON(w, http.StatusOK, map[string]any{
		"server_type": "sora-http-api",
		"features_enabled": map[string]bool{
			"account_management":    true,
			"connection_management": true,
			"cache_management":      s.cache != nil,
			"health_monitoring":     true,
			"auth_statistics":       true,
			"uploader_monitoring":   true,
			"message_restoration":   true,
		},
		"endpoints": map[string][]string{
			"account_management": {
				"POST /admin/accounts",
				"GET /admin/accounts/{email}",
				"PUT /admin/accounts/{email}",
				"DELETE /admin/accounts/{email} (soft delete; ?purge=true requests permanent deletion now)",
				"POST /admin/accounts/{email}/restore",
				"GET /admin/accounts/{email}/exists",
				"POST /admin/accounts/{email}/credentials",
				"GET /admin/accounts/{email}/credentials",
			},
			"domain_management": {
				"GET /admin/domains/{domain}/accounts (list accounts scoped to domain)",
			},
			"usage": {
				"GET /admin/usage/accounts?after={account_id}&limit={n} (every account's storage, page by page)",
			},
			"credential_management": {
				"GET /admin/credentials/{email}",
			},
			"message_restoration": {
				"GET /admin/accounts/{email}/messages/deleted",
				"POST /admin/accounts/{email}/messages/restore",
			},
			"connection_management": {
				"GET /admin/connections",
				"GET /admin/connections/stats",
				"POST /admin/connections/kick",
				"GET /admin/connections/user/{email}",
			},
			"cache_management": {
				"GET /admin/cache/stats",
				"GET /admin/cache/metrics",
				"POST /admin/cache/purge",
			},
			"health_monitoring": {
				"GET /admin/health/overview",
				"GET /admin/health/servers/{hostname}",
				"GET /admin/health/servers/{hostname}/components/{component}",
			},
			"uploader_monitoring": {
				"GET /admin/uploader/status",
				"GET /admin/uploader/failed",
			},
			"auth_statistics": {
				"GET /admin/auth/stats",
				"GET /admin/auth/blocked",
			},
			"system_information": {
				"GET /admin/config",
			},
		},
	})
}
