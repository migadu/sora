package managesieveproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesieveserver"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/sieveengine"
)

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after: a session takes the one its
// protocol server was built with and keeps it, so it never mixes the values of two
// reloads. Debug logging and the master SASL credentials are read afresh, per log
// line and per backend login.
type reloadableSettings struct {
	maxAuthErrors          int // Maximum authentication errors before disconnection
	authIdleTimeout        time.Duration
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	debug                  bool
}

// loadSettings returns the current settings. A Server built without New (as tests
// do) has none stored and reads as zero, as its fields did.
func (s *Server) loadSettings() *reloadableSettings {
	if settings := s.settings.Load(); settings != nil {
		return settings
	}
	return &reloadableSettings{}
}

// Server represents a ManageSieve proxy server.
type Server struct {
	listener           net.Listener
	listenerMu         sync.RWMutex
	rdb                *resilient.ResilientDatabase
	name               string // Server name for logging
	addr               string
	hostname           string
	insecureAuth       bool
	masterUsername     []byte
	masterPassword     []byte
	tls                bool
	tlsUseStartTLS     bool
	tlsConfig          *tls.Config // What the listener serves with (server.ListenerTLS); nil without tls
	connManager        *proxy.ConnectionManager
	connTracker        *server.ConnectionTracker
	wg                 sync.WaitGroup
	ctx                context.Context
	cancel             context.CancelFunc
	enableAffinity     bool
	authLimiter        server.AuthLimiter
	trustedProxies     []string // CIDR blocks for trusted proxies that can forward parameters
	remotelookupConfig *config.RemoteLookupConfig

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Auth cache for routing and password validation
	lookupCache                *lookupcache.LookupCache
	positiveRevalidationWindow time.Duration

	// Listen backlog
	listenBacklog int

	// SIEVE extensions (additional to builtin)
	supportedExtensions []string

	// The settings ReloadConfig replaces; see reloadableSettings.
	settings atomic.Pointer[reloadableSettings]

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*Session]struct{}

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader

	// Startup throttle to prevent thundering herd on restart
	startupThrottleUntil time.Time

	// msLibServer is the go-managesieve protocol server. It is swapped
	// atomically on SIGHUP so reloaded settings apply to new connections
	// (existing connections keep the snapshot they were accepted with).
	msLibServer atomic.Pointer[managesieveserver.Server]
}

// ServerOptions holds options for creating a new ManageSieve proxy server.
type ServerOptions struct {
	Name                     string // Server name for logging
	Addr                     string
	RemoteAddrs              []string
	Pools                    []proxy.PoolSpec // Named backend pools ([[pool]] blocks); when set, RemoteAddrs is unused and each pool brings its own backend-leg settings
	RemotePort               int              // Default port for backends if not in address
	InsecureAuth             bool
	MasterUsername           string
	MasterPassword           string
	MasterSASLUsername       string
	MasterSASLPassword       string
	TLS                      bool
	TLSUseStartTLS           bool // Use STARTTLS on listening port
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS                bool
	RemoteTLSUseStartTLS     bool // Use STARTTLS for backend connections
	RemoteTLSVerify          bool
	RemoteTLSCAFile          string // PEM file with CA certs for backend verification (private-CA / self-signed backends); empty = system roots
	RemoteUseProxyProtocol   bool
	ConnectTimeout           time.Duration
	AuthIdleTimeout          time.Duration
	CommandTimeout           time.Duration // Idle timeout
	AbsoluteSessionTimeout   time.Duration // Maximum total session duration
	MinBytesPerMinute        int64         // Minimum throughput
	EnableAffinity           bool
	EnableBackendHealthCheck bool           // Enable backend health checking (default: true)
	RemoteDNSRefresh         *time.Duration // Backend DNS re-resolution interval; nil = default, 0 = pin to the startup resolution
	AuthRateLimit            server.AuthRateLimiterConfig
	RemoteLookup             *config.RemoteLookupConfig
	TrustedProxies           []string // CIDR blocks for trusted proxies that can forward parameters

	// Connection limiting
	MaxConnections      int      // Maximum total connections per instance (0 = unlimited, local only)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited, cluster-wide if ClusterManager provided)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits
	ListenBacklog       int      // TCP listen backlog size (0 = system default; recommended: 4096-8192)

	// Auth cache configuration
	LookupCache *config.LookupCacheConfig

	// Authentication limits
	MaxAuthErrors int // Maximum authentication errors before disconnection (0 = use default)

	// Cluster support
	ClusterManager       *cluster.Manager                  // Optional: shares per-IP connection counts and auth rate limits with the cluster
	ClusterRateLimitSync config.ClusterRateLimitSyncConfig // [cluster.rate_limit_sync]; read only with ClusterManager

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol        bool   // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout string // Timeout for reading PROXY protocol headers (e.g., "5s")

	// Debug logging
	Debug bool // Enable debug logging

	// SIEVE extensions
	SupportedExtensions []string // Additional SIEVE extensions beyond builtins (e.g., ["vacation", "regex"])
}

// New creates a new ManageSieve proxy server.
func New(appCtx context.Context, rdb *resilient.ResilientDatabase, hostname string, opts ServerOptions) (*Server, error) {
	ctx, cancel := context.WithCancel(appCtx)

	if len(opts.RemoteAddrs) == 0 && len(opts.Pools) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses or backend pools configured")
	}

	// Set default timeout if not specified
	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Ensure RemoteLookup config has a default value to avoid nil panics.
	if opts.RemoteLookup == nil {
		opts.RemoteLookup = &config.RemoteLookupConfig{}
	}

	// Validate TLS configuration: tls_use_starttls only makes sense when tls = true
	if !opts.TLS && opts.TLSUseStartTLS {
		logger.Debug("ManageSieve Proxy: WARNING - tls_use_starttls ignored because tls=false", "name", opts.Name)
		// Force TLSUseStartTLS to false to avoid confusion
		opts.TLSUseStartTLS = false
	}

	// Initialize remotelookup client if configured
	routingLookup, err := proxy.InitializeRemoteLookup("managesieve", opts.RemoteLookup, opts.RemotePort)
	if err != nil {
		logger.Debug("ManageSieve Proxy: Failed to initialize remotelookup client", "name", opts.Name, "error", err)
		if opts.RemoteLookup != nil && !opts.RemoteLookup.ShouldLookupLocalUsers() {
			cancel()
			return nil, fmt.Errorf("failed to initialize remotelookup client: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Continuing without remotelookup - local lookup enabled", "name", opts.Name)
	}
	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
		Pools:              opts.Pools,
		RemoteAddrs:        opts.RemoteAddrs,
		RemotePort:         opts.RemotePort,
		Settings:           proxy.BackendSettings{TLS: opts.RemoteTLS, TLSUseStartTLS: opts.RemoteTLSUseStartTLS, TLSVerify: opts.RemoteTLSVerify, UseProxyProtocol: opts.RemoteUseProxyProtocol},
		RemoteTLSCAFile:    opts.RemoteTLSCAFile,
		ConnectTimeout:     connectTimeout,
		RoutingLookup:      routingLookup,
		ServerName:         opts.Name,
		DisableHealthCheck: !opts.EnableBackendHealthCheck,
	})
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
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
		logger.Debug("ManageSieve Proxy: Failed to resolve addresses", "name", opts.Name, "error", err)
	}

	// Resolve the SIEVE extensions as the backend and delivery do (the
	// configured names the engine supports, or the default set), so the proxy
	// never advertises what the backend will refuse.
	if invalid := sieveengine.InvalidExtensions(opts.SupportedExtensions); len(invalid) > 0 {
		logger.Warn("ManageSieveProxy: ignoring invalid SIEVE extensions", "name", opts.Name, "invalid", invalid, "supported", managesieve.SupportedExtensions)
	}
	opts.SupportedExtensions = sieveengine.EffectiveExtensions(opts.SupportedExtensions)

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("SIEVE-PROXY", opts.Name, hostname, opts.AuthRateLimit, opts.TrustedProxies)
	server.RegisterRateLimiter("managesieve_proxy", opts.Name, authLimiter)
	authLimiter.JoinCluster(opts.ClusterManager, opts.ClusterRateLimitSync)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		if opts.ClusterManager != nil {
			// Cluster mode: use cluster-wide per-IP limiting
			instanceID := fmt.Sprintf("sieve-proxy-%s-%d", hostname, time.Now().UnixNano())
			limiter = server.NewConnectionLimiterWithCluster("SIEVE-PROXY", instanceID, opts.ClusterManager, opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
		} else {
			// Local mode: use local-only limiting
			limiter = server.NewConnectionLimiterWithTrustedNets("SIEVE-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
		}
	}

	// Set listen backlog with reasonable default
	listenBacklog := opts.ListenBacklog
	if listenBacklog == 0 {
		listenBacklog = 1024 // Default backlog
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
		proxyReader, err = server.NewProxyProtocolReader("SIEVE-PROXY", proxyConfig)
		if err != nil {
			if routingLookup != nil {
				routingLookup.Close()
			}
			cancel()
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "proxy", opts.Name)
	}

	// Initialize auth cache for user authentication and routing
	// Initialize authentication cache from config
	// Apply defaults if not configured (enabled by default for performance)
	var lookupCache *lookupcache.LookupCache
	var positiveRevalidationWindow time.Duration
	lookupCacheConfig := opts.LookupCache
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	if lookupCacheConfig.Enabled && !proxy.RemoteLookupUsesClientIP(opts.RemoteLookup) {
		positiveTTL := lookupCacheConfig.GetPositiveTTLWithDefault(opts.Name)
		negativeTTL := lookupCacheConfig.GetNegativeTTLWithDefault(opts.Name)
		cleanupInterval := lookupCacheConfig.GetCleanupIntervalWithDefault(opts.Name)
		maxSize := lookupCacheConfig.GetMaxSize()

		// Parse positive revalidation window from config (used for password change detection)
		positiveRevalidationWindow = lookupCacheConfig.GetPositiveRevalidationWindowWithDefault(opts.Name)

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("ManageSieve Proxy: Lookup cache enabled", "name", opts.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	} else {
		logger.Info("ManageSieve Proxy: Lookup cache disabled", "name", opts.Name)
	}

	s := &Server{
		rdb:                        rdb,
		name:                       opts.Name,
		addr:                       opts.Addr,
		hostname:                   hostname,
		insecureAuth:               opts.InsecureAuth || !opts.TLS, // Auto-enable when TLS not configured
		masterUsername:             []byte(opts.MasterUsername),
		masterPassword:             []byte(opts.MasterPassword),
		tls:                        opts.TLS,
		tlsUseStartTLS:             opts.TLSUseStartTLS,
		connManager:                connManager,
		ctx:                        ctx,
		cancel:                     cancel,
		enableAffinity:             opts.EnableAffinity,
		authLimiter:                authLimiter,
		trustedProxies:             opts.TrustedProxies,
		remotelookupConfig:         opts.RemoteLookup,
		limiter:                    limiter,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		listenBacklog:              listenBacklog,
		supportedExtensions:        opts.SupportedExtensions,
		activeSessions:             make(map[*Session]struct{}),
		proxyReader:                proxyReader,
	}
	s.settings.Store(&reloadableSettings{
		maxAuthErrors:          opts.MaxAuthErrors,
		authIdleTimeout:        opts.AuthIdleTimeout,
		commandTimeout:         opts.CommandTimeout,
		absoluteSessionTimeout: opts.AbsoluteSessionTimeout,
		minBytesPerMinute:      opts.MinBytesPerMinute,
		masterSASLUsername:     []byte(opts.MasterSASLUsername),
		masterSASLPassword:     []byte(opts.MasterSASLPassword),
		debug:                  opts.Debug,
	})

	// One TLS config for implicit TLS and STARTTLS; the certificate source and
	// tls_verify follow the rule every listener shares (server.ListenerTLS).
	if opts.TLS {
		tlsConfig, err := server.ListenerTLS{
			Protocol: "ManageSieve proxy", Name: opts.Name,
			CertFile: opts.TLSCertFile, KeyFile: opts.TLSKeyFile, Verify: opts.TLSVerify,
			Global: opts.TLSConfig, ALPN: []string{"sieve"},
		}.Config()
		if err != nil {
			cancel()
			return nil, err
		}
		s.tlsConfig = tlsConfig
	}

	s.msLibServer.Store(s.buildLibServer())

	return s, nil
}

// buildLibServer constructs the go-managesieve protocol server from the
// current runtime settings. It is called at startup and again from
// ReloadConfig so SIGHUP-reloaded settings apply to new connections.
func (s *Server) buildLibServer() *managesieveserver.Server {
	settings := s.loadSettings()

	maxErrors := settings.maxAuthErrors
	if maxErrors <= 0 {
		maxErrors = 10
	}

	// STARTTLS upgrades are the library's job only on plaintext listeners;
	// implicit-TLS listeners keep TLS outside the library (SoraTLSListener +
	// deferred handshake).
	var startTLSConfig *tls.Config
	if s.tls && s.tlsUseStartTLS {
		startTLSConfig = server.StartTLSConfig(s.tlsConfig, "managesieve_proxy") // records JA4, as SoraTLSConn does for implicit TLS
	}

	opts := managesieveserver.Options{
		TLSConfig:              startTLSConfig,
		OnStartTLS:             server.BeginStartTLS,
		OnTLSHandshakeComplete: server.CompleteStartTLS,
		Implementation:         "Sora ManageSieve Proxy",
		Greeting:               `"ManageSieve proxy ready"`,
		GreetingStartTLSHint:   false, // pre-migration parity: the proxy greeting carried no (STARTTLS) hint
		SieveExtensions:        managesieve.GetSieveCapabilities(s.supportedExtensions),
		MaxLineLength:          8192,
		IdleTimeout:            settings.commandTimeout,
		AuthIdleTimeout:        settings.authIdleTimeout,
		AbsoluteSessionTimeout: settings.absoluteSessionTimeout,
		InsecureAuth:           s.insecureAuth,
		MaxErrors:              maxErrors,
		// Pre-migration parity: failed logins never counted toward the auth
		// error budget on the proxy — the auth rate limiter handles
		// brute-force across connections, so a user who mistypes a password
		// must not be disconnected.
		AuthFailuresExemptFromMaxErrors: true,
		StrictSessionErrors:             true, // Session errors are *managesieveserver.Error; mask anything else
		NewSession: func(c *managesieveserver.Conn) (managesieveserver.Session, error) {
			netConn := c.NetConn()
			proxyInfo := server.GetProxyProtocolInfo(netConn)

			var releaseConn func()
			var err error
			if s.limiter != nil {
				releaseConn, err = s.limiter.AcceptWithRealIP(netConn.RemoteAddr(), server.GetRealClientIP(netConn, proxyInfo))
				if err != nil {
					// DELIBERATE silent close, no banner: matches the previous
					// accept-loop rejection (drop before any greeting), and a
					// "too many connections" banner would tell a flooder
					// exactly when the limiter engages.
					return nil, fmt.Errorf("%w: %w", managesieveserver.ErrSilentReject, err)
				}
			}

			// Implicit-TLS listeners (SoraTLSListener) defer the TLS
			// handshake; the library never triggers it, so complete it here —
			// after the limiter and before the greeting is written. Also
			// captures JA4 and registers the timeout checker for TLS conns.
			if didTLS, err := server.PerformDeferredTLSHandshake(netConn); err != nil {
				if releaseConn != nil {
					releaseConn()
				}
				logger.Debug("ManageSieve Proxy: TLS handshake failed", "proxy", s.name, "remote", server.GetAddrString(netConn.RemoteAddr()), "error", err)
				return nil, fmt.Errorf("%w: TLS handshake: %w", managesieveserver.ErrSilentReject, err)
			} else if didTLS {
				c.SetTLS(true)
			}

			// Count the connection only once it is past every rejection
			// point, so the decrements in the session close path always
			// balance.
			metrics.ConnectionsTotal.WithLabelValues("managesieve_proxy", s.name, s.hostname).Inc()
			metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy", s.name, s.hostname).Inc()

			sessionCtx, sessionCancel := context.WithCancel(s.ctx)

			// Determine client address (use PROXY protocol info if available)
			clientAddr := server.GetAddrString(netConn.RemoteAddr())
			if proxyInfo != nil && proxyInfo.SrcIP != "" {
				clientAddr = proxyInfo.SrcIP
			}

			session := &Session{
				server:       s,
				settings:     settings,
				msConn:       c,
				clientConn:   netConn,
				listenerConn: netConn,
				clientAddr:   clientAddr,
				ctx:          sessionCtx,
				cancel:       sessionCancel,
				startTime:    time.Now(),
				releaseConn:  releaseConn,
				proxyInfo:    proxyInfo,
				// Generate the session id once, up front, so every log line
				// carries it.
				sessionID: idgen.New(),
			}

			session.InfoLog("connected")
			s.addSession(session)
			return session, nil
		},
	}

	return managesieveserver.New(opts)
}

// connConfig is the SoraConn configuration for a connection accepted now. The
// listener asks for it at every accept, so the timeouts a reload changes reach the
// connections accepted after it, as they reach the protocol server rebuilt for them.
func (s *Server) connConfig() server.SoraConnConfig {
	settings := s.loadSettings()
	return server.SoraConnConfig{
		Protocol:             "managesieve_proxy",
		ServerName:           s.name,
		Hostname:             s.hostname,
		IdleTimeout:          settings.commandTimeout,
		AbsoluteTimeout:      settings.absoluteSessionTimeout,
		NoAbsoluteTimeout:    settings.absoluteSessionTimeout <= 0,
		MinBytesPerMinute:    settings.minBytesPerMinute,
		EnableTimeoutChecker: settings.commandTimeout > 0 || settings.absoluteSessionTimeout > 0 || settings.minBytesPerMinute > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send BYE with TRYLATER before closing (RFC 5804)
			var message string
			switch reason {
			case "idle":
				message = "BYE (TRYLATER) \"Idle timeout, please reconnect\"\r\n"
			case "slow_throughput":
				message = "BYE (TRYLATER) \"Connection too slow, please reconnect\"\r\n"
			case "session_max":
				message = "BYE (TRYLATER) \"Maximum session duration exceeded, please reconnect\"\r\n"
			default:
				message = "BYE (TRYLATER) \"Connection timeout, please reconnect\"\r\n"
			}
			_, _ = fmt.Fprint(conn, message)
		},
	}
}

// Start starts the ManageSieve proxy server.
func (s *Server) Start() error {

	// Three TLS scenarios (New resolved the certificate source into s.tlsConfig):
	// 1. Implicit TLS: TLS listener
	// 2. STARTTLS mode: Use plain listener, upgrade to TLS in session after STARTTLS command
	// 3. No TLS: Plain text listener

	if s.tls && !s.tlsUseStartTLS && s.tlsConfig != nil {
		// Scenario 1: Implicit TLS
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog with implicit TLS", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraTLSListener for implicit TLS with JA4 capture and timeout protection
		s.listener = server.NewSoraTLSListenerFunc(s.wrapProxyProtocol(tcpListener), s.tlsConfig, s.connConfig)
		s.listenerMu.Unlock()
	} else if s.tls && s.tlsUseStartTLS {
		// Scenario 2: STARTTLS mode - plain listener, TLS upgrade happens in session
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog with STARTTLS mode", "proxy", s.name, "backlog", s.listenBacklog)
		// Use plain SoraListener - TLS upgrade handled in session after STARTTLS command
		s.listener = server.NewSoraListenerFunc(s.wrapProxyProtocol(tcpListener), s.connConfig)
		s.listenerMu.Unlock()
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for ManageSieve proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
	} else {
		// Scenario 3: No TLS - plain text listener
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog (no TLS)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraListener for non-TLS with timeout protection
		s.listener = server.NewSoraListenerFunc(s.wrapProxyProtocol(tcpListener), s.connConfig)
		s.listenerMu.Unlock()
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	// Startup throttle: spread reconnection load after proxy restart
	// to prevent thundering herd on the database connection pool
	s.startupThrottleUntil = time.Now().Add(30 * time.Second)
	logger.Info("ManageSieve Proxy: Startup throttle active for 30s (5ms delay between accepts)", "proxy", s.name)

	// Start session monitoring routine
	go s.monitorActiveSessions()

	return s.acceptConnections()
}

// acceptConnections accepts incoming connections.
func (s *Server) acceptConnections() error {
	for {
		// Startup throttle: spread reconnection load after proxy restart
		// to prevent thundering herd on the database connection pool
		if time.Now().Before(s.startupThrottleUntil) {
			time.Sleep(5 * time.Millisecond)
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // Graceful shutdown
			default:
				// All Accept() errors are connection-level issues (TLS handshake failures, client disconnects, etc.)
				// They should be logged but not crash the server - the listener itself is still healthy
				logger.Debug("ManageSieve Proxy: Failed to accept connection", "name", s.name, "error", err)
				continue // Continue accepting other connections
			}
		}

		// Connection limiting, TLS handshake completion, counters, and
		// session construction all happen in the library's NewSession
		// callback (see buildLibServer), so rejected connections never
		// inflate the gauges. PROXY protocol info is discovered there via
		// the wrapper-chain walk.

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("ManageSieve Proxy: panic in connection handler", "panic", r, "stack", string(debug.Stack()))
				}
			}()
			s.msLibServer.Load().ServeConn(conn)
		}()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *Server) SetConnectionTracker(tracker *server.ConnectionTracker) {
	s.connTracker = tracker
	// Enable cache invalidation on kick events if lookup cache is available
	if tracker != nil && s.lookupCache != nil {
		tracker.SetLookupCache(s.lookupCache)
	}
}

// GetConnectionTracker returns the connection tracker for the server.
func (s *Server) GetConnectionTracker() *server.ConnectionTracker {
	return s.connTracker
}

// GetConnectionManager returns the connection manager for health checks
func (s *Server) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

// Stop stops the ManageSieve proxy server.
func (s *Server) Stop() error {
	logger.Debug("ManageSieve Proxy: Stopping", "name", s.name)

	// Unregister rate limiter from global registry
	server.UnregisterRateLimiter("managesieve_proxy", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownBye()

	s.cancel()

	s.listenerMu.RLock()
	listener := s.listener
	s.listenerMu.RUnlock()

	if listener != nil {
		listener.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("ManageSieve Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Debug("ManageSieve Proxy: Server stop timeout", "name", s.name)
	}

	// Close remotelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			logger.Debug("ManageSieve Proxy: Closing remotelookup client", "name", s.name)
			if err := routingLookup.Close(); err != nil {
				logger.Debug("ManageSieve Proxy: Error closing remotelookup client", "name", s.name, "error", err)
			}
		}
	}

	// Stop auth cache
	if s.lookupCache != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := s.lookupCache.Stop(stopCtx); err != nil {
			logger.Error("Error stopping auth cache", "proxy", s.name, "error", err)
		}
	}

	return nil
}

// addSession tracks an active session for graceful shutdown
func (s *Server) addSession(session *Session) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *Server) removeSession(session *Session) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownBye sends a BYE message to all active client connections
// and LOGOUT to backend servers for clean shutdown
func (s *Server) sendGracefulShutdownBye() {
	s.activeSessionsMu.RLock()
	activeSessions := make([]*Session, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMu.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("ManageSieve Proxy: Sending graceful shutdown messages", "name", s.name, "active_sessions", len(activeSessions))

	// Step 1: Set gracefulShutdown flag on all sessions.
	for _, session := range activeSessions {
		session.mu.Lock()
		session.gracefulShutdown = true
		session.mu.Unlock()
	}

	// Step 2: Write BYE directly to clientConn (RFC 5804 TRYLATER). Before the
	// hijack clientConn is the SoraConn, below the library's TLS connection
	// after STARTTLS: NoticeConn returns the connection the session is using.
	for _, session := range activeSessions {
		session.mu.Lock()
		server.WriteNotice(session.clientConn, func(conn net.Conn) {
			_, _ = fmt.Fprint(conn, "BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n")
		})
		session.mu.Unlock()
	}

	// Step 3: Give clients a moment to process the BYE before closing.
	time.Sleep(1 * time.Second)

	// Step 4: Close all connections.
	for _, session := range activeSessions {
		session.mu.Lock()
		if session.backendConn != nil {
			session.backendConn.Close()
		}
		if session.clientConn != nil {
			session.clientConn.Close()
		}
		session.mu.Unlock()
	}

	logger.Debug("ManageSieve Proxy: Proceeding with connection cleanup", "name", s.name)
}

// monitorActiveSessions periodically logs active session count for monitoring
func (s *Server) monitorActiveSessions() {
	// Log every 5 minutes (similar to connection tracker cleanup interval)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.activeSessionsMu.RLock()
			count := len(s.activeSessions)
			s.activeSessionsMu.RUnlock()

			// Get unique user count from connection tracker (cluster-wide)
			var uniqueUsers int
			if s.connTracker != nil {
				uniqueUsers = s.connTracker.GetUniqueUserCount()
			}

			// Also log connection limiter stats
			var limiterStats string
			if s.limiter != nil {
				stats := s.limiter.GetStats()
				limiterStats = fmt.Sprintf(" limiter_total=%d limiter_max=%d", stats.TotalConnections, stats.MaxConnections)
			}

			logger.Info("ManageSieve proxy active sessions", "proxy", s.name, "active_sessions", count, "unique_users", uniqueUsers, "limiter_stats", limiterStats)

		case <-s.ctx.Done():
			return
		}
	}
}

// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new connections; existing sessions keep old settings.
func (s *Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string
	next := *s.loadSettings()

	if newVal := cfg.GetMaxAuthErrors(); newVal != next.maxAuthErrors {
		next.maxAuthErrors = newVal
		reloaded = append(reloaded, "max_auth_errors")
	}
	// A value that does not parse keeps the running one (start-up, which has none,
	// uses the default).
	if timeout, err := cfg.GetAuthIdleTimeout(); err != nil {
		logger.Warn("ManageSieve proxy config reload: invalid auth_idle_timeout, keeping the running value", "name", s.name, "error", err, "running", next.authIdleTimeout)
	} else if timeout != next.authIdleTimeout {
		next.authIdleTimeout = timeout
		reloaded = append(reloaded, "auth_idle_timeout")
	}
	if timeout, err := cfg.GetCommandTimeout(); err != nil {
		logger.Warn("ManageSieve proxy config reload: invalid command_timeout, keeping the running value", "name", s.name, "error", err, "running", next.commandTimeout)
	} else if timeout != next.commandTimeout {
		next.commandTimeout = timeout
		reloaded = append(reloaded, "command_timeout")
	}
	if timeout, err := cfg.GetAbsoluteSessionTimeout(); err != nil {
		logger.Warn("ManageSieve proxy config reload: invalid absolute_session_timeout, keeping the running value", "name", s.name, "error", err, "running", next.absoluteSessionTimeout)
	} else if timeout != next.absoluteSessionTimeout {
		next.absoluteSessionTimeout = timeout
		reloaded = append(reloaded, "absolute_session_timeout")
	}
	if bpm := cfg.GetMinBytesPerMinute(); bpm != next.minBytesPerMinute {
		next.minBytesPerMinute = bpm
		reloaded = append(reloaded, "min_bytes_per_minute")
	}
	if cfg.MasterSASLUsername != string(next.masterSASLUsername) {
		next.masterSASLUsername = []byte(cfg.MasterSASLUsername)
		reloaded = append(reloaded, "master_sasl_username")
	}
	if cfg.MasterSASLPassword != string(next.masterSASLPassword) {
		next.masterSASLPassword = []byte(cfg.MasterSASLPassword)
		reloaded = append(reloaded, "master_sasl_password")
	}
	if cfg.Debug != next.debug {
		next.debug = cfg.Debug
		reloaded = append(reloaded, "debug")
	}

	if len(reloaded) > 0 {
		s.settings.Store(&next)
		// Rebuild the library server so new connections pick up the reloaded
		// settings; existing connections keep their snapshot.
		s.msLibServer.Store(s.buildLibServer())
		logger.Info("ManageSieve proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

// GetLimiter returns the connection limiter for testing purposes
func (s *Server) GetLimiter() *server.ConnectionLimiter {
	return s.limiter
}

// wrapProxyProtocol inserts the PROXY protocol listener between the TCP
// socket and the TLS layer when PROXY support is enabled — see
// server.ProxyProtocolListener for the composition rule. STARTTLS listeners
// are unaffected (TLS is negotiated in-protocol, long after the header).
func (s *Server) wrapProxyProtocol(l net.Listener) net.Listener {
	return server.WrapProxyProtocol(l, s.proxyReader, "SIEVE-PROXY")
}
