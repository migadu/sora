package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/proxy"
)

// Server represents a ManageSieve proxy server.
type Server struct {
	listener               net.Listener
	listenerMu             sync.RWMutex
	rdb                    *resilient.ResilientDatabase
	name                   string // Server name for logging
	addr                   string
	hostname               string
	insecureAuth           bool
	masterUsername         []byte
	masterPassword         []byte
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	tls                    bool
	tlsUseStartTLS         bool
	tlsCertFile            string
	tlsKeyFile             string
	tlsVerify              bool
	tlsConfig              *tls.Config // Global TLS config from TLS manager or per-server config
	connManager            *proxy.ConnectionManager
	connTracker            *server.ConnectionTracker
	wg                     sync.WaitGroup
	ctx                    context.Context
	cancel                 context.CancelFunc
	enableAffinity         bool
	affinityValidity       time.Duration
	affinityStickiness     float64
	authLimiter            server.AuthLimiter
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	remotelookupConfig     *config.RemoteLookupConfig
	authIdleTimeout        time.Duration
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Auth cache for routing and password validation
	lookupCache                *lookupcache.LookupCache
	positiveRevalidationWindow time.Duration

	// Listen backlog
	listenBacklog int

	// Debug logging
	debug bool

	// SIEVE extensions (additional to builtin)
	supportedExtensions []string

	// Authentication limits
	maxAuthErrors int // Maximum authentication errors before disconnection

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*Session]struct{}

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader
}

// ServerOptions holds options for creating a new ManageSieve proxy server.
type ServerOptions struct {
	Name                      string // Server name for logging
	Addr                      string
	RemoteAddrs               []string
	RemotePort                int // Default port for backends if not in address
	InsecureAuth              bool
	MasterUsername            string
	MasterPassword            string
	MasterSASLUsername        string
	MasterSASLPassword        string
	TLS                       bool
	TLSUseStartTLS            bool // Use STARTTLS on listening port
	TLSCertFile               string
	TLSKeyFile                string
	TLSVerify                 bool
	TLSConfig                 *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS                 bool
	RemoteTLSUseStartTLS      bool // Use STARTTLS for backend connections
	RemoteTLSVerify           bool
	RemoteUseProxyProtocol    bool
	ConnectTimeout            time.Duration
	AuthIdleTimeout           time.Duration
	CommandTimeout            time.Duration // Idle timeout
	AbsoluteSessionTimeout    time.Duration // Maximum total session duration
	MinBytesPerMinute         int64         // Minimum throughput
	EnableAffinity            bool
	DisableBackendHealthCheck bool // Disable backend health checking
	AffinityValidity          time.Duration
	AffinityStickiness        float64
	AuthRateLimit             server.AuthRateLimiterConfig
	RemoteLookup              *config.RemoteLookupConfig
	TrustedProxies            []string // CIDR blocks for trusted proxies that can forward parameters

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
	ClusterManager *cluster.Manager // Optional: enables cluster-wide per-IP limiting

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

	if len(opts.RemoteAddrs) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses configured")
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
	routingLookup, err := proxy.InitializeRemoteLookup("managesieve", opts.RemoteLookup)
	if err != nil {
		logger.Debug("ManageSieve Proxy: Failed to initialize remotelookup client", "name", opts.Name, "error", err)
		if opts.RemoteLookup != nil && !opts.RemoteLookup.ShouldLookupLocalUsers() {
			cancel()
			return nil, fmt.Errorf("failed to initialize remotelookup client: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Continuing without remotelookup - local lookup enabled", "name", opts.Name)
	}
	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSUseStartTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup, opts.Name, opts.DisableBackendHealthCheck)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Debug("ManageSieve Proxy: Failed to resolve addresses", "name", opts.Name, "error", err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		logger.Debug("ManageSieve Proxy: WARNING - invalid affinity_stickiness, using default 1.0", "name", opts.Name, "value", stickiness)
		stickiness = 1.0
	}

	// Validate SIEVE extensions
	if err := managesieve.ValidateExtensions(opts.SupportedExtensions); err != nil {
		cancel()
		return nil, fmt.Errorf("invalid ManageSieve proxy configuration: %w", err)
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("SIEVE-PROXY", opts.AuthRateLimit, opts.TrustedProxies)

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

	if lookupCacheConfig.Enabled {
		positiveTTL, err := lookupCacheConfig.GetPositiveTTL()
		if err != nil {
			logger.Info("ManageSieve Proxy: Invalid positive TTL in auth cache config, using default (5m)", "name", opts.Name, "error", err)
			positiveTTL = 5 * time.Minute
		}
		negativeTTL, err := lookupCacheConfig.GetNegativeTTL()
		if err != nil {
			logger.Info("ManageSieve Proxy: Invalid negative TTL in auth cache config, using default (1m)", "name", opts.Name, "error", err)
			negativeTTL = 1 * time.Minute
		}
		cleanupInterval, err := lookupCacheConfig.GetCleanupInterval()
		if err != nil {
			logger.Info("ManageSieve Proxy: Invalid cleanup interval in auth cache config, using default (5m)", "name", opts.Name, "error", err)
			cleanupInterval = 5 * time.Minute
		}
		maxSize := lookupCacheConfig.MaxSize
		if maxSize <= 0 {
			maxSize = 10000
		}

		// Parse positive revalidation window from config (used for password change detection)
		positiveRevalidationWindow, err = lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("ManageSieve Proxy: Invalid positive revalidation window in auth cache config, using default (30s)", "name", opts.Name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

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
		insecureAuth:               opts.InsecureAuth,
		masterUsername:             []byte(opts.MasterUsername),
		masterPassword:             []byte(opts.MasterPassword),
		masterSASLUsername:         []byte(opts.MasterSASLUsername),
		masterSASLPassword:         []byte(opts.MasterSASLPassword),
		tls:                        opts.TLS,
		tlsUseStartTLS:             opts.TLSUseStartTLS,
		tlsCertFile:                opts.TLSCertFile,
		tlsKeyFile:                 opts.TLSKeyFile,
		tlsVerify:                  opts.TLSVerify,
		connManager:                connManager,
		ctx:                        ctx,
		cancel:                     cancel,
		enableAffinity:             opts.EnableAffinity,
		affinityValidity:           opts.AffinityValidity,
		affinityStickiness:         stickiness,
		authLimiter:                authLimiter,
		trustedProxies:             opts.TrustedProxies,
		remotelookupConfig:         opts.RemoteLookup,
		authIdleTimeout:            opts.AuthIdleTimeout,
		commandTimeout:             opts.CommandTimeout,
		absoluteSessionTimeout:     opts.AbsoluteSessionTimeout,
		minBytesPerMinute:          opts.MinBytesPerMinute,
		limiter:                    limiter,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		listenBacklog:              listenBacklog,
		maxAuthErrors:              opts.MaxAuthErrors,
		debug:                      opts.Debug,
		supportedExtensions:        opts.SupportedExtensions,
		activeSessions:             make(map[*Session]struct{}),
		proxyReader:                proxyReader,
	}

	// Use all supported extensions by default if none are configured
	if len(s.supportedExtensions) == 0 {
		s.supportedExtensions = managesieve.GoSieveSupportedExtensions
		logger.Debug("ManageSieve Proxy: No supported_extensions configured - using all available", "name", opts.Name, "extensions", managesieve.GoSieveSupportedExtensions)
	}

	// Setup TLS config: Support both implicit TLS and STARTTLS
	// 1. Per-server TLS: cert files provided (for both implicit TLS and STARTTLS)
	// 2. Global TLS: opts.TLS=true, no cert files, global TLS config provided (for both implicit TLS and STARTTLS)
	// 3. No TLS: opts.TLS=false
	if opts.TLS && opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		clientAuth := tls.NoClientCert
		if opts.TLSVerify {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"sieve"},
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if opts.TLS && opts.TLSConfig != nil {
		// Scenario 2: Global TLS manager (works for both implicit TLS and STARTTLS)
		s.tlsConfig = opts.TLSConfig
	} else if opts.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		cancel()
		return nil, fmt.Errorf("TLS enabled for ManageSieve proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", opts.Name)
	}

	return s, nil
}

// Start starts the ManageSieve proxy server.
func (s *Server) Start() error {
	// Configure SoraConn with timeout protection
	connConfig := server.SoraConnConfig{
		Protocol:             "managesieve_proxy",
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0,
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

	// Four TLS scenarios:
	// 1. Per-server TLS with cert files (implicit TLS): Use static certificate with TLS listener
	// 2. Global TLS manager (implicit TLS): Use dynamic certificate with TLS listener
	// 3. STARTTLS mode: Use plain listener, upgrade to TLS in session after STARTTLS command
	// 4. No TLS: Plain text listener

	if s.tls && !s.tlsUseStartTLS && s.tlsCertFile != "" && s.tlsKeyFile != "" {
		// Scenario 1: Per-server TLS with cert files (implicit TLS)
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog with per-server TLS (implicit)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraTLSListener for implicit TLS with JA4 capture and timeout protection
		s.listener = server.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls && !s.tlsUseStartTLS && s.tlsConfig != nil {
		// Scenario 2: Global TLS manager (implicit TLS)
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog with global TLS manager (implicit)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraTLSListener with global TLS config for implicit TLS
		s.listener = server.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls && s.tlsUseStartTLS {
		// Scenario 3: STARTTLS mode - plain listener, TLS upgrade happens in session
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog with STARTTLS mode", "proxy", s.name, "backlog", s.listenBacklog)
		// Use plain SoraListener - TLS upgrade handled in session after STARTTLS command
		s.listener = server.NewSoraListener(tcpListener, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for ManageSieve proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
	} else {
		// Scenario 4: No TLS - plain text listener
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start listener: %w", err)
		}
		logger.Debug("ManageSieve Proxy: Using listen backlog (no TLS)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraListener for non-TLS with timeout protection
		s.listener = server.NewSoraListener(tcpListener, connConfig)
		s.listenerMu.Unlock()
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	// Start session monitoring routine
	go s.monitorActiveSessions()

	return s.acceptConnections()
}

// acceptConnections accepts incoming connections.
func (s *Server) acceptConnections() error {
	for {
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

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.AcceptWithRealIP(conn.RemoteAddr(), "")
			if err != nil {
				logger.Debug("ManageSieve Proxy: Connection rejected", "name", s.name, "error", err)
				conn.Close()
				continue // Try to accept the next connection
			}
		}

		// Read PROXY protocol header if enabled
		var proxyInfo *server.ProxyProtocolInfo
		var wrappedConn net.Conn
		if s.proxyReader != nil {
			var err error
			proxyInfo, wrappedConn, err = s.proxyReader.ReadProxyHeader(conn)
			if err != nil {
				logger.Error("PROXY protocol error", "proxy", s.name, "remote", server.GetAddrString(conn.RemoteAddr()), "error", err)
				conn.Close()
				if releaseConn != nil {
					releaseConn()
				}
				continue // Try to accept the next connection
			}
			conn = wrappedConn // Use wrapped connection that has buffered reader
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			// Track proxy connection
			metrics.ConnectionsTotal.WithLabelValues("managesieve_proxy").Inc()
			metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Inc()

			session := newSession(s, conn, proxyInfo)
			session.releaseConn = releaseConn // Set cleanup function on session
			s.addSession(session)

			// CRITICAL: Panic recovery MUST call removeSession to prevent leak
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("ManageSieve Proxy: Session panic recovered", "name", s.name, "panic", r)
					// Clean up session from active tracking
					s.removeSession(session)
					// Decrement metrics
					metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Dec()
					// Close connection
					conn.Close()
					// Ensure connection limiter is released on panic
					if releaseConn != nil {
						releaseConn()
					}
				}
			}()

			// Note: releaseConn is called in session.close(), which is deferred in handleConnection()
			// This ensures cleanup happens when the session ends, not when the goroutine exits
			session.handleConnection()
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

	// Send shutdown messages to both client and backend
	for _, session := range activeSessions {
		// Send BYE to client
		if session.clientWriter != nil {
			// Send BYE with TRYLATER response code (RFC 5804)
			session.clientWriter.WriteString("BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n")
			session.clientWriter.Flush()
		}

		// Send LOGOUT to backend for clean disconnect
		if session.backendConn != nil {
			// ManageSieve uses LOGOUT command (RFC 5804 Section 2.3)
			writer := bufio.NewWriter(session.backendConn)
			writer.WriteString("LOGOUT\r\n")
			writer.Flush()
		}
	}

	// Give both clients and backends a brief moment to process
	time.Sleep(1 * time.Second)

	// Close connections to unblock any sessions blocked on reads
	for _, session := range activeSessions {
		if session.clientConn != nil {
			session.clientConn.Close()
		}
		if session.backendConn != nil {
			session.backendConn.Close()
		}
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

// GetLimiter returns the connection limiter for testing purposes
func (s *Server) GetLimiter() *server.ConnectionLimiter {
	return s.limiter
}
