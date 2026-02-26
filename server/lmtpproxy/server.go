package lmtpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// Server represents an LMTP proxy server.
type Server struct {
	listener               net.Listener
	listenerMu             sync.RWMutex
	rdb                    *resilient.ResilientDatabase
	name                   string // Server name for logging
	addr                   string
	hostname               string
	connManager            *proxy.ConnectionManager
	connTracker            *server.ConnectionTracker
	tls                    bool
	tlsUseStartTLS         bool
	tlsCertFile            string
	tlsKeyFile             string
	tlsVerify              bool
	tlsConfig              *tls.Config // Global TLS config from TLS manager or per-server config
	enableAffinity         bool
	affinityValidity       time.Duration
	affinityStickiness     float64
	wg                     sync.WaitGroup
	ctx                    context.Context
	cancel                 context.CancelFunc
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	remotelookupConfig     *config.RemoteLookupConfig
	remoteUseXCLIENT       bool          // Whether backend supports XCLIENT command for forwarding
	authIdleTimeout        time.Duration // Idle timeout between commands
	absoluteSessionTimeout time.Duration // Maximum total session duration (prevents hung sessions)
	maxMessageSize         int64

	// Trusted networks for connection filtering
	trustedNetworks []*net.IPNet

	// Connection limiting (total connections only, no per-IP for LMTP)
	limiter *server.ConnectionLimiter

	// Routing cache (for user lookups - no password validation needed)
	lookupCache *lookupcache.LookupCache

	// Listen backlog
	listenBacklog int

	// Debug logging
	debug       bool
	debugWriter io.Writer

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*Session]struct{}

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader
}

// ServerOptions holds options for creating a new LMTP proxy server.
type ServerOptions struct {
	Name                     string // Server name for logging
	Addr                     string
	RemoteAddrs              []string
	RemotePort               int // Default port for backends if not in address
	TLS                      bool
	TLSUseStartTLS           bool // Use STARTTLS on listening port
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS                bool
	RemoteTLSUseStartTLS     bool // Use STARTTLS for backend connections
	RemoteTLSVerify          bool
	RemoteUseProxyProtocol   bool
	ConnectTimeout           time.Duration
	AuthIdleTimeout          time.Duration
	EnableAffinity           bool
	EnableBackendHealthCheck bool // Enable backend health checking (default: true)
	AffinityValidity         time.Duration
	AffinityStickiness       float64
	RemoteLookup             *config.RemoteLookupConfig
	TrustedProxies           []string      // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT         bool          // Whether backend supports XCLIENT command for forwarding
	AbsoluteSessionTimeout   time.Duration // Maximum total session duration (prevents hung sessions)
	MaxMessageSize           int64

	// Connection limiting (total connections only, no per-IP for LMTP)
	MaxConnections int // Maximum total connections (0 = unlimited)
	ListenBacklog  int // TCP listen backlog size (0 = system default; recommended: 4096-8192)

	// Routing cache configuration (for user lookups)
	LookupCache *config.LookupCacheConfig

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol        bool   // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout string // Timeout for reading PROXY protocol headers (e.g., "5s")

	// Debug logging
	Debug bool // Enable debug logging
}

// New creates a new LMTP proxy server.
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
		logger.Debug("LMTP Proxy: WARNING - tls_use_starttls ignored because tls=false", "name", opts.Name)
		// Force TLSUseStartTLS to false to avoid confusion
		opts.TLSUseStartTLS = false
	}

	// Initialize remotelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.RemoteLookup.Enabled {
		remotelookupClient, err := proxy.InitializeRemoteLookup("lmtp", opts.RemoteLookup)
		if err != nil {
			logger.Debug("LMTP Proxy: Failed to initialize remotelookup client", "name", opts.Name, "error", err)
			if !opts.RemoteLookup.ShouldLookupLocalUsers() {
				cancel()
				return nil, fmt.Errorf("failed to initialize remotelookup client: %w", err)
			}
			logger.Debug("LMTP Proxy: Continuing without remotelookup - local lookup enabled", "name", opts.Name)
		} else {
			routingLookup = remotelookupClient
			if opts.Debug {
				logger.Debug("LMTP Proxy: RemoteLookup client initialized successfully", "name", opts.Name)
			}
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSUseStartTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup, opts.Name, !opts.EnableBackendHealthCheck)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Debug("LMTP Proxy: Failed to resolve addresses", "name", opts.Name, "error", err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		logger.Debug("LMTP Proxy: WARNING - invalid affinity_stickiness, using default 1.0", "name", opts.Name, "value", stickiness)
		stickiness = 1.0
	}

	// Parse trusted networks for connection filtering
	trustedNets, err := server.ParseTrustedNetworks(opts.TrustedProxies)
	if err != nil {
		// Log the error and use empty trusted networks to prevent server crash
		logger.Debug("LMTP Proxy: WARNING - failed to parse trusted networks, proxy connections will be restricted", "error", err)
		trustedNets = []*net.IPNet{}
	}

	// Initialize connection limiter for total connections only (no per-IP for LMTP)
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 {
		// For LMTP proxy: total connections only, no per-IP limiting, no trusted networks bypass
		limiter = server.NewConnectionLimiterWithTrustedNets("LMTP-PROXY", opts.MaxConnections, 0, []string{})
	}

	// Setup debug writer if debug is enabled
	var debugWriter io.Writer
	if opts.Debug {
		debugWriter = os.Stdout
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
			TrustedProxies: opts.TrustedProxies, // Proxies use trusted_proxies for PROXY protocol validation
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("LMTP-PROXY", proxyConfig)
		if err != nil {
			if routingLookup != nil {
				routingLookup.Close()
			}
			cancel()
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "proxy", opts.Name)
	}

	// Initialize routing cache for user lookups (no password validation)
	// This caches both positive (user found) and negative (user not found) results
	// Initialize authentication cache from config
	// Apply defaults if not configured (enabled by default for performance)
	var lookupCache *lookupcache.LookupCache
	lookupCacheConfig := opts.LookupCache
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	if lookupCacheConfig.Enabled {
		positiveTTL, err := lookupCacheConfig.GetPositiveTTL()
		if err != nil {
			logger.Info("LMTP Proxy: Invalid positive TTL in auth cache config, using default (5m)", "name", opts.Name, "error", err)
			positiveTTL = 5 * time.Minute
		}
		negativeTTL, err := lookupCacheConfig.GetNegativeTTL()
		if err != nil {
			logger.Info("LMTP Proxy: Invalid negative TTL in auth cache config, using default (1m)", "name", opts.Name, "error", err)
			negativeTTL = 1 * time.Minute
		}
		cleanupInterval, err := lookupCacheConfig.GetCleanupInterval()
		if err != nil {
			logger.Info("LMTP Proxy: Invalid cleanup interval in auth cache config, using default (5m)", "name", opts.Name, "error", err)
			cleanupInterval = 5 * time.Minute
		}
		maxSize := lookupCacheConfig.MaxSize
		if maxSize <= 0 {
			maxSize = 10000
		}

		// LMTP proxy doesn't do password validation, so positive revalidation window is not needed (use 0)
		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, 0)
		logger.Info("LMTP Proxy: Lookup cache enabled", "name", opts.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize)
	} else {
		logger.Info("LMTP Proxy: Lookup cache disabled", "name", opts.Name)
	}

	s := &Server{
		rdb:                    rdb,
		name:                   opts.Name,
		addr:                   opts.Addr,
		hostname:               hostname,
		connManager:            connManager,
		tls:                    opts.TLS,
		tlsUseStartTLS:         opts.TLSUseStartTLS,
		tlsCertFile:            opts.TLSCertFile,
		tlsKeyFile:             opts.TLSKeyFile,
		tlsVerify:              opts.TLSVerify,
		enableAffinity:         opts.EnableAffinity,
		affinityValidity:       opts.AffinityValidity,
		affinityStickiness:     stickiness,
		ctx:                    ctx,
		cancel:                 cancel,
		trustedProxies:         opts.TrustedProxies,
		remotelookupConfig:     opts.RemoteLookup,
		remoteUseXCLIENT:       opts.RemoteUseXCLIENT,
		authIdleTimeout:        opts.AuthIdleTimeout,
		absoluteSessionTimeout: opts.AbsoluteSessionTimeout,
		maxMessageSize:         opts.MaxMessageSize,
		trustedNetworks:        trustedNets,
		limiter:                limiter,
		lookupCache:            lookupCache,
		listenBacklog:          listenBacklog,
		debug:                  opts.Debug,
		debugWriter:            debugWriter,
		activeSessions:         make(map[*Session]struct{}),
		proxyReader:            proxyReader,
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
			NextProtos:               []string{"lmtp"},
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if opts.TLS && opts.TLSConfig != nil {
		// Scenario 2: Global TLS manager (works for both implicit TLS and STARTTLS)
		s.tlsConfig = opts.TLSConfig
	} else if opts.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		cancel()
		return nil, fmt.Errorf("TLS enabled for LMTP proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", opts.Name)
	}

	return s, nil
}

// Start starts the LMTP proxy server.
func (s *Server) Start() error {
	// Configure SoraConn (LMTP proxy doesn't have timeout protection currently)
	connConfig := server.SoraConnConfig{
		Protocol:             "lmtp_proxy",
		ServerName:           s.name,
		Hostname:             s.hostname,
		EnableTimeoutChecker: false,
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
		logger.Debug("LMTP Proxy: Using listen backlog with per-server TLS (implicit)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraTLSListener for implicit TLS with JA4 capture
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
		logger.Debug("LMTP Proxy: Using listen backlog with global TLS manager (implicit)", "proxy", s.name, "backlog", s.listenBacklog)
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
		logger.Debug("LMTP Proxy: Using listen backlog with STARTTLS mode", "proxy", s.name, "backlog", s.listenBacklog)
		// Use plain SoraListener - TLS upgrade handled in session after STARTTLS command
		s.listener = server.NewSoraListener(tcpListener, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for LMTP proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
	} else {
		// Scenario 4: No TLS - plain text listener
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start listener: %w", err)
		}
		logger.Debug("LMTP Proxy: Using listen backlog (no TLS)", "proxy", s.name, "backlog", s.listenBacklog)
		// Use SoraListener for non-TLS
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

// isFromTrustedNetwork checks if an IP address is from a trusted network
func (s *Server) isFromTrustedNetwork(ip net.IP) bool {
	for _, network := range s.trustedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
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
				logger.Debug("LMTP Proxy: Failed to accept connection", "name", s.name, "error", err)
				continue // Continue accepting other connections
			}
		}

		// Check if connection is from a trusted network
		remoteAddr := conn.RemoteAddr()
		var ip net.IP
		switch addr := remoteAddr.(type) {
		case *net.TCPAddr:
			ip = addr.IP
		case *net.UDPAddr:
			ip = addr.IP
		default:
			// Try to parse as string
			host, _, err := net.SplitHostPort(remoteAddr.String())
			if err != nil {
				logger.Debug("LMTP Proxy: Connection rejected - invalid address format", "name", s.name, "remote", remoteAddr)
				conn.Close()
				continue
			}
			ip = net.ParseIP(host)
			if ip == nil {
				logger.Debug("LMTP Proxy: Connection rejected - could not parse IP", "name", s.name, "remote", remoteAddr)
				conn.Close()
				continue
			}
		}

		if !s.isFromTrustedNetwork(ip) {
			logger.Warn("LMTP Proxy: Connection rejected - not from trusted network", "name", s.name, "ip", ip, "remote", remoteAddr)
			conn.Close()
			continue
		}

		// Check total connection limits after trusted network verification
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.AcceptWithRealIP(conn.RemoteAddr(), "")
			if err != nil {
				logger.Debug("LMTP Proxy: Connection rejected", "name", s.name, "ip", ip, "error", err)
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
			metrics.ConnectionsTotal.WithLabelValues("lmtp_proxy", s.name, s.hostname).Inc()
			metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy", s.name, s.hostname).Inc()

			session := newSession(s, conn, proxyInfo)
			session.releaseConn = releaseConn // Set cleanup function on session
			s.registerSession(session)

			// CRITICAL: Panic recovery MUST clean up metrics and limiter
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("LMTP Proxy: Session panic recovered", "name", s.name, "panic", r)
					// Unregister session from active tracking
					s.unregisterSession(session)
					// Decrement metrics
					metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy", s.name, s.hostname).Dec()
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

// registerSession adds a session to the active sessions map for graceful shutdown tracking
func (s *Server) registerSession(session *Session) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	s.activeSessions[session] = struct{}{}
}

// unregisterSession removes a session from the active sessions map
func (s *Server) unregisterSession(session *Session) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a shutdown message to all active client connections
func (s *Server) sendGracefulShutdownMessage() {
	s.activeSessionsMu.RLock()
	activeSessions := make([]*Session, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMu.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Info("Sending graceful shutdown messages to LMTP sessions", "name", s.name, "count", len(activeSessions))

	// Send shutdown message to all active sessions
	for _, session := range activeSessions {
		// Lock the session to safely access writer
		session.mu.Lock()

		// Send 421 temporary failure to client
		// LMTP RFC 2821: 421 means "service not available, closing transmission channel"
		if session.clientWriter != nil {
			session.clientWriter.WriteString("421 4.3.2 Service shutting down, please try again later\r\n")
			session.clientWriter.Flush()
		}

		// Send QUIT to backend for clean disconnect
		if session.backendWriter != nil {
			session.backendWriter.WriteString("QUIT\r\n")
			session.backendWriter.Flush()
		}

		session.mu.Unlock()
	}

	// Give both clients and backends a brief moment to process the messages
	time.Sleep(1 * time.Second)

	// Close connections to unblock any sessions blocked on reads
	for _, session := range activeSessions {
		session.mu.Lock()
		if session.clientConn != nil {
			session.clientConn.Close()
		}
		if session.backendConn != nil {
			session.backendConn.Close()
		}
		session.mu.Unlock()
	}

	logger.Debug("LMTP Proxy: Proceeding with connection cleanup", "name", s.name)
}

// Stop stops the LMTP proxy server.
// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new connections; existing sessions keep old settings.
func (s *Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string

	if timeout, err := cfg.GetAbsoluteSessionTimeout(); err == nil && timeout != s.absoluteSessionTimeout {
		s.absoluteSessionTimeout = timeout
		reloaded = append(reloaded, "absolute_session_timeout")
	}
	if maxSize := cfg.GetMaxMessageSizeWithDefault(); maxSize != s.maxMessageSize {
		s.maxMessageSize = maxSize
		reloaded = append(reloaded, "max_message_size")
	}
	if cfg.Debug != s.debug {
		s.debug = cfg.Debug
		reloaded = append(reloaded, "debug")
	}

	if len(reloaded) > 0 {
		logger.Info("LMTP proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

func (s *Server) Stop() error {
	logger.Info("Stopping LMTP proxy server", "name", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

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
		logger.Debug("LMTP Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Debug("LMTP Proxy: Server stop timeout", "name", s.name)
	}

	// Close remotelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			logger.Debug("LMTP Proxy: Closing remotelookup client", "name", s.name)
			if err := routingLookup.Close(); err != nil {
				logger.Debug("LMTP Proxy: Error closing remotelookup client", "name", s.name, "error", err)
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

			// Also log connection limiter stats
			if s.limiter != nil {
				stats := s.limiter.GetStats()
				logger.Info("LMTP proxy active sessions", "proxy", s.name, "active_sessions", count, "limiter_total", stats.TotalConnections, "limiter_max", stats.MaxConnections)
			} else {
				logger.Info("LMTP proxy active sessions", "proxy", s.name, "active_sessions", count)
			}

		case <-s.ctx.Done():
			return
		}
	}
}
