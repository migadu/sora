package pop3proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type POP3ProxyServer struct {
	name                   string // Server name for logging
	addr                   string
	hostname               string
	rdb                    *resilient.ResilientDatabase
	appCtx                 context.Context
	cancel                 context.CancelFunc
	tlsConfig              *tls.Config
	masterUsername         string
	masterPassword         string
	masterSASLUsername     string
	masterSASLPassword     string
	connManager            *proxy.ConnectionManager
	connTracker            *server.ConnectionTracker
	wg                     sync.WaitGroup
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
	remoteUseXCLIENT       bool          // Whether backend supports XCLIENT command for forwarding

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Auth cache for routing and password validation
	lookupCache                *lookupcache.LookupCache
	positiveRevalidationWindow time.Duration

	// Listen backlog
	listenBacklog int

	// Auth security
	insecureAuth bool

	// Debug logging
	debug       bool
	debugWriter io.Writer

	// Authentication limits
	maxAuthErrors int // Maximum authentication errors before disconnection

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*POP3ProxySession]struct{}

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader
}

// maskingWriter wraps an io.Writer to mask sensitive information in POP3 commands
type maskingWriter struct {
	w io.Writer
}

// Write inspects the log output, and if it's a client command (prefixed with "C: "),
// it attempts to mask sensitive parts of PASS and AUTH commands.
func (mw *maskingWriter) Write(p []byte) (n int, err error) {
	line := string(p)
	originalLen := len(p)

	// Only process client commands
	if !strings.HasPrefix(line, "C: ") {
		return mw.w.Write(p)
	}

	cmdLine := strings.TrimPrefix(line, "C: ")
	trimmedCmdLine := strings.TrimRight(cmdLine, "\r\n")
	parts := strings.Fields(trimmedCmdLine)
	if len(parts) < 1 {
		return mw.w.Write(p)
	}

	command := strings.ToUpper(parts[0])

	// Use the helper to mask the command line
	maskedCmdLine := helpers.MaskSensitive(trimmedCmdLine, command, "PASS", "AUTH")

	// If the line was modified, write the masked version.
	if maskedCmdLine != trimmedCmdLine {
		maskedLine := "C: " + maskedCmdLine + "\r\n"
		_, err = mw.w.Write([]byte(maskedLine))
	} else {
		// Otherwise, write the original line.
		_, err = mw.w.Write(p)
	}

	if err != nil {
		return 0, err
	}

	// Always return the original length to prevent buffering issues
	return originalLen, nil
}

type POP3ProxyServerOptions struct {
	Name                     string // Server name for logging
	InsecureAuth             bool   // Allow PLAIN auth over non-TLS connections
	Debug                    bool
	TLS                      bool
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteAddrs              []string
	RemotePort               int // Default port for backends if not in address
	RemoteTLS                bool
	RemoteTLSVerify          bool
	RemoteUseProxyProtocol   bool
	MasterUsername           string
	MasterPassword           string
	MasterSASLUsername       string
	MasterSASLPassword       string
	ConnectTimeout           time.Duration
	AuthIdleTimeout          time.Duration
	CommandTimeout           time.Duration // Idle timeout
	AbsoluteSessionTimeout   time.Duration // Maximum total session duration
	MinBytesPerMinute        int64         // Minimum throughput
	EnableAffinity           bool
	EnableBackendHealthCheck bool // Enable backend health checking (default: true)
	AffinityValidity         time.Duration
	AffinityStickiness       float64
	AuthRateLimit            server.AuthRateLimiterConfig
	RemoteLookup             *config.RemoteLookupConfig
	TrustedProxies           []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT         bool     // Whether backend supports XCLIENT command for forwarding

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol        bool   // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout string // Timeout for reading PROXY protocol headers (e.g., "5s")

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
}

func New(appCtx context.Context, hostname, addr string, rdb *resilient.ResilientDatabase, options POP3ProxyServerOptions) (*POP3ProxyServer, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Ensure RemoteLookup config has a default value to avoid nil panics.
	if options.RemoteLookup == nil {
		options.RemoteLookup = &config.RemoteLookupConfig{}
	}

	// Initialize remotelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if options.RemoteLookup != nil && options.RemoteLookup.Enabled {
		remotelookupClient, err := proxy.InitializeRemoteLookup("pop3", options.RemoteLookup)
		if err != nil {
			logger.Debug("POP3 Proxy: Failed to initialize remotelookup client", "proxy", options.Name, "error", err)
			if !options.RemoteLookup.ShouldLookupLocalUsers() {
				serverCancel()
				return nil, fmt.Errorf("failed to initialize remotelookup client: %w", err)
			}
			logger.Debug("POP3 Proxy: Continuing without remotelookup due to lookup_local_users=true", "proxy", options.Name)
		} else {
			routingLookup = remotelookupClient
			if options.Debug {
				logger.Debug("POP3 Proxy: RemoteLookup client initialized successfully", "proxy", options.Name)
			}
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
		options.RemoteAddrs,
		options.RemotePort,
		options.RemoteTLS,
		false,
		options.RemoteTLSVerify,
		options.RemoteUseProxyProtocol,
		options.ConnectTimeout,
		routingLookup,
		options.Name,
		!options.EnableBackendHealthCheck,
	)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		serverCancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Debug("WARNING: Failed to resolve some addresses for POP3 proxy", "proxy", options.Name, "error", err)
	}

	// Validate affinity stickiness
	stickiness := options.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		logger.Debug("WARNING: invalid POP3 proxy affinity_stickiness - using default 1.0", "proxy", options.Name, "value", stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("POP3-PROXY", options.Name, hostname, options.AuthRateLimit, options.TrustedProxies)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if options.MaxConnections > 0 || options.MaxConnectionsPerIP > 0 {
		if options.ClusterManager != nil {
			// Cluster mode: use cluster-wide per-IP limiting
			instanceID := fmt.Sprintf("pop3-proxy-%s-%d", hostname, time.Now().UnixNano())
			limiter = server.NewConnectionLimiterWithCluster("POP3-PROXY", instanceID, options.ClusterManager, options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)
		} else {
			// Local mode: use local-only limiting
			limiter = server.NewConnectionLimiterWithTrustedNets("POP3-PROXY", options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)
		}
	}

	// Setup debug writer with password masking if debug is enabled
	var debugWriter io.Writer
	if options.Debug {
		debugWriter = &maskingWriter{w: os.Stdout}
	}

	// Set listen backlog with reasonable default
	listenBacklog := options.ListenBacklog
	if listenBacklog == 0 {
		listenBacklog = 1024 // Default backlog
	}

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		// Build config from flat fields (matching backend format)
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Timeout:        options.ProxyProtocolTimeout,
			TrustedProxies: options.TrustedNetworks, // Proxies always use trusted_networks
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("POP3-PROXY", proxyConfig)
		if err != nil {
			if routingLookup != nil {
				routingLookup.Close()
			}
			serverCancel()
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "proxy", options.Name)
	}

	// Initialize auth cache for user authentication and routing
	// Initialize authentication cache from config
	// Apply defaults if not configured (enabled by default for performance)
	var lookupCache *lookupcache.LookupCache
	var positiveRevalidationWindow time.Duration
	lookupCacheConfig := options.LookupCache
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	if lookupCacheConfig.Enabled {
		positiveTTL, err := lookupCacheConfig.GetPositiveTTL()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid positive TTL in auth cache config, using default (5m)", "name", options.Name, "error", err)
			positiveTTL = 5 * time.Minute
		}
		negativeTTL, err := lookupCacheConfig.GetNegativeTTL()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid negative TTL in auth cache config, using default (1m)", "name", options.Name, "error", err)
			negativeTTL = 1 * time.Minute
		}
		cleanupInterval, err := lookupCacheConfig.GetCleanupInterval()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid cleanup interval in auth cache config, using default (5m)", "name", options.Name, "error", err)
			cleanupInterval = 5 * time.Minute
		}
		maxSize := lookupCacheConfig.MaxSize
		if maxSize <= 0 {
			maxSize = 10000
		}

		// Parse positive revalidation window from config (used for password change detection)
		positiveRevalidationWindow, err = lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid positive revalidation window in auth cache config, using default (30s)", "name", options.Name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("POP3 Proxy: Lookup cache enabled", "name", options.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	} else {
		logger.Info("POP3 Proxy: Lookup cache disabled", "name", options.Name)
	}

	server := &POP3ProxyServer{
		name:                       options.Name,
		hostname:                   hostname,
		addr:                       addr,
		rdb:                        rdb,
		appCtx:                     serverCtx,
		cancel:                     serverCancel,
		masterUsername:             options.MasterUsername,
		masterPassword:             options.MasterPassword,
		masterSASLUsername:         options.MasterSASLUsername,
		masterSASLPassword:         options.MasterSASLPassword,
		connManager:                connManager,
		enableAffinity:             options.EnableAffinity,
		affinityValidity:           options.AffinityValidity,
		affinityStickiness:         stickiness,
		authLimiter:                authLimiter,
		trustedProxies:             options.TrustedProxies,
		remotelookupConfig:         options.RemoteLookup,
		authIdleTimeout:            options.AuthIdleTimeout,
		commandTimeout:             options.CommandTimeout,
		absoluteSessionTimeout:     options.AbsoluteSessionTimeout,
		minBytesPerMinute:          options.MinBytesPerMinute,
		remoteUseXCLIENT:           options.RemoteUseXCLIENT,
		limiter:                    limiter,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		listenBacklog:              listenBacklog,
		maxAuthErrors:              options.MaxAuthErrors,
		insecureAuth:               options.InsecureAuth || !options.TLS, // Auto-enable when TLS not configured
		debug:                      options.Debug,
		debugWriter:                debugWriter,
		activeSessions:             make(map[*POP3ProxySession]struct{}),
		proxyReader:                proxyReader,
	}

	// Setup TLS: Three scenarios
	// 1. Per-server TLS: cert files provided
	// 2. Global TLS: options.TLS=true, no cert files, global TLS config provided
	// 3. No TLS: options.TLS=false
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		clientAuth := tls.NoClientCert
		if options.TLSVerify {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"pop3"},
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if options.TLS && options.TLSConfig != nil {
		// Scenario 2: Global TLS manager
		server.tlsConfig = options.TLSConfig
	} else if options.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		serverCancel()
		return nil, fmt.Errorf("TLS enabled for POP3 proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", options.Name)
	}

	return server, nil
}

func (s *POP3ProxyServer) Start() error {
	var listener net.Listener

	// Configure SoraConn with timeout protection
	connConfig := server.SoraConnConfig{
		Protocol:             "pop3_proxy",
		ServerName:           s.name,
		Hostname:             s.hostname,
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send POP3 error response before closing
			// RFC 1939 doesn't define specific timeout response codes, but [IN-USE] is commonly used
			var message string
			switch reason {
			case "idle":
				message = "-ERR [IN-USE] Idle timeout, please reconnect\r\n"
			case "slow_throughput":
				message = "-ERR [IN-USE] Connection too slow, please reconnect\r\n"
			case "session_max":
				message = "-ERR [IN-USE] Maximum session duration exceeded, please reconnect\r\n"
			default:
				message = "-ERR [IN-USE] Connection timeout, please reconnect\r\n"
			}
			_, _ = fmt.Fprint(conn, message)
		},
	}

	// Create base TCP listener with custom backlog
	tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
	if err != nil {
		s.cancel()
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}
	logger.Debug("POP3 Proxy: Using listen backlog", "proxy", s.name, "backlog", s.listenBacklog)

	if s.tlsConfig != nil {
		// Use SoraTLSListener for TLS with JA4 capture and timeout protection
		listener = server.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
	} else {
		// Use SoraListener for non-TLS with timeout protection
		listener = server.NewSoraListener(tcpListener, connConfig)
	}
	defer listener.Close()

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.appCtx)
	}

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		listener.Close()
	}()

	// Start session monitoring routine
	go s.monitorActiveSessions()

	return s.acceptConnections(listener)
}

func (s *POP3ProxyServer) acceptConnections(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// If context is cancelled, listener.Close() was called, so this is a graceful shutdown.
			if s.appCtx.Err() != nil {
				return nil
			}
			// All Accept() errors are connection-level issues (TLS handshake failures, client disconnects, etc.)
			// They should be logged but not crash the server - the listener itself is still healthy
			logger.Debug("POP3 Proxy: Failed to accept connection", "proxy", s.name, "error", err)
			continue // Continue accepting other connections
		}

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.AcceptWithRealIP(conn.RemoteAddr(), "")
			if err != nil {
				logger.Debug("POP3 Proxy: Connection rejected", "proxy", s.name, "error", err)
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

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &POP3ProxySession{
			server:      s,
			clientConn:  conn,
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			releaseConn: releaseConn, // Set cleanup function on session
			proxyInfo:   proxyInfo,
		}

		// Use real client IP from PROXY protocol if available
		if proxyInfo != nil && proxyInfo.SrcIP != "" {
			session.RemoteIP = proxyInfo.SrcIP
		} else {
			session.RemoteIP = server.GetAddrString(conn.RemoteAddr())
		}
		if s.debug {
			logger.Debug("POP3 proxy: New connection", "proxy", s.name, "remote", session.RemoteIP)
		}

		// Track proxy connection
		metrics.ConnectionsTotal.WithLabelValues("pop3_proxy", s.name, s.hostname).Inc()
		metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy", s.name, s.hostname).Inc()

		// Track session for graceful shutdown
		s.addSession(session)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			// CRITICAL: Panic recovery MUST call removeSession to prevent leak
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("POP3 Proxy: Session panic recovered", "proxy", s.name, "panic", r)
					// Clean up session from active tracking
					s.removeSession(session)
					// Decrement metrics
					metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy", s.name, s.hostname).Dec()
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
func (s *POP3ProxyServer) SetConnectionTracker(tracker *server.ConnectionTracker) {
	s.connTracker = tracker
	// Enable cache invalidation on kick events if lookup cache is available
	if tracker != nil && s.lookupCache != nil {
		tracker.SetLookupCache(s.lookupCache)
	}
}

// GetConnectionTracker returns the connection tracker for the server.
func (s *POP3ProxyServer) GetConnectionTracker() *server.ConnectionTracker {
	return s.connTracker
}

// GetConnectionManager returns the connection manager for health checks
func (s *POP3ProxyServer) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

func (s *POP3ProxyServer) Stop() error {
	logger.Debug("POP3 Proxy: Stopping", "proxy", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	if s.cancel != nil {
		s.cancel()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("POP3 Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Debug("POP3 Proxy: Server stop timeout", "proxy", s.name)
	}

	// Close remotelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			logger.Debug("POP3 Proxy: Closing remotelookup client", "proxy", s.name)
			if err := routingLookup.Close(); err != nil {
				logger.Debug("POP3 Proxy: Error closing remotelookup client", "proxy", s.name, "error", err)
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
func (s *POP3ProxyServer) addSession(session *POP3ProxySession) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *POP3ProxyServer) removeSession(session *POP3ProxySession) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a shutdown error message to all active client connections
// and QUIT to backend servers for clean shutdown
func (s *POP3ProxyServer) sendGracefulShutdownMessage() {
	s.activeSessionsMu.RLock()
	activeSessions := make([]*POP3ProxySession, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMu.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("POP3 Proxy: Sending graceful shutdown messages to active connections", "proxy", s.name, "count", len(activeSessions))

	// Send shutdown messages to both client and backend
	for _, session := range activeSessions {
		// Send error response to client
		if session.clientConn != nil {
			writer := bufio.NewWriter(session.clientConn)
			writer.WriteString("-ERR Server shutting down, please reconnect\r\n")
			writer.Flush()
		}

		// Send QUIT to backend for clean disconnect
		if session.backendConn != nil {
			writer := bufio.NewWriter(session.backendConn)
			writer.WriteString("QUIT\r\n")
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

	logger.Debug("POP3 Proxy: Proceeding with connection cleanup", "proxy", s.name)
}

// monitorActiveSessions periodically logs active session count for monitoring
func (s *POP3ProxyServer) monitorActiveSessions() {
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

			logger.Info("POP3 proxy active sessions", "proxy", s.name, "active_sessions", count, "unique_users", uniqueUsers, "limiter_stats", limiterStats)

		case <-s.appCtx.Done():
			return
		}
	}
}

// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new connections; existing sessions keep old settings.
func (s *POP3ProxyServer) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string

	// Update max auth errors
	if newVal := cfg.GetMaxAuthErrors(); newVal != s.maxAuthErrors {
		s.maxAuthErrors = newVal
		reloaded = append(reloaded, "max_auth_errors")
	}

	// Update timeouts (affect new connections only)
	if timeout := cfg.GetAuthIdleTimeoutWithDefault(); timeout != s.authIdleTimeout {
		s.authIdleTimeout = timeout
		reloaded = append(reloaded, "auth_idle_timeout")
	}
	if timeout, err := cfg.GetCommandTimeout(); err == nil && timeout != s.commandTimeout {
		s.commandTimeout = timeout
		reloaded = append(reloaded, "command_timeout")
	}
	if timeout, err := cfg.GetAbsoluteSessionTimeout(); err == nil && timeout != s.absoluteSessionTimeout {
		s.absoluteSessionTimeout = timeout
		reloaded = append(reloaded, "absolute_session_timeout")
	}
	if bpm := cfg.GetMinBytesPerMinute(); bpm != s.minBytesPerMinute {
		s.minBytesPerMinute = bpm
		reloaded = append(reloaded, "min_bytes_per_minute")
	}

	// Update master credentials
	if cfg.MasterSASLUsername != s.masterSASLUsername {
		s.masterSASLUsername = cfg.MasterSASLUsername
		reloaded = append(reloaded, "master_sasl_username")
	}
	if cfg.MasterSASLPassword != s.masterSASLPassword {
		s.masterSASLPassword = cfg.MasterSASLPassword
		reloaded = append(reloaded, "master_sasl_password")
	}

	// Update debug flag
	if cfg.Debug != s.debug {
		s.debug = cfg.Debug
		reloaded = append(reloaded, "debug")
	}

	if len(reloaded) > 0 {
		logger.Info("POP3 proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

// GetLimiter returns the connection limiter for testing purposes
func (s *POP3ProxyServer) GetLimiter() *server.ConnectionLimiter {
	return s.limiter
}
