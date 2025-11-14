package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"
)

const DefaultMaxScriptSize = 16 * 1024 // 16 KB

type ManageSieveServer struct {
	addr                string
	name                string
	hostname            string
	rdb                 *resilient.ResilientDatabase
	appCtx              context.Context
	cancel              context.CancelFunc
	tlsConfig           *tls.Config
	useStartTLS         bool
	insecureAuth        bool
	maxScriptSize       int64
	supportedExtensions []string // List of supported Sieve extensions
	masterUsername      []byte
	masterPassword      []byte
	masterSASLUsername  []byte
	masterSASLPassword  []byte

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection limiting
	limiter *serverPkg.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// PROXY protocol support
	proxyReader *serverPkg.ProxyProtocolReader

	// Authentication rate limiting
	authLimiter serverPkg.AuthLimiter

	// Command timeout and throughput enforcement
	authIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	commandTimeout         time.Duration
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)

	// Connection tracking
	connTracker *proxy.ConnectionTracker

	// Active session tracking for graceful shutdown
	activeSessionsMutex sync.RWMutex
	activeSessions      map[*ManageSieveSession]struct{}
	sessionsWg          sync.WaitGroup // Tracks active sessions for graceful drain
}

type ManageSieveServerOptions struct {
	InsecureAuth               bool
	Debug                      bool
	TLS                        bool
	TLSCertFile                string
	TLSKeyFile                 string
	TLSVerify                  bool
	TLSUseStartTLS             bool
	TLSConfig                  *tls.Config // Global TLS config from TLS manager (optional)
	MaxScriptSize              int64
	SupportedExtensions        []string // List of supported Sieve extensions
	MasterUsername             string
	MasterPassword             string
	MasterSASLUsername         string
	MasterSASLPassword         string
	MaxConnections             int
	MaxConnectionsPerIP        int
	MaxConnectionsPerUser      int      // Maximum connections per user (0=unlimited) - used for local tracking on backends
	MaxConnectionsPerUserPerIP int      // Maximum connections per user per IP (0=unlimited)
	ListenBacklog              int      // TCP listen backlog size (0 = use default 1024)
	ProxyProtocol              bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout       string   // Timeout for reading PROXY headers
	TrustedNetworks            []string // Global trusted networks for parameter forwarding
	AuthRateLimit              serverPkg.AuthRateLimiterConfig
	AuthIdleTimeout            time.Duration  // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	CommandTimeout             time.Duration  // Maximum idle time before disconnection
	AbsoluteSessionTimeout     time.Duration  // Maximum total session duration (0 = use default 30m)
	MinBytesPerMinute          int64          // Minimum throughput to prevent slowloris (0 = use default 512 bytes/min)
	Config                     *config.Config // Full config for shared settings like connection tracking timeouts
}

func New(appCtx context.Context, name, hostname, addr string, rdb *resilient.ResilientDatabase, options ManageSieveServerOptions) (*ManageSieveServer, error) {
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Initialize PROXY protocol reader if enabled
	var proxyReader *serverPkg.ProxyProtocolReader
	if options.ProxyProtocol {
		// Create ProxyProtocolConfig from simplified settings
		proxyConfig := serverPkg.ProxyProtocolConfig{
			Enabled:        true,
			Mode:           "required",
			TrustedProxies: options.TrustedNetworks,
			Timeout:        options.ProxyProtocolTimeout,
		}

		// Proxy protocol is always required when enabled

		var err error
		proxyReader, err = serverPkg.NewProxyProtocolReader("ManageSieve", proxyConfig)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Validate SIEVE extensions
	if err := ValidateExtensions(options.SupportedExtensions); err != nil {
		serverCancel()
		return nil, fmt.Errorf("invalid ManageSieve configuration: %w", err)
	}

	// Validate TLS configuration: tls_use_starttls only makes sense when tls = true
	if !options.TLS && options.TLSUseStartTLS {
		logger.Debug("ManageSieve: WARNING - tls_use_starttls ignored because tls=false", "name", name)
		// Force TLSUseStartTLS to false to avoid confusion
		options.TLSUseStartTLS = false
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("ManageSieve", options.AuthRateLimit, options.TrustedNetworks)

	serverInstance := &ManageSieveServer{
		hostname:               hostname,
		name:                   name,
		addr:                   addr,
		rdb:                    rdb,
		appCtx:                 serverCtx,
		cancel:                 serverCancel,
		useStartTLS:            options.TLSUseStartTLS,
		insecureAuth:           options.InsecureAuth,
		maxScriptSize:          options.MaxScriptSize,
		supportedExtensions:    options.SupportedExtensions,
		masterUsername:         []byte(options.MasterUsername),
		masterPassword:         []byte(options.MasterPassword),
		masterSASLUsername:     []byte(options.MasterSASLUsername),
		masterSASLPassword:     []byte(options.MasterSASLPassword),
		proxyReader:            proxyReader,
		authLimiter:            authLimiter,
		authIdleTimeout:        options.AuthIdleTimeout,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
		activeSessions:         make(map[*ManageSieveSession]struct{}),
	}

	// Use all supported extensions by default if none are configured
	if len(serverInstance.supportedExtensions) == 0 {
		serverInstance.supportedExtensions = GoSieveSupportedExtensions
		logger.Debug("ManageSieve: No supported_extensions configured - using all available", "name", name, "extensions", GoSieveSupportedExtensions)
	}

	// Create connection limiter with trusted networks from server configuration
	// For ManageSieve backend:
	// - If PROXY protocol is enabled: only connections from trusted networks allowed, no per-IP limiting
	// - If PROXY protocol is disabled: trusted networks bypass per-IP limits, others are limited per-IP
	var limiterTrustedNets []string
	var limiterMaxPerIP int

	if options.ProxyProtocol {
		// PROXY protocol enabled: use trusted networks, disable per-IP limiting
		limiterTrustedNets = options.TrustedNetworks
		limiterMaxPerIP = 0 // No per-IP limiting when PROXY protocol is enabled
	} else {
		// PROXY protocol disabled: use trusted networks for per-IP bypass
		limiterTrustedNets = options.TrustedNetworks
		limiterMaxPerIP = options.MaxConnectionsPerIP
	}

	serverInstance.limiter = serverPkg.NewConnectionLimiterWithTrustedNets("ManageSieve", options.MaxConnections, limiterMaxPerIP, limiterTrustedNets)

	// Set listen backlog with reasonable default
	serverInstance.listenBacklog = options.ListenBacklog
	if serverInstance.listenBacklog == 0 {
		serverInstance.listenBacklog = 1024 // Default backlog
	}

	// Set up TLS config: Support both file-based certificates and global TLS manager
	// 1. Per-server TLS: cert files provided (for both implicit TLS and STARTTLS)
	// 2. Global TLS: options.TLS=true, no cert files, global TLS config provided (for both implicit TLS and STARTTLS)
	// 3. No TLS: options.TLS=false
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		serverInstance.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"sieve"},
			Renegotiation:            tls.RenegotiateNever,
		}

		if !options.TLSVerify {
			serverInstance.tlsConfig.InsecureSkipVerify = true
			logger.Debug("ManageSieve: WARNING - TLS certificate verification disabled", "name", name)
		}
	} else if options.TLS && options.TLSConfig != nil {
		// Scenario 2: Global TLS manager (works for both implicit TLS and STARTTLS)
		serverInstance.tlsConfig = options.TLSConfig
	} else if options.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		serverCancel()
		return nil, fmt.Errorf("TLS enabled for ManageSieve [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", name)
	}

	// Start connection limiter cleanup
	serverInstance.limiter.StartCleanup(serverCtx)

	// Initialize command timeout metrics
	if serverInstance.commandTimeout > 0 {
		metrics.CommandTimeoutThresholdSeconds.WithLabelValues("managesieve").Set(serverInstance.commandTimeout.Seconds())
	}

	// Initialize local connection tracking (no gossip, just local tracking)
	// This enables per-user connection limits and kick functionality on backend servers
	if options.MaxConnectionsPerUser > 0 {
		// Generate unique instance ID for this server instance
		instanceID := fmt.Sprintf("managesieve-%s-%d", name, time.Now().UnixNano())

		// Create ConnectionTracker with nil cluster manager (local mode only)
		serverInstance.connTracker = proxy.NewConnectionTracker(
			"ManageSieve",                      // protocol name
			instanceID,                         // unique instance identifier
			nil,                                // no cluster manager = local mode
			options.MaxConnectionsPerUser,      // per-user connection limit
			options.MaxConnectionsPerUserPerIP, // per-user-per-IP connection limit
			0,                                  // queue size (not used in local mode)
		)

		logger.Debug("ManageSieve: Local connection tracking enabled", "name", name, "max_connections_per_user", options.MaxConnectionsPerUser)
	} else {
		// Connection tracking disabled (unlimited connections per user)
		serverInstance.connTracker = nil
		logger.Debug("ManageSieve: Local connection tracking disabled", "name", name)
	}

	return serverInstance, nil
}

func (s *ManageSieveServer) Start(errChan chan error) {
	var listener net.Listener

	// Configure SoraConn with timeout protection
	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "managesieve",
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send BYE message before closing due to timeout (RFC 5804 Section 1.3)
			// Use TRYLATER response code to indicate temporary condition
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
			// Write BYE - ignore errors as connection may already be broken
			// This is best-effort to inform the client
			_, _ = fmt.Fprint(conn, message)
		},
	}

	isImplicitTLS := s.tlsConfig != nil && !s.useStartTLS
	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if isImplicitTLS {
		// Implicit TLS - create TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TCP listener: %w", err)
			return
		}
		logger.Debug("ManageSieve: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		listener = serverPkg.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("ManageSieve server listening with TLS", "name", s.name, "addr", s.addr, "idle_timeout",
				s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("ManageSieve server listening with TLS", "name", s.name, "addr", s.addr)
		}
	} else {
		// Create TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		logger.Debug("ManageSieve: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		listener = serverPkg.NewSoraListener(tcpListener, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("ManageSieve server listening", "name", s.name, "addr", s.addr, "tls", false, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("ManageSieve server listening", "name", s.name, "addr", s.addr, "tls", false)
		}
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if s.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: s.proxyReader,
		}
	}

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		logger.Debug("ManageSieve: stopping", "name", s.name)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if errors.Is(err, errProxyProtocol) {
				logger.Debug("ManageSieve: rejecting connection", "name", s.name, "error", err)
				continue // Continue accepting other connections
			}

			// Check if the error is due to the listener being closed (graceful shutdown)
			select {
			case <-s.appCtx.Done():
				logger.Info("ManageSieve server stopped gracefully", "name", s.name)
				return
			default:
				// For other errors, this might be a fatal server error
				errChan <- err
				return
			}
		}

		// Extract real client IP and proxy IP from PROXY protocol if available for connection limiting
		var proxyInfoForLimiting *serverPkg.ProxyProtocolInfo
		var realClientIP string
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfoForLimiting = proxyConn.GetProxyInfo()
			if proxyInfoForLimiting != nil && proxyInfoForLimiting.SrcIP != "" {
				realClientIP = proxyInfoForLimiting.SrcIP
			}
		}

		// Check connection limits with PROXY protocol support
		releaseConn, err := s.limiter.AcceptWithRealIP(conn.RemoteAddr(), realClientIP)
		if err != nil {
			logger.Debug("ManageSieve: Connection rejected", "name", s.name, "error", err)
			conn.Close()
			continue
		}

		// Increment total connections counter
		totalCount := s.totalConnections.Add(1)

		// Prometheus metrics - connection established
		metrics.ConnectionsTotal.WithLabelValues("managesieve").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("managesieve").Inc()
		authCount := s.authenticatedConnections.Load()

		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &ManageSieveSession{
			server:      s,
			conn:        &conn,
			reader:      bufio.NewReader(conn),
			writer:      bufio.NewWriter(conn),
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			isTLS:       isImplicitTLS, // Initialize isTLS based on the listener type
			releaseConn: releaseConn,
			startTime:   time.Now(),
		}

		// Extract real client IP and proxy IP from PROXY protocol if available
		// Need to unwrap connection layers to get to proxyProtocolConn
		var proxyInfo *serverPkg.ProxyProtocolInfo
		currentConn := conn
		for currentConn != nil {
			if proxyConn, ok := currentConn.(*proxyProtocolConn); ok {
				proxyInfo = proxyConn.GetProxyInfo()
				break
			}
			// Try to unwrap the connection
			if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
				currentConn = wrapper.Unwrap()
			} else {
				break
			}
		}

		clientIP, proxyIP := serverPkg.GetConnectionIPs(conn, proxyInfo)
		session.RemoteIP = clientIP
		session.ProxyIP = proxyIP
		session.Protocol = "ManageSieve"
		session.ServerName = s.name
		session.Id = idgen.New()
		session.HostName = session.server.hostname
		session.Stats = s // Set the server as the Stats provider

		// Create logging function for the mutex helper
		logFunc := func(format string, args ...any) {
			session.InfoLog(format, args...)
		}

		// Initialize the mutex helper
		session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "MANAGESIEVE", logFunc)

		// Build connection info for logging
		var remoteInfo string
		if session.ProxyIP != "" {
			remoteInfo = fmt.Sprintf("%s proxy=%s", session.RemoteIP, session.ProxyIP)
		} else {
			remoteInfo = session.RemoteIP
		}
		// Log connection with connection counters
		logger.Debug("ManageSieve: new connection", "name", s.name, "remote", remoteInfo, "total_connections", totalCount, "authenticated_connections", authCount)

		// Track session for graceful shutdown
		s.addSession(session)

		// Track session in WaitGroup for graceful drain
		s.sessionsWg.Add(1)

		go func() {
			defer s.sessionsWg.Done()
			session.handleConnection()
		}()
	}
}

// SetConnTracker sets the connection tracker for this server
func (s *ManageSieveServer) SetConnTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

func (s *ManageSieveServer) Close() {
	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Step 1: Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	// Step 2: Cancel context to signal sessions to finish
	if s.cancel != nil {
		s.cancel()
	}

	// Step 3: Wait for active sessions to finish gracefully (with timeout)
	s.waitForSessionsDrain(30 * time.Second)
}

// waitForSessionsDrain waits for all active sessions to finish with a timeout
func (s *ManageSieveServer) waitForSessionsDrain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.sessionsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("ManageSieve: All sessions drained gracefully", "name", s.name)
	case <-time.After(timeout):
		logger.Debug("ManageSieve: Session drain timeout, forcing shutdown", "name", s.name, "timeout", timeout)
	}
}

// addSession tracks an active session for graceful shutdown
func (s *ManageSieveServer) addSession(session *ManageSieveSession) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *ManageSieveServer) removeSession(session *ManageSieveSession) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a graceful shutdown notice to all active sessions
func (s *ManageSieveServer) sendGracefulShutdownMessage() {
	s.activeSessionsMutex.RLock()
	activeSessions := make([]*ManageSieveSession, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMutex.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("ManageSieve: Sending graceful shutdown message to active connections", "name", s.name, "count", len(activeSessions))

	// Send shutdown message to all active connections
	// ManageSieve uses BYE response for clean disconnection
	for _, session := range activeSessions {
		if session.conn != nil && *session.conn != nil {
			writer := bufio.NewWriter(*session.conn)
			// Send BYE with TRYLATER response code (RFC 5804 Section 1.3)
			writer.WriteString("BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n")
			writer.Flush()
		}
	}

	// Give clients a brief moment (1 second) to receive the message
	time.Sleep(1 * time.Second)

	// Close connections to unblock any sessions blocked on reads
	for _, session := range activeSessions {
		if session.conn != nil && *session.conn != nil {
			(*session.conn).Close()
		}
	}

	logger.Debug("ManageSieve: Proceeding with connection cleanup", "name", s.name)
}

// GetTotalConnections returns the current total connection count
func (s *ManageSieveServer) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *ManageSieveServer) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}

var errProxyProtocol = errors.New("PROXY protocol error")

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *serverPkg.ProxyProtocolReader
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Try to read PROXY protocol header
		proxyInfo, wrappedConn, err := l.proxyReader.ReadProxyHeader(conn)
		if err == nil {
			// PROXY header found and parsed successfully.
			return &proxyProtocolConn{
				Conn:      wrappedConn,
				proxyInfo: proxyInfo,
			}, nil
		}

		// An error occurred. Check if we are in "optional" mode and the error is simply that no PROXY header was present.
		// This requires the underlying ProxyProtocolReader to be updated to return a specific error (e.g., serverPkg.ErrNoProxyHeader)
		// and to not consume bytes from the connection if no header is found.
		if l.proxyReader.IsOptionalMode() && errors.Is(err, serverPkg.ErrNoProxyHeader) {
			// Note: We don't have access to server name in this listener, use generic ManageSieve
			logger.Debug("ManageSieve: No PROXY protocol header - treating as direct", "remote", serverPkg.GetAddrString(conn.RemoteAddr()))
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic ManageSieve
		logger.Debug("ManageSieve: PROXY protocol error - rejecting", "remote", serverPkg.GetAddrString(conn.RemoteAddr()), "error", err)
		continue
	}
}

// proxyProtocolConn wraps a connection with PROXY protocol information
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *serverPkg.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *serverPkg.ProxyProtocolInfo {
	return c.proxyInfo
}
