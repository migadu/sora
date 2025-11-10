package pop3

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

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type POP3Server struct {
	addr               string
	name               string
	hostname           string
	rdb                *resilient.ResilientDatabase
	s3                 *resilient.ResilientS3Storage
	appCtx             context.Context
	cancel             context.CancelFunc
	uploader           *uploader.UploadWorker
	cache              *cache.Cache
	tlsConfig          *tls.Config
	masterUsername     []byte
	masterPassword     []byte
	masterSASLUsername []byte
	masterSASLPassword []byte

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

	// XCLIENT is always enabled but limited to trusted networks
	trustedNetworks []string

	// Memory limiting
	sessionMemoryLimit int64

	// Command timeout and throughput enforcement
	authIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	commandTimeout         time.Duration
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)

	// Connection tracking
	connTracker *proxy.ConnectionTracker

	// Active session tracking for graceful shutdown
	activeSessionsMutex sync.RWMutex
	activeSessions      map[*POP3Session]struct{}
	sessionsWg          sync.WaitGroup // Tracks active sessions for graceful drain
}

type POP3ServerOptions struct {
	Debug                  bool
	TLS                    bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	MasterUsername         string
	MasterPassword         string
	MasterSASLUsername     string
	MasterSASLPassword     string
	MaxConnections         int
	MaxConnectionsPerIP    int
	MaxConnectionsPerUser  int      // Maximum connections per user (0=unlimited) - used for local tracking on backends
	ListenBacklog          int      // TCP listen backlog size (0 = use default 1024)
	ProxyProtocol          bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout   string   // Timeout for reading PROXY headers
	TrustedNetworks        []string // Global trusted networks for parameter forwarding
	AuthRateLimit          serverPkg.AuthRateLimiterConfig
	SessionMemoryLimit     int64          // Memory limit per session in bytes
	AuthIdleTimeout        time.Duration  // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	CommandTimeout         time.Duration  // Maximum idle time before disconnection
	AbsoluteSessionTimeout time.Duration  // Maximum total session duration (0 = use default 30m)
	MinBytesPerMinute      int64          // Minimum throughput to prevent slowloris (0 = use default 512 bytes/min)
	Config                 *config.Config // Full config for shared settings like connection tracking timeouts
}

func New(appCtx context.Context, name, hostname, popAddr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options POP3ServerOptions) (*POP3Server, error) {
	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)

	// Create a new context with a cancel function for clean shutdown
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
		proxyReader, err = serverPkg.NewProxyProtocolReader("POP3", proxyConfig)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("POP3", options.AuthRateLimit, options.TrustedNetworks)

	server := &POP3Server{
		hostname:               hostname,
		name:                   name,
		addr:                   popAddr,
		rdb:                    rdb,
		s3:                     resilientS3,
		appCtx:                 serverCtx,
		cancel:                 serverCancel,
		uploader:               uploadWorker,
		cache:                  cache,
		masterUsername:         []byte(options.MasterUsername),
		masterPassword:         []byte(options.MasterPassword),
		masterSASLUsername:     []byte(options.MasterSASLUsername),
		masterSASLPassword:     []byte(options.MasterSASLPassword),
		proxyReader:            proxyReader,
		authLimiter:            authLimiter,
		trustedNetworks:        options.TrustedNetworks,
		sessionMemoryLimit:     options.SessionMemoryLimit,
		authIdleTimeout:        options.AuthIdleTimeout,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
		activeSessions:         make(map[*POP3Session]struct{}),
	}

	// Create connection limiter with trusted networks from server configuration
	// For POP3 backend:
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

	server.limiter = serverPkg.NewConnectionLimiterWithTrustedNets("POP3", options.MaxConnections, limiterMaxPerIP, limiterTrustedNets)

	// Set listen backlog with reasonable default
	server.listenBacklog = options.ListenBacklog
	if server.listenBacklog == 0 {
		server.listenBacklog = 1024 // Default backlog
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
			NextProtos:               []string{"pop3"},
			Renegotiation:            tls.RenegotiateNever,
		}

		// Set InsecureSkipVerify if requested (for self-signed certificates)
		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			logger.Debug("POP3: WARNING - TLS certificate verification not enforced", "name", name)
		}
	}

	// Start connection limiter cleanup
	server.limiter.StartCleanup(serverCtx)

	// Initialize command timeout metrics
	if server.commandTimeout > 0 {
		metrics.CommandTimeoutThresholdSeconds.WithLabelValues("pop3").Set(server.commandTimeout.Seconds())
	}

	// Initialize local connection tracking (no gossip, just local tracking)
	// This enables per-user connection limits and kick functionality on backend servers
	if options.MaxConnectionsPerUser > 0 {
		// Generate unique instance ID for this server instance
		instanceID := fmt.Sprintf("pop3-%s-%d", name, time.Now().UnixNano())

		// Create ConnectionTracker with nil cluster manager (local mode only)
		server.connTracker = proxy.NewConnectionTracker(
			"POP3",                        // protocol name
			instanceID,                    // unique instance identifier
			nil,                           // no cluster manager = local mode
			options.MaxConnectionsPerUser, // per-user connection limit
			0,                             // queue size (not used in local mode)
		)

		logger.Debug("POP3: Local connection tracking enabled", "name", name, "max", options.MaxConnectionsPerUser)
	} else {
		// Connection tracking disabled (unlimited connections per user)
		server.connTracker = nil
		logger.Debug("POP3: Local connection tracking disabled", "name", name)
	}

	return server, nil
}

func (s *POP3Server) Start(errChan chan error) {
	var listener net.Listener

	// Configure SoraConn with timeout protection
	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "pop3",
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send POP3 error message before closing due to timeout
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
			// Write error message - ignore errors as connection may already be broken
			// This is best-effort to inform the client
			_, _ = fmt.Fprint(conn, message)
		},
	}

	if s.tlsConfig != nil {
		// Create base TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.cancel()
			errChan <- fmt.Errorf("failed to create TCP listener: %w", err)
			return
		}
		logger.Debug("POP3: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		// Use SoraTLSListener for TLS with timeout protection
		listener = serverPkg.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("POP3 server listening with TLS", "name", s.name, "addr", s.addr, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("POP3 server listening with TLS", "name", s.name, "addr", s.addr)
		}
	} else {
		// Create base TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.cancel()
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		logger.Debug("POP3: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		// Use SoraListener for non-TLS with timeout protection
		listener = serverPkg.NewSoraListener(tcpListener, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("POP3 server listening", "name", s.name, "addr", s.addr, "tls", false, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("POP3 server listening", "name", s.name, "addr", s.addr, "tls", false)
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
		logger.Debug("POP3: stopping", "name", s.name)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if errors.Is(err, errProxyProtocol) {
				logger.Debug("POP3: rejecting connection", "name", s.name, "error", err)
				continue // Continue accepting other connections
			}

			// Check if the error is due to the listener being closed (graceful shutdown)
			select {
			case <-s.appCtx.Done():
				logger.Info("POP3 server stopped gracefully", "name", s.name)
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
			logger.Debug("POP3: Connection rejected", "name", s.name, "error", err)
			conn.Close()
			continue
		}

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		totalCount := s.totalConnections.Add(1)
		authCount := s.authenticatedConnections.Load()

		// Prometheus metrics - connection established
		metrics.ConnectionsTotal.WithLabelValues("pop3").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("pop3").Inc()

		// Initialize memory tracker with configured limit
		memTracker := serverPkg.NewSessionMemoryTracker(s.sessionMemoryLimit)

		session := &POP3Session{
			server:      s,
			conn:        &conn,
			deleted:     make(map[int]bool),
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			language:    "en", // Default language
			releaseConn: releaseConn,
			startTime:   time.Now(),
			memTracker:  memTracker,
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
		session.Protocol = "POP3"
		session.ServerName = s.name
		session.Id = idgen.New()
		session.HostName = s.hostname
		session.Stats = s
		session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "POP3", session.InfoLog)

		// Build connection info for logging
		var remoteInfo string
		if session.ProxyIP != "" {
			remoteInfo = fmt.Sprintf("%s proxy=%s", session.RemoteIP, session.ProxyIP)
		} else {
			remoteInfo = session.RemoteIP
		}
		logger.Debug("POP3: new connection", "name", s.name, "remote", remoteInfo, "total_connections", totalCount, "authenticated_connections", authCount)

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
func (s *POP3Server) SetConnTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

func (s *POP3Server) Close() {
	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Step 1: Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	// Step 2: Cancel context to signal sessions to finish
	// This will propagate to all session contexts
	if s.cancel != nil {
		s.cancel()
	}

	// Step 3: Wait for active sessions to finish gracefully (with timeout)
	s.waitForSessionsDrain(30 * time.Second)
}

// waitForSessionsDrain waits for all active sessions to finish with a timeout
func (s *POP3Server) waitForSessionsDrain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.sessionsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("POP3: All sessions drained gracefully", "name", s.name)
	case <-time.After(timeout):
		logger.Debug("POP3: Session drain timeout, forcing shutdown", "name", s.name, "timeout", timeout)
	}
}

// addSession tracks an active session for graceful shutdown
func (s *POP3Server) addSession(session *POP3Session) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *POP3Server) removeSession(session *POP3Session) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a graceful shutdown notice to all active sessions
func (s *POP3Server) sendGracefulShutdownMessage() {
	s.activeSessionsMutex.RLock()
	activeSessions := make([]*POP3Session, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMutex.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("POP3: Sending graceful shutdown message to active connections", "name", s.name, "count", len(activeSessions))

	// Send shutdown message to all active connections
	for _, session := range activeSessions {
		if session.conn != nil && *session.conn != nil {
			writer := bufio.NewWriter(*session.conn)
			// POP3 doesn't have a specific "server shutting down" response code
			// But we can send a polite message before disconnection
			writer.WriteString("-ERR Server shutting down, please reconnect\r\n")
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

	logger.Debug("POP3: Proceeding with connection cleanup", "name", s.name)
}

// GetTotalConnections returns the current total connection count
func (s *POP3Server) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *POP3Server) GetAuthenticatedConnections() int64 {
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
			// Note: We don't have access to server name in this listener, use generic POP3
			logger.Debug("POP3: No PROXY protocol header - treating as direct", "remote", serverPkg.GetAddrString(conn.RemoteAddr()))
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic POP3
		logger.Debug("POP3: PROXY protocol error - rejecting", "remote", serverPkg.GetAddrString(conn.RemoteAddr()), "error", err)
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

// Unwrap returns the underlying connection for connection unwrapping
func (c *proxyProtocolConn) Unwrap() net.Conn {
	return c.Conn
}
