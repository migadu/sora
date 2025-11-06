package imapproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// Server represents an IMAP proxy server.
type Server struct {
	listener               net.Listener
	listenerMu             sync.RWMutex
	rdb                    *resilient.ResilientDatabase
	name                   string // Server name for logging
	addr                   string
	hostname               string
	connManager            *proxy.ConnectionManager
	connTracker            *proxy.ConnectionTracker
	masterUsername         []byte
	masterPassword         []byte
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	tls                    bool
	tlsCertFile            string
	tlsKeyFile             string
	tlsVerify              bool
	tlsConfig              *tls.Config // Global TLS config from TLS manager (optional)
	enableAffinity         bool
	authIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only)
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput
	wg                     sync.WaitGroup
	ctx                    context.Context
	cancel                 context.CancelFunc
	authLimiter            server.AuthLimiter
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	prelookupConfig        *config.PreLookupConfig
	remoteUseIDCommand     bool // Whether backend supports IMAP ID command for forwarding

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// Debug logging
	debug       bool
	debugWriter io.Writer

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*Session]struct{}
}

// maskingWriter wraps an io.Writer to mask sensitive information in IMAP commands
type maskingWriter struct {
	w io.Writer
}

// Write inspects the log output, and if it's a client command (prefixed with "C: "),
// it attempts to mask sensitive parts of LOGIN or AUTHENTICATE commands.
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
	if len(parts) < 2 { // Needs at least tag and command
		return mw.w.Write(p)
	}

	command := strings.ToUpper(parts[1])

	// Use the helper to mask the command line
	maskedCmdLine := helpers.MaskSensitive(trimmedCmdLine, command, "LOGIN", "AUTHENTICATE")

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

// ServerOptions holds options for creating a new IMAP proxy server.
type ServerOptions struct {
	Name                   string // Server name for logging
	Addr                   string
	RemoteAddrs            []string
	RemotePort             int // Default port for backends if not in address
	MasterUsername         string
	MasterPassword         string
	MasterSASLUsername     string
	MasterSASLPassword     string
	TLS                    bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	TLSConfig              *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	ConnectTimeout         time.Duration
	AuthIdleTimeout        time.Duration
	CommandTimeout         time.Duration // Idle timeout
	AbsoluteSessionTimeout time.Duration // Maximum total session duration
	MinBytesPerMinute      int64         // Minimum throughput
	EnableAffinity         bool
	AuthRateLimit          server.AuthRateLimiterConfig
	PreLookup              *config.PreLookupConfig
	TrustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseIDCommand     bool     // Whether backend supports IMAP ID command for forwarding

	// Connection limiting
	MaxConnections      int      // Maximum total connections (0 = unlimited)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits
	ListenBacklog       int      // TCP listen backlog size (0 = system default; recommended: 4096-8192)

	// Debug logging
	Debug bool // Enable debug logging with password masking
}

// New creates a new IMAP proxy server.
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

	// Ensure PreLookup config has a default value to avoid nil panics.
	if opts.PreLookup == nil {
		opts.PreLookup = &config.PreLookupConfig{}
	}

	// Initialize prelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.PreLookup.Enabled {
		prelookupClient, err := proxy.InitializePrelookup(opts.PreLookup)
		if err != nil {
			logger.Error("Failed to initialize prelookup client", "proxy", opts.Name, "error", err)
			if !opts.PreLookup.FallbackDefault {
				cancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			logger.Warn("Continuing without prelookup due to fallback_to_default=true", "proxy", opts.Name)
		} else {
			routingLookup = prelookupClient
			if opts.Debug {
				logger.Debug("Prelookup client initialized successfully", "proxy", opts.Name)
			}
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRouting(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup, opts.Name)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Warn("Failed to resolve addresses", "proxy", opts.Name, "error", err)
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("IMAP-PROXY", opts.AuthRateLimit, rdb, opts.TrustedProxies)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		limiter = server.NewConnectionLimiterWithTrustedNets("IMAP-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
	}

	// Setup debug writer with password masking if debug is enabled
	var debugWriter io.Writer
	if opts.Debug {
		debugWriter = &maskingWriter{w: os.Stdout}
	}

	// Set listen backlog with reasonable default
	listenBacklog := opts.ListenBacklog
	if listenBacklog == 0 {
		listenBacklog = 1024 // Default backlog
	}

	return &Server{
		rdb:                    rdb,
		name:                   opts.Name,
		addr:                   opts.Addr,
		hostname:               hostname,
		connManager:            connManager,
		masterUsername:         []byte(opts.MasterUsername),
		masterPassword:         []byte(opts.MasterPassword),
		masterSASLUsername:     []byte(opts.MasterSASLUsername),
		masterSASLPassword:     []byte(opts.MasterSASLPassword),
		tls:                    opts.TLS,
		tlsCertFile:            opts.TLSCertFile,
		tlsKeyFile:             opts.TLSKeyFile,
		tlsVerify:              opts.TLSVerify,
		tlsConfig:              opts.TLSConfig,
		enableAffinity:         opts.EnableAffinity,
		authIdleTimeout:        opts.AuthIdleTimeout,
		commandTimeout:         opts.CommandTimeout,
		absoluteSessionTimeout: opts.AbsoluteSessionTimeout,
		minBytesPerMinute:      opts.MinBytesPerMinute,
		ctx:                    ctx,
		cancel:                 cancel,
		authLimiter:            authLimiter,
		trustedProxies:         opts.TrustedProxies,
		prelookupConfig:        opts.PreLookup,
		remoteUseIDCommand:     opts.RemoteUseIDCommand,
		limiter:                limiter,
		listenBacklog:          listenBacklog,
		debug:                  opts.Debug,
		debugWriter:            debugWriter,
		activeSessions:         make(map[*Session]struct{}),
	}, nil
}

// Start starts the IMAP proxy server.
func (s *Server) Start() error {

	// Three TLS scenarios:
	// 1. Per-server TLS: cert files provided
	// 2. Global TLS: tls=true, no cert files, global TLS config provided
	// 3. No TLS: tls=false
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

		tlsConfig := &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			ServerName:               s.hostname,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"imap"},
			Renegotiation:            tls.RenegotiateNever,
		}

		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("IMAP Proxy: Using listen backlog", "proxy", s.name, "backlog", s.listenBacklog)
		// Wrap with SoraTLSListener for TLS + JA4 capture + timeout protection
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
			OnTimeout: func(conn net.Conn, reason string) {
				// Send BYE to client before closing
				var message string
				switch reason {
				case "idle":
					message = "* BYE Idle timeout, please reconnect\r\n"
				case "slow_throughput":
					message = "* BYE Connection too slow, please reconnect\r\n"
				case "session_max":
					message = "* BYE Maximum session duration exceeded, please reconnect\r\n"
				default:
					message = "* BYE Connection timeout, please reconnect\r\n"
				}
				_, _ = fmt.Fprint(conn, message)
			},
		}
		s.listener = server.NewSoraTLSListener(tcpListener, tlsConfig, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls && s.tlsConfig != nil {
		// Scenario 2: Global TLS manager
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		logger.Debug("IMAP Proxy: Using listen backlog", "proxy", s.name, "backlog", s.listenBacklog)
		// Wrap with SoraTLSListener for TLS + JA4 capture + timeout protection
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
			OnTimeout: func(conn net.Conn, reason string) {
				// Send BYE to client before closing
				var message string
				switch reason {
				case "idle":
					message = "* BYE Idle timeout, please reconnect\r\n"
				case "slow_throughput":
					message = "* BYE Connection too slow, please reconnect\r\n"
				case "session_max":
					message = "* BYE Maximum session duration exceeded, please reconnect\r\n"
				default:
					message = "* BYE Connection timeout, please reconnect\r\n"
				}
				_, _ = fmt.Fprint(conn, message)
			},
		}
		s.listener = server.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for IMAP proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
	} else {
		// Scenario 3: No TLS
		s.listenerMu.Lock()
		// Create base TCP listener with custom backlog
		tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start listener: %w", err)
		}
		logger.Debug("IMAP Proxy: Using listen backlog", "proxy", s.name, "backlog", s.listenBacklog)
		// Wrap with SoraListener for timeout protection (no TLS/JA4)
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
			OnTimeout: func(conn net.Conn, reason string) {
				// Send BYE to client before closing
				var message string
				switch reason {
				case "idle":
					message = "* BYE Idle timeout, please reconnect\r\n"
				case "slow_throughput":
					message = "* BYE Connection too slow, please reconnect\r\n"
				case "session_max":
					message = "* BYE Maximum session duration exceeded, please reconnect\r\n"
				default:
					message = "* BYE Connection timeout, please reconnect\r\n"
				}
				_, _ = fmt.Fprint(conn, message)
			},
		}
		s.listener = server.NewSoraListener(tcpListener, connConfig)
		s.listenerMu.Unlock()
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	return s.acceptConnections()
}

// acceptConnections accepts incoming connections.
func (s *Server) acceptConnections() error {
	for {
		acceptStart := time.Now()
		conn, err := s.listener.Accept()
		acceptDuration := time.Since(acceptStart)
		if acceptDuration > 100*time.Millisecond {
			logger.Warn("IMAP Proxy: Slow accept() detected", "proxy", s.name, "duration", acceptDuration)
		}
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // Graceful shutdown
			default:
				// All Accept() errors are connection-level issues (TLS handshake failures, client disconnects, etc.)
				// They should be logged but not crash the server - the listener itself is still healthy
				logger.Warn("Failed to accept connection", "proxy", s.name, "error", err)
				continue // Continue accepting other connections
			}
		}

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.AcceptWithRealIP(conn.RemoteAddr(), "")
			if err != nil {
				logger.Warn("Connection rejected", "proxy", s.name, "error", err)
				conn.Close()
				continue // Try to accept the next connection
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				// Release connection limit when session ends
				if releaseConn != nil {
					releaseConn()
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Session panic recovered", "proxy", s.name, "error", r)
					conn.Close()
				}
			}()

			// Track proxy connection
			metrics.ConnectionsTotal.WithLabelValues("imap_proxy").Inc()
			metrics.ConnectionsCurrent.WithLabelValues("imap_proxy").Inc()

			session := newSession(s, conn)
			s.addSession(session)
			session.handleConnection()
		}()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *Server) SetConnectionTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

// GetConnectionManager returns the connection manager for health checks
func (s *Server) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

// Stop stops the IMAP proxy server.
func (s *Server) Stop() error {
	logger.Info("Stopping proxy server", "proxy", s.name)

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
		logger.Info("Proxy server stopped gracefully", "proxy", s.name)
	case <-time.After(30 * time.Second):
		logger.Warn("Proxy server stop timeout", "proxy", s.name)
	}

	// Close prelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			logger.Debug("Closing prelookup client", "proxy", s.name)
			if err := routingLookup.Close(); err != nil {
				logger.Error("Error closing prelookup client", "proxy", s.name, "error", err)
			}
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

	logger.Info("Sending graceful shutdown messages", "proxy", s.name, "count", len(activeSessions))

	// Send shutdown messages to both client and backend
	for _, session := range activeSessions {
		// Lock the session to safely access writers
		session.mu.Lock()

		// Send BYE to client
		if session.clientWriter != nil {
			session.clientWriter.WriteString("* BYE Server shutting down, please reconnect\r\n")
			session.clientWriter.Flush()
		}

		// Send LOGOUT to backend for clean disconnect
		if session.backendWriter != nil {
			// Generate a unique tag for the LOGOUT command
			session.backendWriter.WriteString("PROXY1 LOGOUT\r\n")
			session.backendWriter.Flush()
		}

		session.mu.Unlock()
	}

	// Give both clients and backends a brief moment to process
	time.Sleep(1 * time.Second)

	logger.Debug("Proceeding with connection cleanup", "proxy", s.name)
}
