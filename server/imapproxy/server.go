package imapproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
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
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	tls                    bool
	tlsCertFile            string
	tlsKeyFile             string
	tlsVerify              bool
	tlsConfig              *tls.Config // Global TLS config from TLS manager (optional)
	enableAffinity         bool
	sessionTimeout         time.Duration
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

	// Debug logging
	debug       bool
	debugWriter io.Writer
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
	SessionTimeout         time.Duration
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
			log.Printf("[IMAP Proxy %s] Failed to initialize prelookup client: %v", opts.Name, err)
			if !opts.PreLookup.FallbackDefault {
				cancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			log.Printf("[IMAP Proxy %s] Continuing without prelookup due to fallback_to_default=true", opts.Name)
		} else {
			routingLookup = prelookupClient
			if opts.Debug {
				log.Printf("[IMAP Proxy %s] Prelookup client initialized successfully", opts.Name)
			}
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRouting(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[IMAP Proxy %s] Failed to resolve addresses: %v", opts.Name, err)
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

	return &Server{
		rdb:                    rdb,
		name:                   opts.Name,
		addr:                   opts.Addr,
		hostname:               hostname,
		connManager:            connManager,
		masterSASLUsername:     []byte(opts.MasterSASLUsername),
		masterSASLPassword:     []byte(opts.MasterSASLPassword),
		tls:                    opts.TLS,
		tlsCertFile:            opts.TLSCertFile,
		tlsKeyFile:             opts.TLSKeyFile,
		tlsVerify:              opts.TLSVerify,
		tlsConfig:              opts.TLSConfig,
		enableAffinity:         opts.EnableAffinity,
		sessionTimeout:         opts.SessionTimeout,
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
		debug:                  opts.Debug,
		debugWriter:            debugWriter,
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
		}

		s.listenerMu.Lock()
		// Create base TCP listener
		tcpListener, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		// Wrap with SoraTLSListener for TLS + JA4 capture + timeout protection
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
		}
		s.listener = server.NewSoraTLSListener(tcpListener, tlsConfig, connConfig)
		s.listenerMu.Unlock()
	} else if s.tls && s.tlsConfig != nil {
		// Scenario 2: Global TLS manager
		s.listenerMu.Lock()
		// Create base TCP listener
		tcpListener, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		// Wrap with SoraTLSListener for TLS + JA4 capture + timeout protection
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
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
		tcpListener, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.listenerMu.Unlock()
			return fmt.Errorf("failed to start listener: %w", err)
		}
		// Wrap with SoraListener for timeout protection (no TLS/JA4)
		connConfig := server.SoraConnConfig{
			Protocol:             "imap_proxy",
			IdleTimeout:          s.commandTimeout,
			AbsoluteTimeout:      s.absoluteSessionTimeout,
			MinBytesPerMinute:    s.minBytesPerMinute,
			EnableTimeoutChecker: true,
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
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // Graceful shutdown
			default:
				// All Accept() errors are connection-level issues (TLS handshake failures, client disconnects, etc.)
				// They should be logged but not crash the server - the listener itself is still healthy
				log.Printf("[IMAP Proxy %s] Failed to accept connection: %v", s.name, err)
				continue // Continue accepting other connections
			}
		}

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.Accept(conn.RemoteAddr())
			if err != nil {
				log.Printf("[IMAP Proxy %s] Connection rejected: %v", s.name, err)
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
					log.Printf("[IMAP Proxy %s] Session panic recovered: %v", s.name, r)
					conn.Close()
				}
			}()

			// Track proxy connection
			metrics.ConnectionsTotal.WithLabelValues("imap_proxy").Inc()
			metrics.ConnectionsCurrent.WithLabelValues("imap_proxy").Inc()

			session := newSession(s, conn)
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
	log.Printf("IMAP Proxy [%s] stopping...", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

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
		log.Printf("IMAP Proxy [%s] server stopped gracefully", s.name)
	case <-time.After(30 * time.Second):
		log.Printf("IMAP Proxy [%s] Server stop timeout", s.name)
	}

	// Close prelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			log.Printf("IMAP Proxy [%s] closing prelookup client...", s.name)
			if err := routingLookup.Close(); err != nil {
				log.Printf("IMAP Proxy [%s] error closing prelookup client: %v", s.name, err)
			}
		}
	}

	return nil
}
