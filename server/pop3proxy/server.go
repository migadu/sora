package pop3proxy

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

type POP3ProxyServer struct {
	name                   string // Server name for logging
	addr                   string
	hostname               string
	rdb                    *resilient.ResilientDatabase
	appCtx                 context.Context
	cancel                 context.CancelFunc
	tlsConfig              *tls.Config
	masterSASLUsername     string
	masterSASLPassword     string
	connManager            *proxy.ConnectionManager
	connTracker            *proxy.ConnectionTracker
	wg                     sync.WaitGroup
	enableAffinity         bool
	affinityValidity       time.Duration
	affinityStickiness     float64
	authLimiter            server.AuthLimiter
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	prelookupConfig        *config.PreLookupConfig
	sessionTimeout         time.Duration
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput
	remoteUseXCLIENT       bool          // Whether backend supports XCLIENT command for forwarding

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Debug logging
	debugWriter io.Writer
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
	Name                   string // Server name for logging
	Debug                  bool
	TLS                    bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	TLSConfig              *tls.Config // Global TLS config from TLS manager (optional)
	RemoteAddrs            []string
	RemotePort             int // Default port for backends if not in address
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	MasterSASLUsername     string
	MasterSASLPassword     string
	ConnectTimeout         time.Duration
	SessionTimeout         time.Duration
	CommandTimeout         time.Duration // Idle timeout
	AbsoluteSessionTimeout time.Duration // Maximum total session duration
	MinBytesPerMinute      int64         // Minimum throughput
	EnableAffinity         bool
	AffinityValidity       time.Duration
	AffinityStickiness     float64
	AuthRateLimit          server.AuthRateLimiterConfig
	PreLookup              *config.PreLookupConfig
	TrustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT       bool     // Whether backend supports XCLIENT command for forwarding

	// Connection limiting
	MaxConnections      int      // Maximum total connections (0 = unlimited)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits
}

func New(appCtx context.Context, hostname, addr string, rdb *resilient.ResilientDatabase, options POP3ProxyServerOptions) (*POP3ProxyServer, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Ensure PreLookup config has a default value to avoid nil panics.
	if options.PreLookup == nil {
		options.PreLookup = &config.PreLookupConfig{}
	}

	// Initialize prelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if options.PreLookup != nil && options.PreLookup.Enabled {
		prelookupClient, err := proxy.InitializePrelookup(options.PreLookup)
		if err != nil {
			log.Printf("[POP3 Proxy %s] Failed to initialize prelookup client: %v", options.Name, err)
			if !options.PreLookup.FallbackDefault {
				serverCancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			log.Printf("[POP3 Proxy %s] Continuing without prelookup due to fallback_to_default=true", options.Name)
		} else {
			routingLookup = prelookupClient
			log.Printf("[POP3 Proxy %s] Prelookup client initialized successfully", options.Name)
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRouting(
		options.RemoteAddrs,
		options.RemotePort,
		options.RemoteTLS,
		options.RemoteTLSVerify,
		options.RemoteUseProxyProtocol,
		options.ConnectTimeout,
		routingLookup,
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
		log.Printf("WARNING: Failed to resolve some addresses for POP3 proxy [%s]: %v", options.Name, err)
	}

	// Validate affinity stickiness
	stickiness := options.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid POP3 proxy [%s] affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", options.Name, stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("POP3-PROXY", options.AuthRateLimit, rdb, options.TrustedProxies)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if options.MaxConnections > 0 || options.MaxConnectionsPerIP > 0 {
		limiter = server.NewConnectionLimiterWithTrustedNets("POP3-PROXY", options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)
	}

	// Setup debug writer with password masking if debug is enabled
	var debugWriter io.Writer
	if options.Debug {
		debugWriter = &maskingWriter{w: os.Stdout}
	}

	server := &POP3ProxyServer{
		name:                   options.Name,
		hostname:               hostname,
		addr:                   addr,
		rdb:                    rdb,
		appCtx:                 serverCtx,
		cancel:                 serverCancel,
		masterSASLUsername:     options.MasterSASLUsername,
		masterSASLPassword:     options.MasterSASLPassword,
		connManager:            connManager,
		enableAffinity:         options.EnableAffinity,
		affinityValidity:       options.AffinityValidity,
		affinityStickiness:     stickiness,
		authLimiter:            authLimiter,
		trustedProxies:         options.TrustedProxies,
		prelookupConfig:        options.PreLookup,
		sessionTimeout:         options.SessionTimeout,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
		remoteUseXCLIENT:       options.RemoteUseXCLIENT,
		limiter:                limiter,
		debugWriter:            debugWriter,
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
		}

		if options.TLSVerify {
			log.Printf("Client TLS certificate verification is REQUIRED for POP3 proxy [%s] (tls_verify=true)", options.Name)
		} else {
			log.Printf("Client TLS certificate verification is DISABLED for POP3 proxy [%s] (tls_verify=false)", options.Name)
		}
		log.Printf("POP3 proxy [%s] using per-server TLS certificate", options.Name)
	} else if options.TLS && options.TLSConfig != nil {
		// Scenario 2: Global TLS manager
		server.tlsConfig = options.TLSConfig
		log.Printf("POP3 proxy [%s] using global TLS manager", options.Name)
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
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0,
	}

	if s.tlsConfig != nil {
		// Create base TCP listener
		tcpListener, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
		// Use SoraTLSListener for TLS with JA4 capture and timeout protection
		listener = server.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		log.Printf("POP3 proxy [%s] listening with TLS on %s (JA4 enabled, timeout protection: %v)",
			s.name, s.addr, connConfig.EnableTimeoutChecker)
	} else {
		// Create base TCP listener
		tcpListener, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to create listener: %w", err)
		}
		// Use SoraListener for non-TLS with timeout protection
		listener = server.NewSoraListener(tcpListener, connConfig)
		log.Printf("POP3 proxy [%s] listening on %s (timeout protection: %v)",
			s.name, s.addr, connConfig.EnableTimeoutChecker)
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
			// Check if this is a connection-specific error (non-fatal to the server)
			if server.IsConnectionError(err) {
				log.Printf("[POP3 Proxy %s] Connection error (non-fatal): %v", s.name, err)
				continue // Continue accepting other connections
			}
			// Otherwise, it's an unexpected error.
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.Accept(conn.RemoteAddr())
			if err != nil {
				log.Printf("[POP3 Proxy %s] Connection rejected: %v", s.name, err)
				conn.Close()
				continue // Try to accept the next connection
			}
		}

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &POP3ProxySession{
			server:     s,
			clientConn: conn,
			ctx:        sessionCtx,
			cancel:     sessionCancel,
		}

		session.RemoteIP = conn.RemoteAddr().String()
		log.Printf("POP3 proxy [%s] new connection from %s", s.name, session.RemoteIP)

		// Track proxy connection
		metrics.ConnectionsTotal.WithLabelValues("pop3_proxy").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy").Inc()

		s.wg.Add(1)
		go func() {
			defer func() {
				// Release connection limit when session ends
				if releaseConn != nil {
					releaseConn()
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[POP3 Proxy %s] Session panic recovered: %v", s.name, r)
					conn.Close()
				}
			}()
			session.handleConnection()
		}()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *POP3ProxyServer) SetConnectionTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

// GetConnectionManager returns the connection manager for health checks
func (s *POP3ProxyServer) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

func (s *POP3ProxyServer) Stop() error {
	log.Printf("POP3 Proxy [%s] stopping...", s.name)
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
		log.Printf("POP3 Proxy [%s] server stopped gracefully", s.name)
	case <-time.After(30 * time.Second):
		log.Printf("POP3 Proxy [%s] Server stop timeout", s.name)
	}

	// Close prelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			log.Printf("POP3 Proxy [%s] closing prelookup client...", s.name)
			if err := routingLookup.Close(); err != nil {
				log.Printf("POP3 Proxy [%s] error closing prelookup client: %v", s.name, err)
			}
		}
	}

	return nil
}
