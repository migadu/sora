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

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type POP3ProxyServer struct {
	name               string // Server name for logging
	addr               string
	hostname           string
	rdb                *resilient.ResilientDatabase
	appCtx             context.Context
	cancel             context.CancelFunc
	tlsConfig          *tls.Config
	masterSASLUsername string
	masterSASLPassword string
	connManager        *proxy.ConnectionManager
	connTracker        *proxy.ConnectionTracker
	wg                 sync.WaitGroup
	enableAffinity     bool
	affinityValidity   time.Duration
	affinityStickiness float64
	authLimiter        server.AuthLimiter
	trustedProxies     []string // CIDR blocks for trusted proxies that can forward parameters
	prelookupConfig    *proxy.PreLookupConfig
	sessionTimeout     time.Duration
	remoteUseXCLIENT   bool // Whether backend supports XCLIENT command for forwarding

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
	RemoteAddrs            []string
	RemotePort             int // Default port for backends if not in address
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	MasterSASLUsername     string
	MasterSASLPassword     string
	ConnectTimeout         time.Duration
	SessionTimeout         time.Duration
	EnableAffinity         bool
	AffinityValidity       time.Duration
	AffinityStickiness     float64
	AuthRateLimit          server.AuthRateLimiterConfig
	PreLookup              *proxy.PreLookupConfig
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
		options.PreLookup = &proxy.PreLookupConfig{}
	}

	// Initialize prelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if options.PreLookup != nil && options.PreLookup.Enabled {
		prelookupClient, err := proxy.NewPreLookupClient(serverCtx, options.PreLookup)
		if err != nil {
			log.Printf("[POP3 Proxy %s] Failed to initialize prelookup client: %v", options.Name, err)
			if !options.PreLookup.FallbackDefault {
				serverCancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			log.Printf("[POP3 Proxy %s] Continuing without prelookup due to fallback_to_default=true", options.Name)
		} else {
			routingLookup = prelookupClient
			log.Printf("[POP3 Proxy %s] Prelookup database client initialized successfully", options.Name)
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
		name:               options.Name,
		hostname:           hostname,
		addr:               addr,
		rdb:                rdb,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		masterSASLUsername: options.MasterSASLUsername,
		masterSASLPassword: options.MasterSASLPassword,
		connManager:        connManager,
		enableAffinity:     options.EnableAffinity,
		affinityValidity:   options.AffinityValidity,
		affinityStickiness: stickiness,
		authLimiter:        authLimiter,
		trustedProxies:     options.TrustedProxies,
		prelookupConfig:    options.PreLookup,
		sessionTimeout:     options.SessionTimeout,
		remoteUseXCLIENT:   options.RemoteUseXCLIENT,
		limiter:            limiter,
		debugWriter:        debugWriter,
	}

	// Setup TLS if enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
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
		}

		if options.TLSVerify {
			log.Printf("Client TLS certificate verification is REQUIRED for POP3 proxy [%s] (tls_verify=true)", options.Name)
		} else {
			log.Printf("Client TLS certificate verification is DISABLED for POP3 proxy [%s] (tls_verify=false)", options.Name)
		}
	}

	return server, nil
}

func (s *POP3ProxyServer) Start() error {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to create TLS listener: %w", err)
		}
		log.Printf("* POP3 proxy [%s] listening with TLS on %s", s.name, s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("* POP3 proxy [%s] listening on %s", s.name, s.addr)
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

	for {
		conn, err := listener.Accept()
		if err != nil {
			// If context is cancelled, listener.Close() was called, so this is a graceful shutdown.
			if s.appCtx.Err() != nil {
				return nil
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
		log.Printf("* POP3 proxy [%s] new connection from %s", s.name, session.RemoteIP)

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

func (s *POP3ProxyServer) Stop() error {
	log.Printf("* POP3 proxy [%s] server closing", s.name)
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
		log.Println("[POP3 Proxy] Server stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("[POP3 Proxy] Server stop timeout")
	}

	return nil
}
