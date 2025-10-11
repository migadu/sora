package managesieveproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// Server represents a ManageSieve proxy server.
type Server struct {
	listener               net.Listener
	rdb                    *resilient.ResilientDatabase
	name                   string // Server name for logging
	addr                   string
	hostname               string
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	tls                    bool
	tlsUseStartTLS         bool
	tlsCertFile            string
	tlsKeyFile             string
	tlsVerify              bool
	connManager            *proxy.ConnectionManager
	connTracker            *proxy.ConnectionTracker
	wg                     sync.WaitGroup
	ctx                    context.Context
	cancel                 context.CancelFunc
	enableAffinity         bool
	affinityValidity       time.Duration
	affinityStickiness     float64
	authLimiter            server.AuthLimiter
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	prelookupConfig        *proxy.PreLookupConfig
	sessionTimeout         time.Duration
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Debug logging
	debug bool
}

// ServerOptions holds options for creating a new ManageSieve proxy server.
type ServerOptions struct {
	Name                   string // Server name for logging
	Addr                   string
	RemoteAddrs            []string
	RemotePort             int // Default port for backends if not in address
	MasterSASLUsername     string
	MasterSASLPassword     string
	TLS                    bool
	TLSUseStartTLS         bool // Use STARTTLS on listening port
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	RemoteTLS              bool
	RemoteTLSUseStartTLS   bool // Use STARTTLS for backend connections
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	ConnectTimeout         time.Duration
	SessionTimeout         time.Duration
	CommandTimeout         time.Duration // Idle timeout
	AbsoluteSessionTimeout time.Duration // Maximum total session duration
	MinBytesPerMinute      int64         // Minimum throughput
	EnableAffinity         bool
	AffinityValidity       time.Duration
	AffinityStickiness     float64
	AuthRateLimit          server.AuthRateLimiterConfig
	PreLookup              *proxy.PreLookupConfig
	TrustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters

	// Connection limiting
	MaxConnections      int      // Maximum total connections (0 = unlimited)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits

	// Debug logging
	Debug bool // Enable debug logging
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

	// Ensure PreLookup config has a default value to avoid nil panics.
	if opts.PreLookup == nil {
		opts.PreLookup = &proxy.PreLookupConfig{}
	}

	// Initialize prelookup client if configured
	routingLookup, err := proxy.InitializePrelookup(ctx, opts.PreLookup, "ManageSieve")
	if err != nil {
		cancel()
		return nil, err // InitializePrelookup handles fallback logic and returns error only when fatal
	}
	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLS(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSUseStartTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[ManageSieve Proxy %s] Failed to resolve addresses: %v", opts.Name, err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid ManageSieve proxy [%s] affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", opts.Name, stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("SIEVE-PROXY", opts.AuthRateLimit, rdb, opts.TrustedProxies)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		limiter = server.NewConnectionLimiterWithTrustedNets("SIEVE-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
	}

	return &Server{
		rdb:                    rdb,
		name:                   opts.Name,
		addr:                   opts.Addr,
		hostname:               hostname,
		masterSASLUsername:     []byte(opts.MasterSASLUsername),
		masterSASLPassword:     []byte(opts.MasterSASLPassword),
		tls:                    opts.TLS,
		tlsUseStartTLS:         opts.TLSUseStartTLS,
		tlsCertFile:            opts.TLSCertFile,
		tlsKeyFile:             opts.TLSKeyFile,
		tlsVerify:              opts.TLSVerify,
		connManager:            connManager,
		ctx:                    ctx,
		cancel:                 cancel,
		enableAffinity:         opts.EnableAffinity,
		affinityValidity:       opts.AffinityValidity,
		affinityStickiness:     stickiness,
		authLimiter:            authLimiter,
		trustedProxies:         opts.TrustedProxies,
		prelookupConfig:        opts.PreLookup,
		sessionTimeout:         opts.SessionTimeout,
		commandTimeout:         opts.CommandTimeout,
		absoluteSessionTimeout: opts.AbsoluteSessionTimeout,
		minBytesPerMinute:      opts.MinBytesPerMinute,
		limiter:                limiter,
		debug:                  opts.Debug,
	}, nil
}

// Start starts the ManageSieve proxy server.
func (s *Server) Start() error {
	var err error

	// Only use implicit TLS listener if TLS is enabled AND StartTLS is not being used
	if s.tls && !s.tlsUseStartTLS {
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
		}

		if s.tlsVerify {
			log.Printf("Client TLS certificate verification is REQUIRED for ManageSieve proxy [%s] (tls_verify=true)", s.name)
		} else {
			log.Printf("Client TLS certificate verification is DISABLED for ManageSieve proxy [%s] (tls_verify=false)", s.name)
		}

		s.listener, err = tls.Listen("tcp", s.addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
		log.Printf("* ManageSieve proxy [%s] listening with implicit TLS on %s", s.name, s.addr)
	} else {
		s.listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		if s.tlsUseStartTLS {
			log.Printf("* ManageSieve proxy [%s] listening on %s (STARTTLS enabled)", s.name, s.addr)
		} else {
			log.Printf("* ManageSieve proxy [%s] listening on %s", s.name, s.addr)
		}
	}

	// Wrap listener with timeout protection
	if s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0 {
		s.listener = &timeoutListener{
			Listener:          s.listener,
			timeout:           s.commandTimeout,
			absoluteTimeout:   s.absoluteSessionTimeout,
			minBytesPerMinute: s.minBytesPerMinute,
			protocol:          "managesieve_proxy",
		}
		log.Printf("* ManageSieve proxy [%s] timeout protection enabled - idle: %v, session_max: %v, throughput: %d bytes/min",
			s.name, s.commandTimeout, s.absoluteSessionTimeout, s.minBytesPerMinute)
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
				return fmt.Errorf("failed to accept connection: %w", err)
			}
		}

		// Check connection limits before processing
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.Accept(conn.RemoteAddr())
			if err != nil {
				log.Printf("[ManageSieve Proxy %s] Connection rejected: %v", s.name, err)
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
					log.Printf("[ManageSieve Proxy %s] Session panic recovered: %v", s.name, r)
					conn.Close()
				}
			}()

			// Track proxy connection
			metrics.ConnectionsTotal.WithLabelValues("managesieve_proxy").Inc()
			metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Inc()

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

// Stop stops the ManageSieve proxy server.
func (s *Server) Stop() error {
	log.Printf("* ManageSieve Proxy [%s] stopping...", s.name)

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("* ManageSieve Proxy [%s] server stopped gracefully", s.name)
	case <-time.After(30 * time.Second):
		log.Printf("ManageSieve Proxy [%s] Server stop timeout", s.name)
	}

	// Close prelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			log.Printf("* ManageSieve Proxy [%s] closing prelookup client...", s.name)
			if err := routingLookup.Close(); err != nil {
				log.Printf("* ManageSieve Proxy [%s] error closing prelookup client: %v", s.name, err)
			}
		}
	}

	return nil
}
