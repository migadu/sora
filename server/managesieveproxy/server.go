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
	listener           net.Listener
	rdb                *resilient.ResilientDatabase
	addr               string
	hostname           string
	masterSASLUsername []byte
	masterSASLPassword []byte
	tls                bool
	tlsCertFile        string
	tlsKeyFile         string
	tlsVerify          bool
	connManager        *proxy.ConnectionManager
	connTracker        *proxy.ConnectionTracker
	wg                 sync.WaitGroup
	ctx                context.Context
	cancel             context.CancelFunc
	enableAffinity     bool
	affinityValidity   time.Duration
	affinityStickiness float64
	authLimiter        server.AuthLimiter
	trustedProxies     []string // CIDR blocks for trusted proxies that can forward parameters
	remoteUseXCLIENT   bool     // Whether backend supports XCLIENT command for forwarding
}

// ServerOptions holds options for creating a new ManageSieve proxy server.
type ServerOptions struct {
	Addr                   string
	RemoteAddrs            []string
	MasterSASLUsername     string
	MasterSASLPassword     string
	TLS                    bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	ConnectTimeout         time.Duration
	EnableAffinity         bool
	AffinityValidity       time.Duration
	AffinityStickiness     float64
	AuthRateLimit          server.AuthRateLimiterConfig
	PreLookup              *proxy.PreLookupConfig
	TrustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT       bool     // Whether backend supports XCLIENT command for forwarding
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

	// Initialize prelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.PreLookup != nil && opts.PreLookup.Enabled {
		prelookupClient, err := proxy.NewPreLookupClient(ctx, opts.PreLookup)
		if err != nil {
			log.Printf("[ManageSieve Proxy] Failed to initialize prelookup client: %v", err)
			if !opts.PreLookup.FallbackDefault {
				cancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			log.Printf("[ManageSieve Proxy] Continuing without prelookup due to fallback_to_default=true")
		} else {
			routingLookup = prelookupClient
			log.Printf("[ManageSieve Proxy] Prelookup database client initialized successfully")
		}
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRouting(opts.RemoteAddrs, opts.RemoteTLS, opts.RemoteTLSVerify, opts.RemoteUseProxyProtocol, connectTimeout, routingLookup)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[ManageSieve Proxy] Failed to resolve addresses: %v", err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid ManageSieve proxy affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter
	authLimiter := server.NewAuthRateLimiter("SIEVE-PROXY", opts.AuthRateLimit, rdb)

	return &Server{
		rdb:                rdb,
		addr:               opts.Addr,
		hostname:           hostname,
		masterSASLUsername: []byte(opts.MasterSASLUsername),
		masterSASLPassword: []byte(opts.MasterSASLPassword),
		tls:                opts.TLS,
		tlsCertFile:        opts.TLSCertFile,
		tlsKeyFile:         opts.TLSKeyFile,
		tlsVerify:          opts.TLSVerify,
		connManager:        connManager,
		ctx:                ctx,
		cancel:             cancel,
		enableAffinity:     opts.EnableAffinity,
		affinityValidity:   opts.AffinityValidity,
		affinityStickiness: stickiness,
		authLimiter:        authLimiter,
		trustedProxies:     opts.TrustedProxies,
		remoteUseXCLIENT:   opts.RemoteUseXCLIENT,
	}, nil
}

// Start starts the ManageSieve proxy server.
func (s *Server) Start() error {
	var err error

	if s.tls {
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		s.listener, err = tls.Listen("tcp", s.addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
		log.Printf("* ManageSieve proxy listening with TLS on %s", s.addr)
	} else {
		s.listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		log.Printf("* ManageSieve proxy listening on %s", s.addr)
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

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[ManageSieve Proxy] Session panic recovered: %v", r)
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

// Stop stops the ManageSieve proxy server.
func (s *Server) Stop() error {
	log.Println("[ManageSieve Proxy] Stopping server...")

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
		log.Println("[ManageSieve Proxy] Server stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("[ManageSieve Proxy] Server stop timeout")
	}

	return nil
}
