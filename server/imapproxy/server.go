package imapproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// Server represents an IMAP proxy server.
type Server struct {
	listener           net.Listener
	db                 *db.Database
	addr               string
	hostname           string
	connManager        *proxy.ConnectionManager
	connTracker        *proxy.ConnectionTracker
	masterSASLUsername []byte
	masterSASLPassword []byte
	tls                bool
	tlsCertFile        string
	tlsKeyFile         string
	tlsVerify          bool
	enableAffinity     bool
	affinityValidity   time.Duration
	affinityStickiness float64
	wg                 sync.WaitGroup
	ctx                context.Context
	cancel             context.CancelFunc
	authLimiter        server.AuthLimiter
}

// ServerOptions holds options for creating a new IMAP proxy server.
type ServerOptions struct {
	Addr               string
	RemoteAddrs        []string
	MasterSASLUsername string
	MasterSASLPassword string
	TLS                bool
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	RemoteTLS          bool
	RemoteTLSVerify    bool
	ConnectTimeout     time.Duration
	EnableAffinity     bool
	AffinityValidity   time.Duration
	AffinityStickiness float64
	AuthRateLimit      server.AuthRateLimiterConfig
}

// New creates a new IMAP proxy server.
func New(appCtx context.Context, db *db.Database, hostname string, opts ServerOptions) (*Server, error) {
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

	// Create connection manager
	connManager, err := proxy.NewConnectionManager(opts.RemoteAddrs, opts.RemoteTLS, opts.RemoteTLSVerify, connectTimeout)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[IMAP Proxy] Failed to resolve addresses: %v", err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid IMAP proxy affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter
	authLimiter := server.NewAuthRateLimiter("IMAP-PROXY", opts.AuthRateLimit, db)

	return &Server{
		db:                 db,
		addr:               opts.Addr,
		hostname:           hostname,
		connManager:        connManager,
		masterSASLUsername: []byte(opts.MasterSASLUsername),
		masterSASLPassword: []byte(opts.MasterSASLPassword),
		tls:                opts.TLS,
		tlsCertFile:        opts.TLSCertFile,
		tlsKeyFile:         opts.TLSKeyFile,
		tlsVerify:          opts.TLSVerify,
		enableAffinity:     opts.EnableAffinity,
		affinityValidity:   opts.AffinityValidity,
		affinityStickiness: stickiness,
		ctx:                ctx,
		cancel:             cancel,
		authLimiter:        authLimiter,
	}, nil
}

// Start starts the IMAP proxy server.
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
		log.Printf("* IMAP proxy listening with TLS on %s", s.addr)
	} else {
		s.listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		log.Printf("* IMAP proxy listening on %s", s.addr)
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

// Stop stops the IMAP proxy server.
func (s *Server) Stop() error {
	log.Println("* IMAP proxy stopping...")

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
		log.Println("* IMAP proxy stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("[IMAP Proxy] Server stop timeout")
	}

	return nil
}
