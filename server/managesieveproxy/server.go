package managesieveproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/proxy"
)

// Server represents a ManageSieve proxy server.
type Server struct {
	listener           net.Listener
	db                 *db.Database
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
}

// ServerOptions holds options for creating a new ManageSieve proxy server.
type ServerOptions struct {
	Addr               string
	RemoteAddr         string // Deprecated: use RemoteAddrs
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
}

// New creates a new ManageSieve proxy server.
func New(appCtx context.Context, db *db.Database, hostname string, opts ServerOptions) (*Server, error) {
	ctx, cancel := context.WithCancel(appCtx)

	// Handle backward compatibility
	remoteAddrs := opts.RemoteAddrs
	if len(remoteAddrs) == 0 && opts.RemoteAddr != "" {
		remoteAddrs = []string{opts.RemoteAddr}
	}

	if len(remoteAddrs) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses configured")
	}

	// Set default timeout if not specified
	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Create connection manager
	connManager, err := proxy.NewConnectionManager(remoteAddrs, opts.RemoteTLS, opts.RemoteTLSVerify, connectTimeout)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[ManageSieve Proxy] Failed to resolve addresses: %v", err)
	}

	return &Server{
		db:                 db,
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
