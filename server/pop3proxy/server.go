package pop3proxy

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

type POP3ProxyServer struct {
	addr               string
	hostname           string
	db                 *db.Database
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
}

type POP3ProxyServerOptions struct {
	Debug              bool
	TLS                bool
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	RemoteAddrs        []string
	RemoteTLS          bool
	RemoteTLSVerify    bool
	MasterSASLUsername string
	MasterSASLPassword string
	ConnectTimeout     time.Duration
	EnableAffinity     bool
	AffinityValidity   time.Duration
	AffinityStickiness float64
	AuthRateLimit      server.AuthRateLimiterConfig
}

func New(appCtx context.Context, hostname, addr string, database *db.Database, options POP3ProxyServerOptions) (*POP3ProxyServer, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Create connection manager
	connManager, err := proxy.NewConnectionManager(
		options.RemoteAddrs,
		options.RemoteTLS,
		options.RemoteTLSVerify,
		options.ConnectTimeout,
	)
	if err != nil {
		serverCancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("WARNING: Failed to resolve some addresses for POP3 proxy: %v", err)
	}

	// Validate affinity stickiness
	stickiness := options.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid POP3 proxy affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", stickiness)
		stickiness = 1.0
	}

	// Initialize authentication rate limiter
	authLimiter := server.NewAuthRateLimiter("POP3-PROXY", options.AuthRateLimit, database)

	server := &POP3ProxyServer{
		hostname:           hostname,
		addr:               addr,
		db:                 database,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		masterSASLUsername: options.MasterSASLUsername,
		masterSASLPassword: options.MasterSASLPassword,
		connManager:        connManager,
		enableAffinity:     options.EnableAffinity,
		affinityValidity:   options.AffinityValidity,
		affinityStickiness: stickiness,
		authLimiter:        authLimiter,
	}

	// Setup TLS if enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
		}

		// Set InsecureSkipVerify if requested (for self-signed certificates)
		if !options.TLSVerify {
			server.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for POP3 proxy server")
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
		log.Printf("* POP3 proxy listening with TLS on %s", s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("* POP3 proxy listening on %s", s.addr)
	}
	defer listener.Close()

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

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &POP3ProxySession{
			server:     s,
			clientConn: conn,
			ctx:        sessionCtx,
			cancel:     sessionCancel,
		}

		session.RemoteIP = conn.RemoteAddr().String()
		log.Printf("* POP3 proxy new connection from %s", session.RemoteIP)

		// Track proxy connection
		metrics.ConnectionsTotal.WithLabelValues("pop3_proxy").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy").Inc()

		s.wg.Add(1)
		go session.handleConnection()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *POP3ProxyServer) SetConnectionTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

func (s *POP3ProxyServer) Stop() error {
	log.Printf("* POP3 proxy server closing")
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
