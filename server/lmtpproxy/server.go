package lmtpproxy

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

// Server represents an LMTP proxy server.
type Server struct {
	listener           net.Listener
	rdb                *resilient.ResilientDatabase
	name               string // Server name for logging
	addr               string
	hostname           string
	connManager        *proxy.ConnectionManager
	connTracker        *proxy.ConnectionTracker
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
	trustedProxies     []string // CIDR blocks for trusted proxies that can forward parameters
	prelookupConfig    *proxy.PreLookupConfig
	remoteUseXCLIENT   bool // Whether backend supports XCLIENT command for forwarding
	sessionTimeout     time.Duration
	maxMessageSize     int64

	// Trusted networks for connection filtering
	trustedNetworks []*net.IPNet

	// Connection limiting (total connections only, no per-IP for LMTP)
	limiter *server.ConnectionLimiter
}

// ServerOptions holds options for creating a new LMTP proxy server.
type ServerOptions struct {
	Name                   string // Server name for logging
	Addr                   string
	RemoteAddrs            []string
	RemotePort             int // Default port for backends if not in address
	TLS                    bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSVerify              bool
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	ConnectTimeout         time.Duration
	SessionTimeout         time.Duration
	EnableAffinity         bool
	AffinityValidity       time.Duration
	AffinityStickiness     float64
	PreLookup              *proxy.PreLookupConfig
	TrustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT       bool     // Whether backend supports XCLIENT command for forwarding
	MaxMessageSize         int64

	// Connection limiting (total connections only, no per-IP for LMTP)
	MaxConnections int // Maximum total connections (0 = unlimited)
}

// New creates a new LMTP proxy server.
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
	var routingLookup proxy.UserRoutingLookup
	if opts.PreLookup.Enabled {
		prelookupClient, err := proxy.NewPreLookupClient(ctx, opts.PreLookup)
		if err != nil {
			log.Printf("[LMTP Proxy %s] Failed to initialize prelookup client: %v", opts.Name, err)
			if !opts.PreLookup.FallbackDefault {
				cancel()
				return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
			}
			log.Printf("[LMTP Proxy %s] Continuing without prelookup due to fallback_to_default=true", opts.Name)
		} else {
			routingLookup = prelookupClient
			log.Printf("[LMTP Proxy %s] Prelookup database client initialized successfully", opts.Name)
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
		log.Printf("[LMTP Proxy %s] Failed to resolve addresses: %v", opts.Name, err)
	}

	// Validate affinity stickiness
	stickiness := opts.AffinityStickiness
	if stickiness < 0.0 || stickiness > 1.0 {
		log.Printf("WARNING: invalid LMTP proxy [%s] affinity_stickiness '%.2f': value must be between 0.0 and 1.0. Using default of 1.0.", opts.Name, stickiness)
		stickiness = 1.0
	}

	// Parse trusted networks for connection filtering
	trustedNets, err := server.ParseTrustedNetworks(opts.TrustedProxies)
	if err != nil {
		// Log the error and use empty trusted networks to prevent server crash
		log.Printf("WARNING: failed to parse trusted networks for LMTP proxy (%v), using empty trusted networks (proxy connections will be restricted)", err)
		trustedNets = []*net.IPNet{}
	}

	// Initialize connection limiter for total connections only (no per-IP for LMTP)
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 {
		// For LMTP proxy: total connections only, no per-IP limiting, no trusted networks bypass
		limiter = server.NewConnectionLimiterWithTrustedNets("LMTP-PROXY", opts.MaxConnections, 0, []string{})
	}

	return &Server{
		rdb:                rdb,
		name:               opts.Name,
		addr:               opts.Addr,
		hostname:           hostname,
		connManager:        connManager,
		tls:                opts.TLS,
		tlsCertFile:        opts.TLSCertFile,
		tlsKeyFile:         opts.TLSKeyFile,
		tlsVerify:          opts.TLSVerify,
		enableAffinity:     opts.EnableAffinity,
		affinityValidity:   opts.AffinityValidity,
		affinityStickiness: stickiness,
		ctx:                ctx,
		cancel:             cancel,
		trustedProxies:     opts.TrustedProxies,
		prelookupConfig:    opts.PreLookup,
		remoteUseXCLIENT:   opts.RemoteUseXCLIENT,
		sessionTimeout:     opts.SessionTimeout,
		maxMessageSize:     opts.MaxMessageSize,
		trustedNetworks:    trustedNets,
		limiter:            limiter,
	}, nil
}

// Start starts the LMTP proxy server.
func (s *Server) Start() error {
	var err error

	if s.tls {
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
			log.Printf("Client TLS certificate verification is REQUIRED for LMTP proxy [%s] (tls_verify=true)", s.name)
		} else {
			log.Printf("Client TLS certificate verification is DISABLED for LMTP proxy [%s] (tls_verify=false)", s.name)
		}

		s.listener, err = tls.Listen("tcp", s.addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
		log.Printf("* LMTP proxy [%s] listening with TLS on %s", s.name, s.addr)
	} else {
		s.listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		log.Printf("* LMTP proxy [%s] listening on %s", s.name, s.addr)
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	return s.acceptConnections()
}

// isFromTrustedNetwork checks if an IP address is from a trusted network
func (s *Server) isFromTrustedNetwork(ip net.IP) bool {
	for _, network := range s.trustedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
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

		// Check if connection is from a trusted network
		remoteAddr := conn.RemoteAddr()
		var ip net.IP
		switch addr := remoteAddr.(type) {
		case *net.TCPAddr:
			ip = addr.IP
		case *net.UDPAddr:
			ip = addr.IP
		default:
			// Try to parse as string
			host, _, err := net.SplitHostPort(remoteAddr.String())
			if err != nil {
				log.Printf("[LMTP Proxy %s] Connection rejected from %s: invalid address format", s.name, remoteAddr)
				conn.Close()
				continue
			}
			ip = net.ParseIP(host)
			if ip == nil {
				log.Printf("[LMTP Proxy %s] Connection rejected from %s: could not parse IP", s.name, remoteAddr)
				conn.Close()
				continue
			}
		}

		if !s.isFromTrustedNetwork(ip) {
			log.Printf("[LMTP Proxy %s] Connection rejected from %s: not from trusted network", s.name, ip)
			conn.Close()
			continue
		}

		// Check total connection limits after trusted network verification
		var releaseConn func()
		if s.limiter != nil {
			releaseConn, err = s.limiter.Accept(conn.RemoteAddr())
			if err != nil {
				log.Printf("[LMTP Proxy %s] Connection rejected from %s: %v", s.name, ip, err)
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
					log.Printf("[LMTP Proxy %s] Session panic recovered: %v", s.name, r)
					conn.Close()
				}
			}()

			// Track proxy connection
			metrics.ConnectionsTotal.WithLabelValues("lmtp_proxy").Inc()
			metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy").Inc()

			session := newSession(s, conn)
			session.handleConnection()
		}()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *Server) SetConnectionTracker(tracker *proxy.ConnectionTracker) {
	s.connTracker = tracker
}

// Stop stops the LMTP proxy server.
func (s *Server) Stop() error {
	log.Println("* LMTP proxy stopping...")

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
		log.Println("* LMTP proxy stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("[LMTP Proxy] stop timeout")
	}

	return nil
}
