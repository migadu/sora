package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
)

const DefaultMaxScriptSize = 16 * 1024 // 16 KB

type ManageSieveServer struct {
	addr                string
	name                string
	hostname            string
	rdb                 *resilient.ResilientDatabase
	appCtx              context.Context
	cancel              context.CancelFunc
	tlsConfig           *tls.Config
	useStartTLS         bool
	insecureAuth        bool
	maxScriptSize       int64
	supportedExtensions []string // List of supported Sieve extensions
	masterSASLUsername  []byte
	masterSASLPassword  []byte

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection limiting
	limiter *server.ConnectionLimiter

	// PROXY protocol support
	proxyReader *server.ProxyProtocolReader

	// Authentication rate limiting
	authLimiter server.AuthLimiter
}

type ManageSieveServerOptions struct {
	InsecureAuth         bool
	Debug                bool
	TLS                  bool
	TLSCertFile          string
	TLSKeyFile           string
	TLSVerify            bool
	TLSUseStartTLS       bool
	MaxScriptSize        int64
	SupportedExtensions  []string // List of supported Sieve extensions
	MasterSASLUsername   string
	MasterSASLPassword   string
	MaxConnections       int
	MaxConnectionsPerIP  int
	ProxyProtocol        bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout string   // Timeout for reading PROXY headers
	TrustedNetworks      []string // Global trusted networks for parameter forwarding
	AuthRateLimit        server.AuthRateLimiterConfig
}

func New(appCtx context.Context, name, hostname, addr string, rdb *resilient.ResilientDatabase, options ManageSieveServerOptions) (*ManageSieveServer, error) {
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		// Create ProxyProtocolConfig from simplified settings
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Mode:           "required",
			TrustedProxies: options.TrustedNetworks,
			Timeout:        options.ProxyProtocolTimeout,
		}

		// Proxy protocol is always required when enabled

		var err error
		proxyReader, err = server.NewProxyProtocolReader("ManageSieve", proxyConfig)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("ManageSieve", options.AuthRateLimit, rdb, options.TrustedNetworks)

	serverInstance := &ManageSieveServer{
		hostname:            hostname,
		name:                name,
		addr:                addr,
		rdb:                 rdb,
		appCtx:              serverCtx,
		cancel:              serverCancel,
		useStartTLS:         options.TLSUseStartTLS,
		insecureAuth:        options.InsecureAuth,
		maxScriptSize:       options.MaxScriptSize,
		supportedExtensions: options.SupportedExtensions,
		masterSASLUsername:  []byte(options.MasterSASLUsername),
		masterSASLPassword:  []byte(options.MasterSASLPassword),
		proxyReader:         proxyReader,
		authLimiter:         authLimiter,
	}

	// No default extensions - only use what's explicitly configured

	// Create connection limiter with trusted networks from server configuration
	// For ManageSieve backend:
	// - If PROXY protocol is enabled: only connections from trusted networks allowed, no per-IP limiting
	// - If PROXY protocol is disabled: trusted networks bypass per-IP limits, others are limited per-IP
	var limiterTrustedNets []string
	var limiterMaxPerIP int

	if options.ProxyProtocol {
		// PROXY protocol enabled: use trusted networks, disable per-IP limiting
		limiterTrustedNets = options.TrustedNetworks
		limiterMaxPerIP = 0 // No per-IP limiting when PROXY protocol is enabled
	} else {
		// PROXY protocol disabled: use trusted networks for per-IP bypass
		limiterTrustedNets = options.TrustedNetworks
		limiterMaxPerIP = options.MaxConnectionsPerIP
	}

	serverInstance.limiter = server.NewConnectionLimiterWithTrustedNets("ManageSieve", options.MaxConnections, limiterMaxPerIP, limiterTrustedNets)

	// Set up TLS config if TLS is enabled and certificates are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		serverInstance.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
		}

		if !options.TLSVerify {
			serverInstance.tlsConfig.InsecureSkipVerify = true
			log.Printf("ManageSieve [%s] WARNING: TLS certificate verification disabled", name)
		}
	}

	// Start connection limiter cleanup
	serverInstance.limiter.StartCleanup(serverCtx)

	return serverInstance, nil
}

func (s *ManageSieveServer) Start(errChan chan error) {
	var listener net.Listener
	var err error

	isImplicitTLS := s.tlsConfig != nil && !s.useStartTLS
	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if isImplicitTLS {
		// Implicit TLS - use TLS listener
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* ManageSieve [%s] listening with implicit TLS on %s", s.name, s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* ManageSieve [%s] listening on %s", s.name, s.addr)
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if s.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: s.proxyReader,
		}
	}

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		log.Printf("* ManageSieve [%s] stopping", s.name)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if errors.Is(err, errProxyProtocol) {
				log.Printf("ManageSieve [%s] %v, rejecting connection", s.name, err)
				continue // Continue accepting other connections
			}

			// Check if the error is due to the listener being closed (graceful shutdown)
			select {
			case <-s.appCtx.Done():
				log.Printf("* ManageSieve [%s] server stopped gracefully", s.name)
				return
			default:
				// For other errors, this might be a fatal server error
				errChan <- err
				return
			}
		}

		// Extract real client IP and proxy IP from PROXY protocol if available for connection limiting
		var proxyInfoForLimiting *server.ProxyProtocolInfo
		var realClientIP string
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfoForLimiting = proxyConn.GetProxyInfo()
			if proxyInfoForLimiting != nil && proxyInfoForLimiting.SrcIP != "" {
				realClientIP = proxyInfoForLimiting.SrcIP
			}
		}

		// Check connection limits with PROXY protocol support
		releaseConn, err := s.limiter.AcceptWithRealIP(conn.RemoteAddr(), realClientIP)
		if err != nil {
			log.Printf("ManageSieve [%s] Connection rejected: %v", s.name, err)
			conn.Close()
			continue
		}

		// Increment total connections counter
		totalCount := s.totalConnections.Add(1)

		// Prometheus metrics - connection established
		metrics.ConnectionsTotal.WithLabelValues("managesieve").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("managesieve").Inc()
		authCount := s.authenticatedConnections.Load()

		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &ManageSieveSession{
			server:      s,
			conn:        &conn,
			reader:      bufio.NewReader(conn),
			writer:      bufio.NewWriter(conn),
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			isTLS:       isImplicitTLS, // Initialize isTLS based on the listener type
			releaseConn: releaseConn,
			startTime:   time.Now(),
		}

		// Extract real client IP and proxy IP from PROXY protocol if available
		var proxyInfo *server.ProxyProtocolInfo
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfo = proxyConn.GetProxyInfo()
		}

		clientIP, proxyIP := server.GetConnectionIPs(conn, proxyInfo)
		session.RemoteIP = clientIP
		session.ProxyIP = proxyIP
		session.Protocol = "ManageSieve"
		session.ServerName = s.name
		session.Id = idgen.New()
		session.HostName = session.server.hostname
		session.Stats = s // Set the server as the Stats provider

		// Create logging function for the mutex helper
		logFunc := func(format string, args ...interface{}) {
			session.Log(format, args...)
		}

		// Initialize the mutex helper
		session.mutexHelper = server.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "MANAGESIEVE", logFunc)

		// Build connection info for logging
		var remoteInfo string
		if session.ProxyIP != "" {
			remoteInfo = fmt.Sprintf("%s proxy=%s", session.RemoteIP, session.ProxyIP)
		} else {
			remoteInfo = session.RemoteIP
		}
		// Log connection with connection counters
		log.Printf("* ManageSieve [%s] new connection from %s (connections: total=%d, authenticated=%d)",
			s.name, remoteInfo, totalCount, authCount)

		go session.handleConnection()
	}
}

func (s *ManageSieveServer) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// GetTotalConnections returns the current total connection count
func (s *ManageSieveServer) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *ManageSieveServer) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}

var errProxyProtocol = errors.New("PROXY protocol error")

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *server.ProxyProtocolReader
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Try to read PROXY protocol header
		proxyInfo, wrappedConn, err := l.proxyReader.ReadProxyHeader(conn)
		if err == nil {
			// PROXY header found and parsed successfully.
			return &proxyProtocolConn{
				Conn:      wrappedConn,
				proxyInfo: proxyInfo,
			}, nil
		}

		// An error occurred. Check if we are in "optional" mode and the error is simply that no PROXY header was present.
		// This requires the underlying ProxyProtocolReader to be updated to return a specific error (e.g., server.ErrNoProxyHeader)
		// and to not consume bytes from the connection if no header is found.
		if l.proxyReader.IsOptionalMode() && errors.Is(err, server.ErrNoProxyHeader) {
			// Note: We don't have access to server name in this listener, use generic ManageSieve
			log.Printf("ManageSieve No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic ManageSieve
		log.Printf("ManageSieve PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
		continue
	}
}

// proxyProtocolConn wraps a connection with PROXY protocol information
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *server.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *server.ProxyProtocolInfo {
	return c.proxyInfo
}
