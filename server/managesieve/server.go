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
	addr               string
	hostname           string
	rdb                *resilient.ResilientDatabase
	appCtx             context.Context
	cancel             context.CancelFunc
	tlsConfig          *tls.Config
	useStartTLS        bool
	insecureAuth       bool
	maxScriptSize      int64
	masterSASLUsername []byte
	masterSASLPassword []byte

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
	InsecureAuth        bool
	Debug               bool
	TLS                 bool
	TLSCertFile         string
	TLSKeyFile          string
	TLSVerify           bool
	TLSUseStartTLS      bool
	MaxScriptSize       int64
	MasterSASLUsername  string
	MasterSASLPassword  string
	MaxConnections      int
	MaxConnectionsPerIP int
	ProxyProtocol       server.ProxyProtocolConfig
	AuthRateLimit       server.AuthRateLimiterConfig
}

func New(appCtx context.Context, hostname, addr string, rdb *resilient.ResilientDatabase, options ManageSieveServerOptions) (*ManageSieveServer, error) {
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol.Enabled {
		var err error
		proxyReader, err = server.NewProxyProtocolReader("ManageSieve", options.ProxyProtocol)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize authentication rate limiter
	authLimiter := server.NewAuthRateLimiter("ManageSieve", options.AuthRateLimit, rdb)

	serverInstance := &ManageSieveServer{
		hostname:           hostname,
		addr:               addr,
		rdb:                rdb,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		useStartTLS:        options.TLSUseStartTLS,
		insecureAuth:       options.InsecureAuth,
		maxScriptSize:      options.MaxScriptSize,
		masterSASLUsername: []byte(options.MasterSASLUsername),
		masterSASLPassword: []byte(options.MasterSASLPassword),
		limiter:            server.NewConnectionLimiter("ManageSieve", options.MaxConnections, options.MaxConnectionsPerIP),
		proxyReader:        proxyReader,
		authLimiter:        authLimiter,
	}

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
			log.Printf("WARNING: TLS certificate verification disabled for ManageSieve server")
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
		log.Printf("* ManageSieve listening with implicit TLS on %s", s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* ManageSieve listening on %s", s.addr)
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
		log.Printf("* ManageSieve server shutting down due to context cancellation")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed
			if s.appCtx.Err() != nil {
				log.Printf("* ManageSieve server closed: %v", s.appCtx.Err())
				return
			}

			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if errors.Is(err, errProxyProtocol) {
				log.Printf("[ManageSieve] %v, rejecting connection", err)
				continue // Continue accepting other connections
			}

			// For other errors, this might be a fatal server error
			errChan <- err
			return
		}

		// Check connection limits
		releaseConn, err := s.limiter.Accept(conn.RemoteAddr())
		if err != nil {
			log.Printf("[ManageSieve] Connection rejected: %v", err)
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
		log.Printf("* ManageSieve new connection from %s (connections: total=%d, authenticated=%d)",
			remoteInfo, totalCount, authCount)

		go session.handleConnection()
	}
}

func (s *ManageSieveServer) Close() {
	log.Printf("* ManageSieve server closing")
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
		if err != nil {
			conn.Close()
			// Log the error but continue accepting new connections - don't crash the entire server
			log.Printf("[ManageSieve] PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
			// Continue the loop to accept the next connection instead of returning an error
			continue
		}

		// Wrap the connection with proxy info for later extraction
		return &proxyProtocolConn{
			Conn:      wrappedConn,
			proxyInfo: proxyInfo,
		}, nil
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
