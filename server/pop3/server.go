package pop3

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type POP3Server struct {
	addr               string
	hostname           string
	db                 *db.Database
	s3                 *storage.S3Storage
	appCtx             context.Context
	cancel             context.CancelFunc // Cancel function for the app context
	uploader           *uploader.UploadWorker
	cache              *cache.Cache
	tlsConfig          *tls.Config
	masterSASLUsername []byte
	masterSASLPassword []byte

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64
	
	// Connection limiting
	limiter *serverPkg.ConnectionLimiter
	
	// PROXY protocol support
	proxyReader *serverPkg.ProxyProtocolReader
	
	// Authentication rate limiting
	authLimiter serverPkg.AuthLimiter
}

type POP3ServerOptions struct {
	Debug              bool
	TLS                bool
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	MasterSASLUsername string
	MasterSASLPassword string
	MaxConnections     int
	MaxConnectionsPerIP int
	ProxyProtocol      serverPkg.ProxyProtocolConfig
	AuthRateLimit      serverPkg.AuthRateLimiterConfig
}

func New(appCtx context.Context, hostname, popAddr string, storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options POP3ServerOptions) (*POP3Server, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Initialize PROXY protocol reader if enabled
	var proxyReader *serverPkg.ProxyProtocolReader
	if options.ProxyProtocol.Enabled {
		var err error
		proxyReader, err = serverPkg.NewProxyProtocolReader("POP3", options.ProxyProtocol)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize enhanced authentication rate limiter
	authLimiter := serverPkg.NewEnhancedAuthRateLimiterFromBasic("POP3", options.AuthRateLimit, database)

	server := &POP3Server{
		hostname:           hostname,
		addr:               popAddr,
		db:                 database,
		s3:                 storage,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		uploader:           uploadWorker,
		cache:              cache,
		masterSASLUsername: []byte(options.MasterSASLUsername),
		masterSASLPassword: []byte(options.MasterSASLPassword),
		limiter:            serverPkg.NewConnectionLimiter("POP3", options.MaxConnections, options.MaxConnectionsPerIP),
		proxyReader:        proxyReader,
		authLimiter:        authLimiter,
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
		}

		// Set InsecureSkipVerify if requested (for self-signed certificates)
		if !options.TLSVerify {
			server.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for POP3 server")
		}
	}

	// Start connection limiter cleanup
	server.limiter.StartCleanup(serverCtx)

	return server, nil
}

func (s *POP3Server) Start(errChan chan error) {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			s.cancel()
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* POP3 listening with TLS on %s", s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* POP3 listening on %s", s.addr)
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
		log.Printf("* POP3 server shutting down due to context cancellation")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed
			if s.appCtx.Err() != nil {
				log.Printf("* POP3 server closed: %v", s.appCtx.Err())
				return
			}
			
			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if strings.Contains(err.Error(), "PROXY protocol error") {
				log.Printf("[POP3] PROXY protocol error, rejecting connection: %v", err)
				continue // Continue accepting other connections
			}
			
			// For other errors, this might be a fatal server error
			errChan <- err
			return
		}

		// Check connection limits
		releaseConn, err := s.limiter.Accept(conn.RemoteAddr())
		if err != nil {
			log.Printf("[POP3] Connection rejected: %v", err)
			conn.Close()
			continue
		}

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		totalCount := s.totalConnections.Add(1)
		authCount := s.authenticatedConnections.Load()

		session := &POP3Session{
			server:      s,
			conn:        &conn,
			deleted:     make(map[int]bool),
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			language:    "en", // Default language
			releaseConn: releaseConn,
		}

		// Extract real client IP and proxy IP from PROXY protocol if available
		var proxyInfo *serverPkg.ProxyProtocolInfo
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfo = proxyConn.GetProxyInfo()
		}
		
		clientIP, proxyIP := serverPkg.GetConnectionIPs(conn, proxyInfo)
		session.RemoteIP = clientIP
		session.ProxyIP = proxyIP
		session.Protocol = "POP3"
		session.Id = idgen.New()
		session.HostName = s.hostname
		session.Stats = s
		session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "POP3", session.Log)

		// Build connection info for logging
		var remoteInfo string
		if session.ProxyIP != "" {
			remoteInfo = fmt.Sprintf("%s proxy=%s", session.RemoteIP, session.ProxyIP)
		} else {
			remoteInfo = session.RemoteIP
		}
		log.Printf("* POP3 new connection from %s (connections: total=%d, authenticated=%d)",
			remoteInfo, totalCount, authCount)

		go session.handleConnection()
	}
}

func (s *POP3Server) Close() {
	log.Printf("* POP3 server closing")
	// Cancel the app context if it's still active
	// This will propagate to all session contexts
	if s.cancel != nil {
		s.cancel()
	}
}

// GetTotalConnections returns the current total connection count
func (s *POP3Server) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *POP3Server) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *serverPkg.ProxyProtocolReader
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Try to read PROXY protocol header
	proxyInfo, wrappedConn, err := l.proxyReader.ReadProxyHeader(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("PROXY protocol error: %w", err)
	}

	// Wrap the connection with proxy info for later extraction
	return &proxyProtocolConn{
		Conn:      wrappedConn,
		proxyInfo: proxyInfo,
	}, nil
}

// proxyProtocolConn wraps a connection with PROXY protocol information
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *serverPkg.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *serverPkg.ProxyProtocolInfo {
	return c.proxyInfo
}
