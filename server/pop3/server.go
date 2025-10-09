package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type POP3Server struct {
	addr               string
	name               string
	hostname           string
	rdb                *resilient.ResilientDatabase
	s3                 *resilient.ResilientS3Storage
	appCtx             context.Context
	cancel             context.CancelFunc
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

	// XCLIENT is always enabled but limited to trusted networks
	trustedNetworks []string

	// Memory limiting
	sessionMemoryLimit int64
}

type POP3ServerOptions struct {
	Debug                bool
	TLS                  bool
	TLSCertFile          string
	TLSKeyFile           string
	TLSVerify            bool
	MasterSASLUsername   string
	MasterSASLPassword   string
	MaxConnections       int
	MaxConnectionsPerIP  int
	ProxyProtocol        bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout string   // Timeout for reading PROXY headers
	TrustedNetworks      []string // Global trusted networks for parameter forwarding
	AuthRateLimit        serverPkg.AuthRateLimiterConfig
	SessionMemoryLimit   int64 // Memory limit per session in bytes
}

func New(appCtx context.Context, name, hostname, popAddr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options POP3ServerOptions) (*POP3Server, error) {
	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)

	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Initialize PROXY protocol reader if enabled
	var proxyReader *serverPkg.ProxyProtocolReader
	if options.ProxyProtocol {
		// Create ProxyProtocolConfig from simplified settings
		proxyConfig := serverPkg.ProxyProtocolConfig{
			Enabled:        true,
			Mode:           "required",
			TrustedProxies: options.TrustedNetworks,
			Timeout:        options.ProxyProtocolTimeout,
		}

		// Proxy protocol is always required when enabled

		var err error
		proxyReader, err = serverPkg.NewProxyProtocolReader("POP3", proxyConfig)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("POP3", options.AuthRateLimit, rdb, options.TrustedNetworks)

	server := &POP3Server{
		hostname:           hostname,
		name:               name,
		addr:               popAddr,
		rdb:                rdb,
		s3:                 resilientS3,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		uploader:           uploadWorker,
		cache:              cache,
		masterSASLUsername: []byte(options.MasterSASLUsername),
		masterSASLPassword: []byte(options.MasterSASLPassword),
		proxyReader:        proxyReader,
		authLimiter:        authLimiter,
		trustedNetworks:    options.TrustedNetworks,
		sessionMemoryLimit: options.SessionMemoryLimit,
	}

	// Create connection limiter with trusted networks from server configuration
	// For POP3 backend:
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

	server.limiter = serverPkg.NewConnectionLimiterWithTrustedNets("POP3", options.MaxConnections, limiterMaxPerIP, limiterTrustedNets)

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
		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			log.Printf("POP3 [%s] WARNING: Client TLS certificate verification is not enforced (tls_verify=false)", name)
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
		log.Printf("* POP3 [%s] listening with TLS on %s", s.name, s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.cancel()
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* POP3 [%s] listening on %s", s.name, s.addr)
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
		log.Printf("* POP3 [%s] stopping", s.name)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if this is a PROXY protocol error (connection-specific, not fatal)
			if errors.Is(err, errProxyProtocol) {
				log.Printf("POP3 [%s] %v, rejecting connection", s.name, err)
				continue // Continue accepting other connections
			}

			// Check if the error is due to the listener being closed (graceful shutdown)
			select {
			case <-s.appCtx.Done():
				log.Printf("* POP3 [%s] server stopped gracefully", s.name)
				return
			default:
				// For other errors, this might be a fatal server error
				errChan <- err
				return
			}
		}

		// Extract real client IP and proxy IP from PROXY protocol if available for connection limiting
		var proxyInfoForLimiting *serverPkg.ProxyProtocolInfo
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
			log.Printf("POP3 [%s] Connection rejected: %v", s.name, err)
			conn.Close()
			continue
		}

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		totalCount := s.totalConnections.Add(1)
		authCount := s.authenticatedConnections.Load()

		// Prometheus metrics - connection established
		metrics.ConnectionsTotal.WithLabelValues("pop3").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("pop3").Inc()

		// Initialize memory tracker with configured limit
		memTracker := serverPkg.NewSessionMemoryTracker(s.sessionMemoryLimit)

		session := &POP3Session{
			server:      s,
			conn:        &conn,
			deleted:     make(map[int]bool),
			ctx:         sessionCtx,
			cancel:      sessionCancel,
			language:    "en", // Default language
			releaseConn: releaseConn,
			startTime:   time.Now(),
			memTracker:  memTracker,
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
		session.ServerName = s.name
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
		log.Printf("* POP3 [%s] new connection from %s (connections: total=%d, authenticated=%d)",
			s.name, remoteInfo, totalCount, authCount)

		go session.handleConnection()
	}
}

func (s *POP3Server) Close() {
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

var errProxyProtocol = errors.New("PROXY protocol error")

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *serverPkg.ProxyProtocolReader
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
		// This requires the underlying ProxyProtocolReader to be updated to return a specific error (e.g., serverPkg.ErrNoProxyHeader)
		// and to not consume bytes from the connection if no header is found.
		if l.proxyReader.IsOptionalMode() && errors.Is(err, serverPkg.ErrNoProxyHeader) {
			// Note: We don't have access to server name in this listener, use generic POP3
			log.Printf("[POP3] No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic POP3
		log.Printf("[POP3] PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
		continue
	}
}

// proxyProtocolConn wraps a connection with PROXY protocol information
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *serverPkg.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *serverPkg.ProxyProtocolInfo {
	return c.proxyInfo
}
