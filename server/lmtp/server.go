package lmtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type LMTPServerBackend struct {
	addr          string
	hostname      string
	db            *db.Database
	s3            *storage.S3Storage
	uploader      *uploader.UploadWorker
	server        *smtp.Server
	appCtx        context.Context
	externalRelay string
	tlsConfig     *tls.Config
	debug         bool

	// Connection counters
	totalConnections atomic.Int64

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Sieve script caching
	sieveCache           *SieveScriptCache
	defaultSieveExecutor sieveengine.Executor

	// PROXY protocol support
	proxyReader *server.ProxyProtocolReader
}

type LMTPServerOptions struct {
	ExternalRelay       string
	Debug               bool
	TLS                 bool
	TLSCertFile         string
	TLSKeyFile          string
	TLSVerify           bool
	TLSUseStartTLS      bool
	MaxConnections      int
	MaxConnectionsPerIP int
	ProxyProtocol       server.ProxyProtocolConfig
}

func New(appCtx context.Context, hostname, addr string, s3 *storage.S3Storage, db *db.Database, uploadWorker *uploader.UploadWorker, options LMTPServerOptions) (*LMTPServerBackend, error) {
	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol.Enabled {
		var err error
		proxyReader, err = server.NewProxyProtocolReader("LMTP", options.ProxyProtocol)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	backend := &LMTPServerBackend{
		addr:          addr,
		appCtx:        appCtx,
		hostname:      hostname,
		db:            db,
		s3:            s3,
		uploader:      uploadWorker,
		externalRelay: options.ExternalRelay,
		debug:         options.Debug,
		limiter:       server.NewConnectionLimiter("LMTP", options.MaxConnections, options.MaxConnectionsPerIP),
		proxyReader:   proxyReader,
	}

	// Initialize Sieve script cache with a reasonable default size and TTL
	// 5 minute TTL ensures cross-server updates are picked up relatively quickly
	backend.sieveCache = NewSieveScriptCache(100, 5*time.Minute)

	// Parse and cache the default Sieve script at startup
	defaultExecutor, err := sieveengine.NewSieveExecutor(defaultSieveScript)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default Sieve script: %w", err)
	}
	backend.defaultSieveExecutor = defaultExecutor
	log.Printf("LMTP default Sieve script parsed and cached")

	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		backend.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
		}

		if !options.TLSVerify {
			backend.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for LMTP server")
		}
	}

	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	s.AllowInsecureAuth = true
	s.LMTP = true

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		log.Printf("StartTLS is enabled")
		// Force AllowInsecureAuth to true when StartTLS is enabled
		// This is necessary because with StartTLS, initial connections are unencrypted
		s.AllowInsecureAuth = true
	}
	// We only use a TLS listener for implicit TLS, not for StartTLS

	backend.server = s

	s.Network = "tcp"

	var debugWriter io.Writer
	if options.Debug {
		debugWriter = os.Stdout
		s.Debug = debugWriter
	}

	// Start connection limiter cleanup
	backend.limiter.StartCleanup(appCtx)

	return backend, nil
}

func (b *LMTPServerBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// Check connection limits
	releaseConn, err := b.limiter.Accept(c.Conn().RemoteAddr())
	if err != nil {
		log.Printf("[LMTP] Connection rejected: %v", err)
		return nil, fmt.Errorf("connection limit exceeded: %w", err)
	}

	sessionCtx, sessionCancel := context.WithCancel(b.appCtx)

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("lmtp").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("lmtp").Inc()

	s := &LMTPSession{
		backend:     b,
		conn:        c,
		ctx:         sessionCtx,
		cancel:      sessionCancel,
		releaseConn: releaseConn,
		startTime:   time.Now(),
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	netConn := c.Conn()
	var proxyInfo *server.ProxyProtocolInfo
	if proxyConn, ok := netConn.(*proxyProtocolConn); ok {
		proxyInfo = proxyConn.GetProxyInfo()
	}

	clientIP, proxyIP := server.GetConnectionIPs(netConn, proxyInfo)
	s.RemoteIP = clientIP
	s.ProxyIP = proxyIP
	s.Id = idgen.New()
	s.HostName = b.hostname
	s.Protocol = "LMTP"
	s.Stats = b // Set the server as the Stats provider

	// Create logging function for the mutex helper
	logFunc := func(format string, args ...interface{}) {
		s.Log(format, args...)
	}

	// Initialize the mutex helper
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "LMTP", logFunc)

	// Log connection with connection counters
	totalCount := b.totalConnections.Load()
	s.Log("new session remote=%s id=%s (connections: total=%d)",
		s.RemoteIP, s.Id, totalCount)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	var listener net.Listener
	var err error

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - use TLS listener
		listener, err = tls.Listen("tcp", b.server.Addr, b.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* LMTP listening with implicit TLS on %s", b.server.Addr)
	} else {
		listener, err = net.Listen("tcp", b.server.Addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* LMTP listening on %s", b.server.Addr)
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if b.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: b.proxyReader,
		}
	}

	if err := b.server.Serve(listener); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		if b.appCtx.Err() == nil {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	}
}

func (b *LMTPServerBackend) Close() error {
	if b.server != nil {
		return b.server.Close()
	}
	return nil
}

// GetTotalConnections returns the current total connection count
func (b *LMTPServerBackend) GetTotalConnections() int64 {
	return b.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
// For LMTP, all connections are considered authenticated
func (b *LMTPServerBackend) GetAuthenticatedConnections() int64 {
	return 0
}

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *server.ProxyProtocolReader
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
		// Log but don't crash - let the server continue accepting other connections
		log.Printf("[LMTP] PROXY protocol error, rejecting connection: %v", err)
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
	proxyInfo *server.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *server.ProxyProtocolInfo {
	return c.proxyInfo
}
