package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const DefaultAppendLimit = 25 * 1024 * 1024 // 25MB

type IMAPServer struct {
	addr               string
	db                 *db.Database
	hostname           string
	s3                 *storage.S3Storage
	server             *imapserver.Server
	uploader           *uploader.UploadWorker
	cache              *cache.Cache
	appCtx             context.Context
	caps               imap.CapSet
	tlsConfig          *tls.Config
	masterUsername     []byte
	masterPassword     []byte
	masterSASLUsername []byte
	masterSASLPassword []byte
	appendLimit        int64

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection limiting
	limiter *serverPkg.ConnectionLimiter

	// Authentication rate limiting
	authLimiter serverPkg.AuthLimiter

	// PROXY protocol support
	proxyReader *serverPkg.ProxyProtocolReader
}

type IMAPServerOptions struct {
	Debug               bool
	TLS                 bool
	TLSCertFile         string
	TLSKeyFile          string
	TLSVerify           bool
	MasterUsername      []byte
	MasterPassword      []byte
	MasterSASLUsername  []byte
	MasterSASLPassword  []byte
	AppendLimit         int64
	MaxConnections      int
	MaxConnectionsPerIP int
	ProxyProtocol       serverPkg.ProxyProtocolConfig
	AuthRateLimit       serverPkg.AuthRateLimiterConfig
}

func New(appCtx context.Context, hostname, imapAddr string, storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options IMAPServerOptions) (*IMAPServer, error) {
	// Initialize PROXY protocol reader if enabled
	var proxyReader *serverPkg.ProxyProtocolReader
	if options.ProxyProtocol.Enabled {
		var err error
		proxyReader, err = serverPkg.NewProxyProtocolReader("IMAP", options.ProxyProtocol)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize enhanced authentication rate limiter
	authLimiter := serverPkg.NewEnhancedAuthRateLimiterFromBasic("IMAP", options.AuthRateLimit, database)

	s := &IMAPServer{
		hostname:    hostname,
		appCtx:      appCtx,
		addr:        imapAddr,
		db:          database,
		s3:          storage,
		uploader:    uploadWorker,
		cache:       cache,
		appendLimit: options.AppendLimit,
		limiter:     serverPkg.NewConnectionLimiter("IMAP", options.MaxConnections, options.MaxConnectionsPerIP),
		authLimiter: authLimiter,
		proxyReader: proxyReader,
		caps: imap.CapSet{
			imap.CapIMAP4rev1:   struct{}{},
			imap.CapLiteralPlus: struct{}{},
			imap.CapSASLIR:      struct{}{},
			imap.CapAuthPlain:   struct{}{},
			imap.CapMove:        struct{}{},
			imap.CapIdle:        struct{}{},
			imap.CapUIDPlus:     struct{}{},
			imap.CapESearch:     struct{}{},
			imap.CapESort:       struct{}{},
			imap.CapSort:        struct{}{},
			imap.CapSortDisplay: struct{}{},
			imap.CapSpecialUse:  struct{}{},
			imap.CapListStatus:  struct{}{},
			imap.CapBinary:      struct{}{},
			imap.CapCondStore:   struct{}{},
			imap.CapChildren:    struct{}{},
			imap.CapID:          struct{}{},
		},
		masterUsername:     options.MasterUsername,
		masterPassword:     options.MasterPassword,
		masterSASLUsername: options.MasterSASLUsername,
		masterSASLPassword: options.MasterSASLPassword,
	}

	if s.appendLimit > 0 {
		appendLimitCapName := imap.Cap(fmt.Sprintf("APPENDLIMIT=%d", s.appendLimit))
		s.caps[appendLimitCapName] = struct{}{}
		s.caps.Has(imap.CapAppendLimit)
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
		}

		if !options.TLSVerify {
			s.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING TLS certificate verification disabled for IMAP server")
		}
	}

	var debugWriter io.Writer
	if options.Debug {
		debugWriter = os.Stdout
	}

	s.server = imapserver.New(&imapserver.Options{
		NewSession:   s.newSession,
		Logger:       log.Default(),
		InsecureAuth: !options.TLS,
		DebugWriter:  debugWriter,
		Caps:         s.caps,
		TLSConfig:    s.tlsConfig,
	})

	// Start connection limiter cleanup
	s.limiter.StartCleanup(appCtx)

	return s, nil
}

func (s *IMAPServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	// Check connection limits
	releaseConn, err := s.limiter.Accept(conn.NetConn().RemoteAddr())
	if err != nil {
		log.Printf("[IMAP] Connection rejected: %v", err)
		return nil, nil, fmt.Errorf("connection limit exceeded: %w", err)
	}

	sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

	totalCount := s.totalConnections.Add(1)

	session := &IMAPSession{
		server:      s,
		conn:        conn,
		ctx:         sessionCtx,
		cancel:      sessionCancel,
		releaseConn: releaseConn,
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	netConn := conn.NetConn()
	var proxyInfo *serverPkg.ProxyProtocolInfo
	if proxyConn, ok := netConn.(*proxyProtocolConn); ok {
		proxyInfo = proxyConn.GetProxyInfo()
	}

	clientIP, proxyIP := serverPkg.GetConnectionIPs(netConn, proxyInfo)
	session.RemoteIP = clientIP
	session.ProxyIP = proxyIP
	session.Protocol = "IMAP"
	session.Id = idgen.New()
	session.HostName = s.hostname
	session.Stats = s
	session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "IMAP", session.Log)

	greeting := &imapserver.GreetingData{
		PreAuth: false,
	}

	authCount := s.authenticatedConnections.Load()
	session.Log("connected (connections: total=%d, authenticated=%d)", totalCount, authCount)

	return session, greeting, nil
}

func (s *IMAPServer) Serve(imapAddr string) error {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", imapAddr, s.tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to create TLS listener: %w", err)
		}
		log.Printf("* IMAP listening with TLS on %s", imapAddr)
	} else {
		listener, err = net.Listen("tcp", imapAddr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("* IMAP listening on %s", imapAddr)
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if s.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: s.proxyReader,
		}
	}

	return s.server.Serve(listener)
}

func (s *IMAPServer) Close() {
	if s.server != nil {
		// This will close the listener and cause s.server.Serve(listener) to return.
		// It will also start closing active client connections.
		s.server.Close()
	}
}

// GetTotalConnections returns the current total connection count
func (s *IMAPServer) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *IMAPServer) GetAuthenticatedConnections() int64 {
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
		// Log but don't crash - let the server continue accepting other connections
		log.Printf("[IMAP] PROXY protocol error, rejecting connection: %v", err)
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
