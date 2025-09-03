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
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
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
	
	// Cache warmup configuration
	enableWarmup       bool
	warmupMessageCount int
	warmupMailboxes    []string
	warmupAsync        bool
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
	// Cache warmup configuration
	EnableWarmup         bool
	WarmupMessageCount   int
	WarmupMailboxes      []string
	WarmupAsync          bool
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

	// Initialize authentication rate limiter
	authLimiter := serverPkg.NewAuthRateLimiter("IMAP", options.AuthRateLimit, database)

	s := &IMAPServer{
		hostname:           hostname,
		appCtx:             appCtx,
		addr:               imapAddr,
		db:                 database,
		s3:                 storage,
		uploader:           uploadWorker,
		cache:              cache,
		appendLimit:        options.AppendLimit,
		limiter:            serverPkg.NewConnectionLimiter("IMAP", options.MaxConnections, options.MaxConnectionsPerIP),
		authLimiter:        authLimiter,
		proxyReader:        proxyReader,
		enableWarmup:       options.EnableWarmup,
		warmupMessageCount: options.WarmupMessageCount,
		warmupMailboxes:    options.WarmupMailboxes,
		warmupAsync:        options.WarmupAsync,
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

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("imap").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("imap").Inc()

	session := &IMAPSession{
		server:      s,
		conn:        conn,
		ctx:         sessionCtx,
		cancel:      sessionCancel,
		releaseConn: releaseConn,
		startTime:   time.Now(),
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

// WarmupCache pre-fetches recent messages for a user to improve performance when they reconnect
// This method fetches message content from S3 and stores it in the local cache
func (s *IMAPServer) WarmupCache(ctx context.Context, userID int64, mailboxNames []string, messageCount int, async bool) error {
	if messageCount <= 0 || len(mailboxNames) == 0 || s.cache == nil {
		return nil
	}

	log.Printf("[IMAP] starting cache warmup for user %d: %d messages from mailboxes %v (async=%t)", 
		userID, messageCount, mailboxNames, async)

	warmupFunc := func() {
		// Get recent message content hashes from database through cache
		messageHashes, err := s.cache.GetRecentMessagesForWarmup(ctx, userID, mailboxNames, messageCount)
		if err != nil {
			log.Printf("[IMAP] failed to get recent messages for warmup: %v", err)
			return
		}

		totalHashes := 0
		for mailbox, hashes := range messageHashes {
			totalHashes += len(hashes)
			log.Printf("[IMAP] warmup found %d messages in mailbox '%s'", len(hashes), mailbox)
		}

		if totalHashes == 0 {
			log.Printf("[IMAP] no messages found for warmup")
			return
		}

		// Get user's primary email for S3 key construction
		address, err := s.db.GetPrimaryEmailForAccount(ctx, userID)
		if err != nil {
			log.Printf("[IMAP] warmup: failed to get primary address for account %d: %v", userID, err)
			return
		}

		warmedCount := 0
		skippedCount := 0

		// Pre-fetch each message content
		for _, hashes := range messageHashes {
			for _, contentHash := range hashes {
				// Check if already in cache
				exists, err := s.cache.Exists(contentHash)
				if err != nil {
					log.Printf("[IMAP] warmup: error checking existence of %s: %v", contentHash, err)
					continue
				}

				if exists {
					skippedCount++
					continue // Already cached
				}

				// Build S3 key and fetch from S3
				s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), contentHash)
				reader, err := s.s3.Get(s3Key)
				if err != nil {
					log.Printf("[IMAP] warmup: failed to fetch content %s from S3: %v", contentHash, err)
					continue
				}

				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					log.Printf("[IMAP] warmup: failed to read content %s: %v", contentHash, err)
					continue
				}

				// Store in cache
				err = s.cache.Put(contentHash, data)
				if err != nil {
					log.Printf("[IMAP] warmup: failed to cache content %s: %v", contentHash, err)
					continue
				}

				warmedCount++
			}
		}

		log.Printf("[IMAP] warmup completed for user %d: %d messages cached, %d skipped (already cached)", 
			userID, warmedCount, skippedCount)
	}

	if async {
		go warmupFunc()
	} else {
		warmupFunc()
	}

	return nil
}
