package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const DefaultAppendLimit = 25 * 1024 * 1024 // 25MB

// connectionLimitingListener wraps a net.Listener to enforce connection limits at the TCP level
type connectionLimitingListener struct {
	net.Listener
	limiter *serverPkg.ConnectionLimiter
	name    string
}

// Accept accepts connections and checks connection limits before returning them
func (l *connectionLimitingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Extract real client IP and proxy info if this is a PROXY protocol connection
		var realClientIP string
		var proxyInfo *serverPkg.ProxyProtocolInfo
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfo = proxyConn.GetProxyInfo()
			if proxyInfo != nil && proxyInfo.SrcIP != "" {
				realClientIP = proxyInfo.SrcIP
			}
		}

		// Check connection limits with PROXY protocol support
		releaseConn, limitErr := l.limiter.AcceptWithRealIP(conn.RemoteAddr(), realClientIP)
		if limitErr != nil {
			log.Printf("[IMAP-%s] Connection rejected: %v", l.name, limitErr)
			conn.Close()
			continue // Try to accept the next connection
		}

		// Wrap the connection to ensure cleanup on close and preserve PROXY info
		return &connectionLimitingConn{
			Conn:        conn,
			releaseFunc: releaseConn,
			proxyInfo:   proxyInfo,
		}, nil
	}
}

// connectionLimitingConn wraps a net.Conn to ensure connection limit cleanup on close
type connectionLimitingConn struct {
	net.Conn
	releaseFunc func()
	proxyInfo   *serverPkg.ProxyProtocolInfo
}

// GetProxyInfo implements the same interface as proxyProtocolConn
func (c *connectionLimitingConn) GetProxyInfo() *serverPkg.ProxyProtocolInfo {
	return c.proxyInfo
}

func (c *connectionLimitingConn) Close() error {
	if c.releaseFunc != nil {
		c.releaseFunc()
		c.releaseFunc = nil // Prevent double release
	}
	return c.Conn.Close()
}

// maskingWriter is a wrapper for an io.Writer that redacts sensitive information.
type maskingWriter struct {
	w io.Writer
}

// Write inspects the log output, and if it's a client command (prefixed with "C: "),
// it attempts to mask sensitive parts of LOGIN or AUTHENTICATE commands.
func (mw *maskingWriter) Write(p []byte) (n int, err error) {
	line := string(p)
	originalLen := len(p)

	// Only process client commands
	if !strings.HasPrefix(line, "C: ") {
		return mw.w.Write(p)
	}

	cmdLine := strings.TrimPrefix(line, "C: ")
	trimmedCmdLine := strings.TrimRight(cmdLine, "\r\n")
	parts := strings.Fields(trimmedCmdLine)
	if len(parts) < 2 { // Needs at least tag and command
		return mw.w.Write(p)
	}

	command := strings.ToUpper(parts[1])

	// Use the helper to mask the command line
	maskedCmdLine := helpers.MaskSensitive(trimmedCmdLine, command, "LOGIN", "AUTHENTICATE")

	// If the line was modified, write the masked version.
	if maskedCmdLine != trimmedCmdLine {
		maskedLine := "C: " + maskedCmdLine + "\r\n"
		_, err = mw.w.Write([]byte(maskedLine))
	} else {
		// Otherwise, write the original line.
		_, err = mw.w.Write(p)
	}

	if err != nil {
		return 0, err
	}

	// We "pretend" to have written the original number of bytes
	// to satisfy the io.Writer contract and not confuse the caller.
	return originalLen, nil
}

type IMAPServer struct {
	addr               string
	name               string
	rdb                *resilient.ResilientDatabase
	hostname           string
	s3                 *resilient.ResilientS3Storage
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
	ftsRetention       time.Duration

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
	warmupTimeout      time.Duration
}

type IMAPServerOptions struct {
	Debug                bool
	TLS                  bool
	TLSCertFile          string
	TLSKeyFile           string
	TLSVerify            bool
	MasterUsername       []byte
	MasterPassword       []byte
	MasterSASLUsername   []byte
	MasterSASLPassword   []byte
	AppendLimit          int64
	MaxConnections       int
	MaxConnectionsPerIP  int
	ProxyProtocol        bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout string   // Timeout for reading PROXY headers
	TrustedNetworks      []string // Global trusted networks for parameter forwarding
	AuthRateLimit        serverPkg.AuthRateLimiterConfig
	// Cache warmup configuration
	EnableWarmup       bool
	WarmupMessageCount int
	WarmupMailboxes    []string
	WarmupAsync        bool
	WarmupTimeout      string
	FTSRetention       time.Duration
}

func New(appCtx context.Context, name, hostname, imapAddr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options IMAPServerOptions) (*IMAPServer, error) {
	// Validate required dependencies
	if s3 == nil {
		return nil, fmt.Errorf("S3 storage is required for IMAP server")
	}
	if rdb == nil {
		return nil, fmt.Errorf("database is required for IMAP server")
	}

	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)

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
		proxyReader, err = serverPkg.NewProxyProtocolReader("IMAP", proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("IMAP", options.AuthRateLimit, rdb, options.TrustedNetworks)

	// Parse warmup timeout with default fallback
	warmupTimeout := 5 * time.Minute // Default timeout
	if options.WarmupTimeout != "" {
		if parsed, err := helpers.ParseDuration(options.WarmupTimeout); err != nil {
			log.Printf("[IMAP] WARNING: invalid warmup_timeout '%s': %v. Using default of %v", options.WarmupTimeout, err, warmupTimeout)
		} else {
			warmupTimeout = parsed
		}
	}

	s := &IMAPServer{
		hostname:           hostname,
		name:               name,
		appCtx:             appCtx,
		addr:               imapAddr,
		rdb:                rdb,
		s3:                 resilientS3,
		uploader:           uploadWorker,
		cache:              cache,
		appendLimit:        options.AppendLimit,
		ftsRetention:       options.FTSRetention,
		authLimiter:        authLimiter,
		proxyReader:        proxyReader,
		enableWarmup:       options.EnableWarmup,
		warmupMessageCount: options.WarmupMessageCount,
		warmupMailboxes:    options.WarmupMailboxes,
		warmupAsync:        options.WarmupAsync,
		warmupTimeout:      warmupTimeout,
		caps: imap.CapSet{
			imap.CapIMAP4rev1:     struct{}{},
			imap.CapLiteralPlus:   struct{}{},
			imap.CapSASLIR:        struct{}{},
			imap.CapMove:          struct{}{},
			imap.AuthCap("PLAIN"): struct{}{},
			imap.CapIdle:          struct{}{},
			imap.CapUIDPlus:       struct{}{},
			imap.CapESearch:       struct{}{},
			imap.CapESort:         struct{}{},
			imap.CapSort:          struct{}{},
			imap.CapSortDisplay:   struct{}{},
			imap.CapSpecialUse:    struct{}{},
			imap.CapListStatus:    struct{}{},
			imap.CapBinary:        struct{}{},
			imap.CapCondStore:     struct{}{},
			imap.CapChildren:      struct{}{},
			imap.CapID:            struct{}{},
			imap.CapNamespace:     struct{}{},
		},
		masterUsername:     options.MasterUsername,
		masterPassword:     options.MasterPassword,
		masterSASLUsername: options.MasterSASLUsername,
		masterSASLPassword: options.MasterSASLPassword,
	}

	// Create connection limiter with trusted networks from server configuration
	// For IMAP backend:
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

	s.limiter = serverPkg.NewConnectionLimiterWithTrustedNets("IMAP", options.MaxConnections, limiterMaxPerIP, limiterTrustedNets)

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

		// Warn if the certificate chain is incomplete.
		if len(cert.Certificate) < 2 {
			log.Printf("[IMAP] WARNING: The loaded TLS certificate file '%s' contains only one certificate. For full client compatibility, it should contain the full certificate chain (leaf + intermediates).", options.TLSCertFile)
		}

		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
		}

		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			log.Printf("WARNING: Client TLS certificate verification is not enforced for IMAP server (tls_verify=false)")
		}
	}

	var debugWriter io.Writer
	if options.Debug {
		// Wrap os.Stdout with our masking writer to redact passwords from debug logs
		debugWriter = &maskingWriter{w: os.Stdout}
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
	// Connection limits are now handled at the listener level
	sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

	totalCount := s.totalConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("imap").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("imap").Inc()

	session := &IMAPSession{
		server:    s,
		conn:      conn,
		ctx:       sessionCtx,
		cancel:    sessionCancel,
		startTime: time.Now(),
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	netConn := conn.NetConn()
	var proxyInfo *serverPkg.ProxyProtocolInfo
	if proxyConn, ok := netConn.(*proxyProtocolConn); ok {
		proxyInfo = proxyConn.GetProxyInfo()
	} else if limitingConn, ok := netConn.(*connectionLimitingConn); ok {
		proxyInfo = limitingConn.GetProxyInfo()
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
		log.Printf("* IMAP [%s] listening with TLS on %s", s.name, imapAddr)
	} else {
		listener, err = net.Listen("tcp", imapAddr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("* IMAP [%s] listening on %s", s.name, imapAddr)
	}
	defer listener.Close()
	defer func() {
		_ = listener.Close()
	}()

	// Wrap listener with PROXY protocol support if enabled
	if s.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: s.proxyReader,
		}
	}

	// Wrap listener with connection limiting
	limitedListener := &connectionLimitingListener{
		Listener: listener,
		limiter:  s.limiter,
		name:     s.name,
	}

	return s.server.Serve(limitedListener)
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
			log.Printf("[IMAP] No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		log.Printf("[IMAP] PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
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

// WarmupCache pre-fetches recent messages for a user to improve performance when they reconnect
// This method fetches message content from S3 and stores it in the local cache
func (s *IMAPServer) WarmupCache(ctx context.Context, userID int64, mailboxNames []string, messageCount int, async bool) error {
	if messageCount <= 0 || len(mailboxNames) == 0 || s.cache == nil {
		return nil
	}

	log.Printf("[IMAP] starting cache warmup for user %d: %d messages from mailboxes %v (async=%t, timeout=%v)",
		userID, messageCount, mailboxNames, async, s.warmupTimeout)

	warmupFunc := func() {
		// Add timeout to prevent runaway warmup operations
		warmupCtx, cancel := context.WithTimeout(ctx, s.warmupTimeout)
		defer cancel()
		// Get recent message content hashes from database through cache
		messageHashes, err := s.cache.GetRecentMessagesForWarmup(warmupCtx, userID, mailboxNames, messageCount)
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
		address, err := s.rdb.GetPrimaryEmailForAccountWithRetry(warmupCtx, userID)
		if err != nil {
			log.Printf("[IMAP] warmup: failed to get primary address for account %d: %v", userID, err)
			return
		}

		warmedCount := 0
		skippedCount := 0

		// Pre-fetch each message content
		for _, hashes := range messageHashes {
			for _, contentHash := range hashes {
				// Check for context cancellation
				select {
				case <-warmupCtx.Done():
					log.Printf("[IMAP] warmup cancelled for user %d: %v", userID, warmupCtx.Err())
					return
				default:
					// Continue processing
				}

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

				// Build S3 key and fetch from S3 with retry logic
				s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), contentHash)
				var data []byte

				// Retry S3 operations up to 3 times with exponential backoff
				maxRetries := 3
				var fetchErr error
				for attempt := 0; attempt < maxRetries; attempt++ {
					if attempt > 0 {
						// Exponential backoff: 100ms, 200ms, 400ms
						backoffTime := time.Duration(100*(1<<uint(attempt-1))) * time.Millisecond
						select {
						case <-time.After(backoffTime):
						case <-warmupCtx.Done():
							log.Printf("[IMAP] warmup cancelled during retry backoff for user %d", userID)
							return
						}
						log.Printf("[IMAP] warmup: retrying S3 fetch for %s (attempt %d/%d)", contentHash, attempt+1, maxRetries)
					}

					reader, err := s.s3.GetWithRetry(ctx, s3Key)
					if err != nil {
						fetchErr = err
						continue
					}

					data, err = io.ReadAll(reader)
					reader.Close()
					if err != nil {
						fetchErr = err
						continue
					}

					// Success - break out of retry loop
					fetchErr = nil
					break
				}

				if fetchErr != nil {
					log.Printf("[IMAP] warmup: failed to fetch content %s from S3 after %d attempts: %v", contentHash, maxRetries, fetchErr)
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
