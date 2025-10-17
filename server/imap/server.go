// Package imap implements an IMAP4rev1 server with modern extensions.
//
// This package provides a production-ready IMAP server implementation with:
//   - IMAP4rev1 (RFC 3501) core protocol
//   - IDLE (RFC 2177) for push notifications
//   - MOVE (RFC 6851) for efficient message moving
//   - ESEARCH (RFC 4731) for extended search
//   - COMPRESS=DEFLATE (RFC 4978) for bandwidth optimization
//   - QUOTA (RFC 2087) for mailbox quota management
//   - Full UTF-8 support
//   - TLS/STARTTLS support
//   - SASL authentication (PLAIN, LOGIN)
//
// # Server Architecture
//
// The server uses a connection-per-client model with goroutines.
// Each connection has a state machine tracking authentication and
// mailbox selection:
//
//	NOT AUTHENTICATED → AUTHENTICATED → SELECTED → LOGOUT
//
// # Starting an IMAP Server
//
//	cfg := &config.IMAPConfig{
//		Addr:    ":143",
//		TLSAddr: ":993",
//		MaxConnections: 1000,
//	}
//	srv, err := imap.NewServer(cfg, db, s3, cache)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Start listeners
//	go srv.ListenAndServe(ctx)
//	go srv.ListenAndServeTLS(ctx, certFile, keyFile)
//
// # Supported Commands
//
// Pre-authentication:
//   - CAPABILITY: List server capabilities
//   - STARTTLS: Upgrade to TLS
//   - LOGIN: Authenticate with username/password
//
// Authenticated:
//   - SELECT/EXAMINE: Select a mailbox
//   - CREATE/DELETE/RENAME: Mailbox management
//   - SUBSCRIBE/UNSUBSCRIBE: Subscription management
//   - LIST/LSUB: Mailbox listing
//   - STATUS: Query mailbox status
//   - APPEND: Add message to mailbox
//
// Selected:
//   - FETCH: Retrieve message data
//   - STORE: Modify message flags
//   - SEARCH/ESEARCH: Search messages
//   - COPY/MOVE: Copy or move messages
//   - EXPUNGE: Permanently delete messages
//   - IDLE: Wait for mailbox changes
//
// # IDLE Implementation
//
// The IDLE command allows clients to receive real-time updates:
//
//	C: A001 IDLE
//	S: + idling
//	... server sends EXISTS/EXPUNGE as changes occur ...
//	C: DONE
//	S: A001 OK IDLE terminated
//
// # Performance Features
//
//   - Connection pooling to PostgreSQL
//   - Local cache for frequently accessed messages
//   - Batch operations for FETCH and SEARCH
//   - COMPRESS=DEFLATE reduces bandwidth by ~70%
//   - Efficient UID handling with sequence caching
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
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const DefaultAppendLimit = 25 * 1024 * 1024 // 25MB

// ClientCapabilityFilter extends the config.ClientCapabilityFilter with compiled regex patterns
type ClientCapabilityFilter struct {
	config.ClientCapabilityFilter
	clientNameRegexp     *regexp.Regexp
	clientVersionRegexp  *regexp.Regexp
	ja4FingerprintRegexp *regexp.Regexp
}

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
			log.Printf("IMAP [%s] Connection rejected: %v", l.name, limitErr)
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

// Unwrap returns the underlying connection for connection unwrapping
func (c *connectionLimitingConn) Unwrap() net.Conn {
	return c.Conn
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
	version            string

	// Metadata limits (RFC 5464)
	metadataMaxEntrySize         int
	metadataMaxEntriesPerMailbox int
	metadataMaxEntriesPerServer  int
	metadataMaxTotalSize         int

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection limiting
	limiter *serverPkg.ConnectionLimiter

	// Authentication rate limiting
	authLimiter serverPkg.AuthLimiter

	// Search rate limiting
	searchRateLimiter *serverPkg.SearchRateLimiter

	// Session memory limit
	sessionMemoryLimit int64

	// PROXY protocol support
	proxyReader *serverPkg.ProxyProtocolReader

	// Cache warmup configuration
	enableWarmup       bool
	warmupMessageCount int
	warmupMailboxes    []string
	warmupAsync        bool
	warmupTimeout      time.Duration

	// Client capability filtering
	capFilters []ClientCapabilityFilter

	// Command timeout and throughput enforcement
	commandTimeout         time.Duration
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)
}

type IMAPServerOptions struct {
	Debug                 bool
	TLS                   bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSVerify             bool
	MasterUsername        []byte
	MasterPassword        []byte
	MasterSASLUsername    []byte
	MasterSASLPassword    []byte
	AppendLimit           int64
	MaxConnections        int
	MaxConnectionsPerIP   int
	ProxyProtocol         bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout  string   // Timeout for reading PROXY headers
	TrustedNetworks       []string // Global trusted networks for parameter forwarding
	AuthRateLimit         serverPkg.AuthRateLimiterConfig
	SearchRateLimitPerMin int           // Search rate limit (searches per minute, 0=disabled)
	SearchRateLimitWindow time.Duration // Search rate limit time window
	SessionMemoryLimit    int64         // Per-session memory limit in bytes (0=unlimited)
	// Cache warmup configuration
	EnableWarmup       bool
	WarmupMessageCount int
	WarmupMailboxes    []string
	WarmupAsync        bool
	WarmupTimeout      string
	FTSRetention       time.Duration
	// Client capability filtering
	CapabilityFilters []config.ClientCapabilityFilter
	// Version information
	Version string
	// Metadata limits (RFC 5464)
	MetadataMaxEntrySize         int
	MetadataMaxEntriesPerMailbox int
	MetadataMaxEntriesPerServer  int
	MetadataMaxTotalSize         int
	// Command timeout and throughput enforcement
	CommandTimeout         time.Duration // Maximum idle time before disconnection
	AbsoluteSessionTimeout time.Duration // Maximum total session duration (0 = use default 30m)
	MinBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = use default 1KB/min)
}

func New(appCtx context.Context, name, hostname, imapAddr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options IMAPServerOptions) (*IMAPServer, error) {
	log.Printf("IMAP [%s] Creating server: TLS=%v, Cert=%q, Key=%q", name, options.TLS, options.TLSCertFile, options.TLSKeyFile)
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

	// Initialize search rate limiter
	searchRateLimiter := serverPkg.NewSearchRateLimiter("IMAP", options.SearchRateLimitPerMin, options.SearchRateLimitWindow)

	// Parse warmup timeout with default fallback
	warmupTimeout := 5 * time.Minute // Default timeout
	if options.WarmupTimeout != "" {
		if parsed, err := helpers.ParseDuration(options.WarmupTimeout); err != nil {
			log.Printf("IMAP [%s] WARNING: invalid warmup_timeout '%s': %v. Using default of %v", name, options.WarmupTimeout, err, warmupTimeout)
		} else {
			warmupTimeout = parsed
		}
	}

	s := &IMAPServer{
		hostname:                     hostname,
		name:                         name,
		appCtx:                       appCtx,
		addr:                         imapAddr,
		rdb:                          rdb,
		s3:                           resilientS3,
		uploader:                     uploadWorker,
		cache:                        cache,
		appendLimit:                  options.AppendLimit,
		ftsRetention:                 options.FTSRetention,
		version:                      options.Version,
		metadataMaxEntrySize:         options.MetadataMaxEntrySize,
		metadataMaxEntriesPerMailbox: options.MetadataMaxEntriesPerMailbox,
		metadataMaxEntriesPerServer:  options.MetadataMaxEntriesPerServer,
		metadataMaxTotalSize:         options.MetadataMaxTotalSize,
		authLimiter:                  authLimiter,
		searchRateLimiter:            searchRateLimiter,
		sessionMemoryLimit:           options.SessionMemoryLimit,
		proxyReader:                  proxyReader,
		enableWarmup:                 options.EnableWarmup,
		warmupMessageCount:           options.WarmupMessageCount,
		warmupMailboxes:              options.WarmupMailboxes,
		warmupAsync:                  options.WarmupAsync,
		warmupTimeout:                warmupTimeout,
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
			imap.CapMetadata:      struct{}{},
		},
		masterUsername:         options.MasterUsername,
		masterPassword:         options.MasterPassword,
		masterSASLUsername:     options.MasterSASLUsername,
		masterSASLPassword:     options.MasterSASLPassword,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
	}

	// Pre-compile regex patterns for capability filters for performance and correctness
	validFilters := make([]ClientCapabilityFilter, 0, len(options.CapabilityFilters))
	for _, configFilter := range options.CapabilityFilters {
		filter := ClientCapabilityFilter{ClientCapabilityFilter: configFilter}
		isValid := true

		if filter.ClientName != "" {
			re, err := regexp.Compile(filter.ClientName)
			if err != nil {
				log.Printf("IMAP [%s] WARNING: invalid client_name regex pattern '%s' in capability filter, skipping filter: %v", name, filter.ClientName, err)
				isValid = false
			} else {
				filter.clientNameRegexp = re
			}
		}
		if filter.ClientVersion != "" && isValid {
			re, err := regexp.Compile(filter.ClientVersion)
			if err != nil {
				log.Printf("IMAP [%s] WARNING: invalid client_version regex pattern '%s' in capability filter, skipping filter: %v", name, filter.ClientVersion, err)
				isValid = false
			} else {
				filter.clientVersionRegexp = re
			}
		}
		if filter.JA4Fingerprint != "" && isValid {
			re, err := regexp.Compile(filter.JA4Fingerprint)
			if err != nil {
				log.Printf("IMAP [%s] WARNING: invalid ja4_fingerprint regex pattern '%s' in capability filter, skipping filter: %v", name, filter.JA4Fingerprint, err)
				isValid = false
			} else {
				filter.ja4FingerprintRegexp = re
			}
		}

		// Only add the filter if all regex patterns are valid
		if isValid {
			validFilters = append(validFilters, filter)
		}
	}

	// Store the valid filters
	s.capFilters = validFilters

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
		log.Printf("IMAP [%s] Loading TLS certificate from %s and %s", name, options.TLSCertFile, options.TLSKeyFile)
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		// Warn if the certificate chain is incomplete.
		if len(cert.Certificate) < 2 {
			log.Printf("IMAP [%s] WARNING: The loaded TLS certificate file '%s' contains only one certificate. For full client compatibility, it should contain the full certificate chain (leaf + intermediates).", name, options.TLSCertFile)
		}

		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
			NextProtos:               []string{"imap"},
		}

		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			log.Printf("IMAP [%s] WARNING: Client TLS certificate verification is not enforced (tls_verify=false)", name)
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
		InsecureAuth: true, // We handle TLS authentication ourselves
		DebugWriter:  debugWriter,
		Caps:         s.caps,
		TLSConfig:    nil,
	})

	// Start connection limiter cleanup
	s.limiter.StartCleanup(appCtx)

	// Initialize command timeout metrics
	if s.commandTimeout > 0 {
		metrics.CommandTimeoutThresholdSeconds.WithLabelValues("imap").Set(s.commandTimeout.Seconds())
	}

	return s, nil
}

func (s *IMAPServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	// Connection limits are now handled at the listener level
	sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

	totalCount := s.totalConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("imap").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("imap").Inc()

	// Initialize memory tracker with configured limit
	memTracker := serverPkg.NewSessionMemoryTracker(s.sessionMemoryLimit)

	session := &IMAPSession{
		server:     s,
		conn:       conn,
		ctx:        sessionCtx,
		cancel:     sessionCancel,
		startTime:  time.Now(),
		memTracker: memTracker,
	}

	// Initialize session with full server capabilities
	// These will be filtered in GetCapabilities() when JA4 fingerprint becomes available
	session.sessionCaps = make(imap.CapSet)
	for cap := range s.caps {
		session.sessionCaps[cap] = struct{}{}
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	// Need to unwrap connection layers to get to proxyProtocolConn
	netConn := conn.NetConn()
	var proxyInfo *serverPkg.ProxyProtocolInfo
	currentConn := netConn
	for currentConn != nil {
		if proxyConn, ok := currentConn.(*proxyProtocolConn); ok {
			proxyInfo = proxyConn.GetProxyInfo()
			break
		} else if limitingConn, ok := currentConn.(*connectionLimitingConn); ok {
			if limitingInfo := limitingConn.GetProxyInfo(); limitingInfo != nil {
				proxyInfo = limitingInfo
				break
			}
		}
		// Try to unwrap the connection
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}

	// Check for JA4 fingerprint from PROXY v2 TLV (highest priority)
	var proxyJA4Fingerprint string
	if proxyInfo != nil && proxyInfo.JA4Fingerprint != "" {
		proxyJA4Fingerprint = proxyInfo.JA4Fingerprint
		log.Printf("IMAP [%s] Received JA4 fingerprint from PROXY v2 TLV: %s", s.name, proxyJA4Fingerprint)
	}

	// Extract JA4 fingerprint if this is a JA4-enabled TLS connection
	// Need to unwrap connection layers to get to the underlying JA4 connection
	var ja4Conn interface{ GetJA4Fingerprint() (string, error) }
	currentConn = netConn
	for currentConn != nil {
		if jc, ok := currentConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			ja4Conn = jc
			break
		}
		// Try to unwrap by checking for common wrapper patterns
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else if proxy, ok := currentConn.(*proxyProtocolConn); ok {
			currentConn = proxy.Conn
		} else if limiting, ok := currentConn.(*connectionLimitingConn); ok {
			currentConn = limiting.Conn
		} else {
			break
		}
	}

	// Priority order for JA4 fingerprint: PROXY v2 TLV > Direct connection unwrapping > ID command
	if proxyJA4Fingerprint != "" {
		// Use JA4 from PROXY v2 TLV (highest priority)
		session.ja4Fingerprint = proxyJA4Fingerprint
		log.Printf("[JA4-DEBUG] Using JA4 from PROXY v2 TLV: %s on session object %p", session.ja4Fingerprint, session)
		// Apply filters to sessionCaps BEFORE greeting is sent
		session.applyCapabilityFilters()
		log.Printf("[JA4-DEBUG] After applyCapabilityFilters (PROXY TLV), ja4Fingerprint=%s on session object %p", session.ja4Fingerprint, session)
	} else if ja4Conn != nil {
		log.Printf("[JA4-DEBUG] ja4Conn found, type=%T, attempting to retrieve fingerprint", ja4Conn)

		// Try to perform TLS handshake explicitly if the method is available
		// (Some connection types may have already completed the handshake)
		if handshaker, ok := ja4Conn.(interface{ Handshake() error }); ok {
			if err := handshaker.Handshake(); err != nil {
				log.Printf("IMAP [%s] TLS handshake failed: %v", s.name, err)
			} else {
				log.Printf("IMAP [%s] TLS handshake completed via explicit call", s.name)
			}
		}

		// Always try to capture the fingerprint immediately, regardless of whether
		// we called Handshake() explicitly. The handshake may have already completed
		// during connection acceptance.
		fingerprint, err := ja4Conn.GetJA4Fingerprint()
		log.Printf("[JA4-DEBUG] GetJA4Fingerprint returned: fingerprint=%q, err=%v", fingerprint, err)

		if err == nil && fingerprint != "" {
			session.ja4Fingerprint = fingerprint
			log.Printf("[JA4-DEBUG] Setting ja4Fingerprint=%s (direct) on session object %p", session.ja4Fingerprint, session)
			// Apply filters to sessionCaps BEFORE greeting is sent
			session.applyCapabilityFilters()
			log.Printf("[JA4-DEBUG] After applyCapabilityFilters (direct), ja4Fingerprint=%s on session object %p", session.ja4Fingerprint, session)
		} else {
			// Fingerprint not yet available - store ja4Conn for lazy capture
			// This should be rare since handshake typically completes during accept
			log.Printf("[JA4-DEBUG] Fingerprint not ready (fp=%q, err=%v), storing ja4Conn for lazy capture", fingerprint, err)
			session.ja4Conn = ja4Conn
		}
	} else {
		log.Printf("[JA4-DEBUG] No JA4 fingerprint available from PROXY TLV or direct connection - may be available via ID command")
	}

	clientIP, proxyIP := serverPkg.GetConnectionIPs(netConn, proxyInfo)
	session.RemoteIP = clientIP
	session.ProxyIP = proxyIP
	session.Protocol = "IMAP"
	session.ServerName = s.name
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
		// Create base TCP listener
		tcpListener, err := net.Listen("tcp", imapAddr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}

		// Wrap with JA4 TLS listener for fingerprinting
		listener = serverPkg.NewJA4TLSListener(tcpListener, s.tlsConfig)
		log.Printf("IMAP [%s] listening with TLS (JA4 fingerprinting enabled) on %s", s.name, imapAddr)
	} else {
		listener, err = net.Listen("tcp", imapAddr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("IMAP [%s] listening on %s", s.name, imapAddr)
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

	// Wrap listener with command timeout enforcement if configured
	var finalListener net.Listener = limitedListener
	if s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0 {
		finalListener = &timeoutListener{
			Listener:          limitedListener,
			timeout:           s.commandTimeout,
			absoluteTimeout:   s.absoluteSessionTimeout,
			minBytesPerMinute: s.minBytesPerMinute,
			protocol:          "imap",
		}
		log.Printf("IMAP [%s] timeout protection enabled - idle: %v, session_max: %v, throughput: %d bytes/min",
			s.name, s.commandTimeout, s.absoluteSessionTimeout, s.minBytesPerMinute)
	}

	err = s.server.Serve(finalListener)

	// Check if this was a graceful shutdown
	if s.appCtx.Err() != nil {
		log.Printf("IMAP [%s] server stopped gracefully", s.name)
		return nil
	}

	return err
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
			// Note: We don't have access to server name in this listener, use generic IMAP
			log.Printf("[IMAP] No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic IMAP
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

// Unwrap returns the underlying connection for connection unwrapping
func (c *proxyProtocolConn) Unwrap() net.Conn {
	return c.Conn
}

// WarmupCache pre-fetches recent messages for a user to improve performance when they reconnect
// This method fetches message content from S3 and stores it in the local cache
func (s *IMAPServer) WarmupCache(ctx context.Context, userID int64, mailboxNames []string, messageCount int, async bool) error {
	if messageCount <= 0 || len(mailboxNames) == 0 || s.cache == nil {
		return nil
	}

	log.Printf("IMAP [%s] starting cache warmup for user %d: %d messages from mailboxes %v (async=%t, timeout=%v)",
		s.name, userID, messageCount, mailboxNames, async, s.warmupTimeout)

	warmupFunc := func() {
		// Add timeout to prevent runaway warmup operations
		warmupCtx, cancel := context.WithTimeout(ctx, s.warmupTimeout)
		defer cancel()
		// Get recent message content hashes from database through cache
		messageHashes, err := s.cache.GetRecentMessagesForWarmup(warmupCtx, userID, mailboxNames, messageCount)
		if err != nil {
			log.Printf("IMAP [%s] failed to get recent messages for warmup: %v", s.name, err)
			return
		}

		totalHashes := 0
		for mailbox, hashes := range messageHashes {
			totalHashes += len(hashes)
			log.Printf("IMAP [%s] warmup found %d messages in mailbox '%s'", s.name, len(hashes), mailbox)
		}

		if totalHashes == 0 {
			log.Printf("IMAP [%s] no messages found for warmup", s.name)
			return
		}

		// Get user's primary email for S3 key construction
		address, err := s.rdb.GetPrimaryEmailForAccountWithRetry(warmupCtx, userID)
		if err != nil {
			log.Printf("IMAP [%s] warmup: failed to get primary address for account %d: %v", s.name, userID, err)
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
					log.Printf("IMAP [%s] warmup cancelled for user %d: %v", s.name, userID, warmupCtx.Err())
					return
				default:
					// Continue processing
				}

				// Check if already in cache
				exists, err := s.cache.Exists(contentHash)
				if err != nil {
					log.Printf("IMAP [%s] warmup: error checking existence of %s: %v", s.name, contentHash, err)
					continue
				}

				if exists {
					skippedCount++
					continue // Already cached
				}

				// Build S3 key and fetch from S3 (best-effort, no retries during warmup)
				s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), contentHash)

				// Single attempt - warmup is best-effort
				reader, fetchErr := s.s3.GetWithRetry(warmupCtx, s3Key)
				if fetchErr != nil {
					log.Printf("IMAP [%s] warmup: skipping %s, failed to fetch from S3: %v", s.name, contentHash, fetchErr)
					skippedCount++
					continue
				}

				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					log.Printf("IMAP [%s] warmup: skipping %s, failed to read from S3: %v", s.name, contentHash, err)
					skippedCount++
					continue
				}

				// Store in cache
				err = s.cache.Put(contentHash, data)
				if err != nil {
					if errors.Is(err, cache.ErrObjectTooLarge) {
						log.Printf("IMAP [%s] warmup: skipping %s, object too large for cache (%d bytes)", s.name, contentHash, len(data))
						skippedCount++
					} else {
						log.Printf("IMAP [%s] warmup: failed to cache content %s: %v", s.name, contentHash, err)
					}
					continue
				}

				warmedCount++
			}
		}

		log.Printf("IMAP [%s] warmup completed for user %d: %d messages cached, %d skipped (already cached)",
			s.name, userID, warmedCount, skippedCount)
	}

	if async {
		go warmupFunc()
	} else {
		warmupFunc()
	}

	return nil
}

// filterCapabilitiesForClient applies client-specific capability filtering and returns disabled capabilities
func (s *IMAPServer) filterCapabilitiesForClient(sessionCaps imap.CapSet, clientID *imap.IDData, tlsFingerprint string) []string {
	var disabledCaps []string

	if len(s.capFilters) == 0 {
		return disabledCaps // No filters configured
	}

	// Extract client info
	var clientName, clientVersion string
	if clientID != nil {
		clientName = clientID.Name
		clientVersion = clientID.Version
	}

	// Apply each matching filter
	log.Printf("IMAP [%s] Checking %d capability filters (clientName=%q, clientVersion=%q, tlsFingerprint=%q)",
		s.name, len(s.capFilters), clientName, clientVersion, tlsFingerprint)
	for i, filter := range s.capFilters {
		log.Printf("IMAP [%s] Filter %d: ClientName=%q, ClientVersion=%q, JA4Fingerprint=%q, DisableCaps=%v",
			s.name, i, filter.ClientName, filter.ClientVersion, filter.JA4Fingerprint, filter.DisableCaps)
		if s.clientMatches(clientName, clientVersion, tlsFingerprint, filter) {
			log.Printf("IMAP [%s] Applying capability filter: %s (clientName=%s, clientVersion=%s, tlsFingerprint=%s)",
				s.name, filter.Reason, clientName, clientVersion, tlsFingerprint)

			// Disable specified capabilities
			for _, capStr := range filter.DisableCaps {
				cap := imap.Cap(capStr)
				if _, exists := sessionCaps[cap]; exists {
					delete(sessionCaps, cap)
					disabledCaps = append(disabledCaps, capStr)
					log.Printf("IMAP [%s] Disabled capability %s (reason: %s)", s.name, cap, filter.Reason)
				}
			}
		}
	}

	return disabledCaps
}

// clientMatches checks if a client matches the filter criteria
// A filter matches if ANY of the following are true:
// 1. JA4 fingerprint matches (if specified in filter)
// 2. Client name/version match (if specified in filter)
func (s *IMAPServer) clientMatches(clientName, clientVersion, tlsFingerprint string, filter ClientCapabilityFilter) bool {
	// Check if JA4 fingerprint matches (if filter specifies one)
	if filter.ja4FingerprintRegexp != nil {
		if tlsFingerprint != "" && filter.ja4FingerprintRegexp.MatchString(tlsFingerprint) {
			// JA4 match is sufficient - return true immediately
			return true
		}
	}

	// Check if client name/version match (if filter specifies them)
	clientNameMatches := true // Default to true if not specified
	if filter.clientNameRegexp != nil {
		if clientName == "" || !filter.clientNameRegexp.MatchString(clientName) {
			clientNameMatches = false
		}
	}

	clientVersionMatches := true // Default to true if not specified
	if filter.clientVersionRegexp != nil {
		if clientVersion == "" || !filter.clientVersionRegexp.MatchString(clientVersion) {
			clientVersionMatches = false
		}
	}

	// Client name/version match if both specified criteria are met
	if filter.clientNameRegexp != nil || filter.clientVersionRegexp != nil {
		return clientNameMatches && clientVersionMatches
	}

	// If we reach here, no filter criteria were specified (shouldn't happen due to validation)
	return false
}
