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
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"golang.org/x/crypto/bcrypt"
)

const DefaultAppendLimit = 25 * 1024 * 1024 // 25MB

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

// ClientCapabilityFilter extends the config.ClientCapabilityFilter with compiled regex patterns
type ClientCapabilityFilter struct {
	config.ClientCapabilityFilter
	clientNameRegexp      *regexp.Regexp
	clientVersionRegexp   *regexp.Regexp
	ja4FingerprintRegexps []*regexp.Regexp // Multiple JA4 patterns - matches if ANY pattern matches
}

// connectionLimitingListener wraps a net.Listener to enforce connection limits and rate limits at the TCP level
type connectionLimitingListener struct {
	net.Listener
	limiter     *serverPkg.ConnectionLimiter
	authLimiter serverPkg.AuthLimiter
	name        string
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
			logger.Debug("IMAP: Connection rejected", "name", l.name, "error", limitErr)
			conn.Close()
			continue // Try to accept the next connection
		}

		// Check if IP is blocked by rate limiter (Tier 2: IP-level blocking)
		// This happens BEFORE TLS handshake to save resources
		if l.authLimiter != nil && l.authLimiter.IsIPBlockedWithProxy(conn, proxyInfo) {
			// Determine real IP for logging
			logIP := realClientIP
			if logIP == "" {
				logIP = server.GetAddrString(conn.RemoteAddr())
			}
			logger.Info("IMAP: Rejected connection from rate-limited IP",
				"name", l.name,
				"ip", logIP,
				"reason", "IP blocked by rate limiter (Tier 2)")
			releaseConn() // Release the connection limit
			conn.Close()
			continue // Try to accept the next connection
		}

		// Perform TLS handshake if this is a TLS connection (before any I/O)
		// Must happen before go-imap library starts reading from the connection
		if tlsConn, ok := conn.(interface{ PerformHandshake() error }); ok {
			if err := tlsConn.PerformHandshake(); err != nil {
				logger.Debug("IMAP: TLS handshake failed", "name", l.name, "remote", server.GetAddrString(conn.RemoteAddr()), "error", err)
				releaseConn() // Release the connection limit
				conn.Close()
				continue // Try to accept the next connection
			}
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
	closeMu     sync.Mutex
	closed      bool
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
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	if c.closed {
		return nil // Already closed
	}
	c.closed = true

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
	lookupCache        *lookupcache.LookupCache // Authentication cache (wraps database authentication calls)
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
	config             *config.Config // Full config reference for shared mailboxes

	// Metadata limits (RFC 5464)
	metadataMaxEntrySize         int
	metadataMaxEntriesPerMailbox int
	metadataMaxEntriesPerServer  int
	metadataMaxTotalSize         int

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection tracking
	connTracker *serverPkg.ConnectionTracker

	// Connection limiting
	limiter *serverPkg.ConnectionLimiter

	// Listen backlog
	listenBacklog int

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
	warmupInterval     time.Duration // Minimum time between warmups for same user
	lastWarmupTimes    sync.Map      // map[int64]time.Time - tracks last warmup time per user

	// Client capability filtering
	capFilters []ClientCapabilityFilter

	// Command timeout and throughput enforcement
	authIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	commandTimeout         time.Duration
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)

	// Active connection tracking for graceful shutdown
	activeConnsMutex sync.RWMutex
	activeConns      map[*imapserver.Conn]struct{}
	sessionsWg       sync.WaitGroup // Tracks active sessions for graceful drain
}

type IMAPServerOptions struct {
	Debug                       bool
	TLS                         bool
	TLSCertFile                 string
	TLSKeyFile                  string
	TLSVerify                   bool
	MasterUsername              []byte
	MasterPassword              []byte
	MasterSASLUsername          []byte
	MasterSASLPassword          []byte
	AppendLimit                 int64
	MaxConnections              int
	MaxConnectionsPerIP         int
	MaxConnectionsPerUser       int      // Maximum connections per user (0=unlimited) - used for local tracking on backends
	MaxConnectionsPerUserPerIP  int      // Maximum connections per user per IP (0=unlimited)
	ListenBacklog               int      // TCP listen backlog size (0 = use default 1024)
	ProxyProtocol               bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout        string   // Timeout for reading PROXY headers
	ProxyProtocolTrustedProxies []string // CIDR blocks for PROXY protocol validation (defaults to trusted_networks if empty)
	TrustedNetworks             []string // Global trusted networks for parameter forwarding
	AuthRateLimit               serverPkg.AuthRateLimiterConfig
	LookupCache                 *config.LookupCacheConfig // Authentication cache configuration
	SearchRateLimitPerMin       int                       // Search rate limit (searches per minute, 0=disabled)
	SearchRateLimitWindow       time.Duration             // Search rate limit time window
	SessionMemoryLimit          int64                     // Per-session memory limit in bytes (0=unlimited)
	// Cache warmup configuration
	EnableWarmup       bool
	WarmupMessageCount int
	WarmupMailboxes    []string
	WarmupAsync        bool
	WarmupTimeout      string
	WarmupInterval     string // Minimum time between warmups for same user (e.g., "1h", "30m")
	FTSRetention       time.Duration
	// Client capability filtering
	CapabilityFilters []config.ClientCapabilityFilter
	// Global capability disabling
	DisabledCaps []string
	// Version information
	Version string
	// Metadata limits (RFC 5464)
	MetadataMaxEntrySize         int
	MetadataMaxEntriesPerMailbox int
	MetadataMaxEntriesPerServer  int
	MetadataMaxTotalSize         int
	// Command timeout and throughput enforcement
	AuthIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	CommandTimeout         time.Duration // Maximum idle time before disconnection
	AbsoluteSessionTimeout time.Duration // Maximum total session duration (0 = use default 30m)
	MinBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = use default 512 bytes/min)
	// Full config for shared mailboxes and other features
	Config *config.Config
}

func New(appCtx context.Context, name, hostname, imapAddr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options IMAPServerOptions) (*IMAPServer, error) {
	logger.Debug("IMAP: Creating server", "name", name, "tls", options.TLS, "cert", options.TLSCertFile, "key", options.TLSKeyFile)
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
			TrustedProxies: getProxyProtocolTrustedProxies(options.ProxyProtocolTrustedProxies, options.TrustedNetworks),
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
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("IMAP", options.AuthRateLimit, options.TrustedNetworks)

	// Initialize search rate limiter
	searchRateLimiter := serverPkg.NewSearchRateLimiter("IMAP", options.SearchRateLimitPerMin, options.SearchRateLimitWindow)

	// Initialize authentication cache from config
	// Default to enabled if not explicitly configured
	var lookupCache *lookupcache.LookupCache
	lookupCacheConfig := options.LookupCache

	// If no config provided, use defaults and enable cache
	if lookupCacheConfig == nil {
		lookupCacheConfig = &config.LookupCacheConfig{
			Enabled:                    true,
			PositiveTTL:                "5m",
			NegativeTTL:                "1m",
			MaxSize:                    10000,
			CleanupInterval:            "5m",
			PositiveRevalidationWindow: "30s",
		}
	}

	// Only disable if explicitly set to false
	if !lookupCacheConfig.Enabled {
		logger.Info("IMAP: Lookup cache disabled", "name", name)
	} else {
		positiveTTL, err := time.ParseDuration(lookupCacheConfig.PositiveTTL)
		if err != nil || lookupCacheConfig.PositiveTTL == "" {
			logger.Info("IMAP: Using default positive TTL (5m)", "name", name)
			positiveTTL = 5 * time.Minute
		}

		negativeTTL, err := time.ParseDuration(lookupCacheConfig.NegativeTTL)
		if err != nil || lookupCacheConfig.NegativeTTL == "" {
			logger.Info("IMAP: Using default negative TTL (1m)", "name", name)
			negativeTTL = 1 * time.Minute
		}

		cleanupInterval, err := time.ParseDuration(lookupCacheConfig.CleanupInterval)
		if err != nil || lookupCacheConfig.CleanupInterval == "" {
			logger.Info("IMAP: Using default cleanup interval (5m)", "name", name)
			cleanupInterval = 5 * time.Minute
		}

		maxSize := lookupCacheConfig.MaxSize
		if maxSize == 0 {
			maxSize = 10000
		}

		positiveRevalidationWindow, err := lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("IMAP: Invalid positive revalidation window in auth cache config, using default (30s)", "name", name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("IMAP: Lookup cache enabled", "name", name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	// Parse warmup timeout with default fallback
	warmupTimeout := 5 * time.Minute // Default timeout
	if options.WarmupTimeout != "" {
		if parsed, err := helpers.ParseDuration(options.WarmupTimeout); err != nil {
			logger.Debug("IMAP: WARNING - invalid warmup_timeout, using default", "name", name, "value", options.WarmupTimeout, "error", err, "default", warmupTimeout)
		} else {
			warmupTimeout = parsed
		}
	}

	// Parse warmup interval with default fallback
	warmupInterval := 24 * time.Hour // Default: only warmup once per day per user
	if options.WarmupInterval != "" {
		if parsed, err := helpers.ParseDuration(options.WarmupInterval); err != nil {
			logger.Debug("IMAP: WARNING - invalid warmup_interval, using default", "name", name, "value", options.WarmupInterval, "error", err, "default", warmupInterval)
		} else {
			warmupInterval = parsed
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
		lookupCache:                  lookupCache,
		appendLimit:                  options.AppendLimit,
		ftsRetention:                 options.FTSRetention,
		version:                      options.Version,
		config:                       options.Config,
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
		warmupInterval:               warmupInterval,
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
		authIdleTimeout:        options.AuthIdleTimeout,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
		activeConns:            make(map[*imapserver.Conn]struct{}),
	}

	// Pre-compile regex patterns for capability filters for performance and correctness
	validFilters := make([]ClientCapabilityFilter, 0, len(options.CapabilityFilters))
	for _, configFilter := range options.CapabilityFilters {
		filter := ClientCapabilityFilter{ClientCapabilityFilter: configFilter}
		isValid := true

		if filter.ClientName != "" {
			re, err := regexp.Compile(filter.ClientName)
			if err != nil {
				logger.Debug("IMAP: WARNING - invalid client_name regex in capability filter, skipping", "name", name, "pattern", filter.ClientName, "error", err)
				isValid = false
			} else {
				filter.clientNameRegexp = re
			}
		}
		if filter.ClientVersion != "" && isValid {
			re, err := regexp.Compile(filter.ClientVersion)
			if err != nil {
				logger.Debug("IMAP: WARNING - invalid client_version regex in capability filter, skipping", "name", name, "pattern", filter.ClientVersion, "error", err)
				isValid = false
			} else {
				filter.clientVersionRegexp = re
			}
		}
		// Compile all JA4 fingerprint patterns
		if len(filter.JA4Fingerprints) > 0 && isValid {
			filter.ja4FingerprintRegexps = make([]*regexp.Regexp, 0, len(filter.JA4Fingerprints))
			for _, pattern := range filter.JA4Fingerprints {
				re, err := regexp.Compile(pattern)
				if err != nil {
					logger.Debug("IMAP: WARNING - invalid ja4_fingerprints regex in capability filter, skipping", "name", name, "pattern", pattern, "error", err)
					isValid = false
					break
				}
				filter.ja4FingerprintRegexps = append(filter.ja4FingerprintRegexps, re)
			}
		}

		// Only add the filter if all regex patterns are valid
		if isValid {
			validFilters = append(validFilters, filter)
		}
	}

	// Store the valid filters
	s.capFilters = validFilters

	// Remove globally disabled capabilities from the server
	if len(options.DisabledCaps) > 0 {
		for _, capStr := range options.DisabledCaps {
			cap := imap.Cap(capStr)
			if _, exists := s.caps[cap]; exists {
				delete(s.caps, cap)
				logger.Debug("IMAP: Disabled capability (global server setting)", "name", name, "capability", capStr)
			} else {
				logger.Debug("IMAP: WARNING - Cannot disable capability, not found in defaults", "name", name, "capability", capStr)
			}
		}
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

	// Set listen backlog with reasonable default
	s.listenBacklog = options.ListenBacklog
	if s.listenBacklog == 0 {
		s.listenBacklog = 1024 // Default backlog
	}

	if s.appendLimit > 0 {
		appendLimitCapName := imap.Cap(fmt.Sprintf("APPENDLIMIT=%d", s.appendLimit))
		s.caps[appendLimitCapName] = struct{}{}
		s.caps.Has(imap.CapAppendLimit)
	}

	// Enable ACL capability only if shared mailboxes are enabled
	if s.config != nil && s.config.SharedMailboxes.Enabled {
		s.caps[imap.CapACL] = struct{}{} // RFC 4314 - Access Control List
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		logger.Debug("IMAP: Loading TLS certificate", "name", name, "cert", options.TLSCertFile, "key", options.TLSKeyFile)
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		// Warn if the certificate chain is incomplete.
		if len(cert.Certificate) < 2 {
			logger.Debug("IMAP: WARNING - TLS certificate file contains only one certificate, should contain full chain", "name", name, "cert_file", options.TLSCertFile)
		}

		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
			NextProtos:               []string{"imap"},
			Renegotiation:            tls.RenegotiateNever,
		}

		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			logger.Debug("IMAP: WARNING - Client TLS certificate verification not enforced", "name", name)
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

	// Start active connections monitoring
	go s.monitorActiveConnections()

	// Initialize command timeout metrics
	if s.commandTimeout > 0 {
		metrics.CommandTimeoutThresholdSeconds.WithLabelValues("imap").Set(s.commandTimeout.Seconds())
	}

	// Initialize local connection tracking (no gossip, just local tracking)
	// This enables per-user connection limits and kick functionality on backend servers
	if options.MaxConnectionsPerUser > 0 {
		// Generate unique instance ID for this server instance
		instanceID := fmt.Sprintf("imap-%s-%d", name, time.Now().UnixNano())

		// Create ConnectionTracker with nil cluster manager (local mode only)
		s.connTracker = serverPkg.NewConnectionTracker(
			"IMAP",                             // protocol name
			instanceID,                         // unique instance identifier
			nil,                                // no cluster manager = local mode
			options.MaxConnectionsPerUser,      // per-user connection limit
			options.MaxConnectionsPerUserPerIP, // per-user-per-IP connection limit
			0,                                  // queue size (not used in local mode)
		)

		logger.Debug("IMAP: Local connection tracking enabled", "name", name, "max_per_user", options.MaxConnectionsPerUser)
	} else {
		// Connection tracking disabled (unlimited connections per user)
		s.connTracker = nil
		logger.Debug("IMAP: Local connection tracking disabled (not configured)", "name", name)
	}

	return s, nil
}

func (s *IMAPServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	// TLS handshake is now performed in connectionLimitingListener.Accept()
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

	// Extract underlying net.Conn for setting timeouts and proxy protocol handling
	netConn := conn.NetConn()

	// Set auth idle timeout if configured (applies during pre-auth phase only)
	if s.authIdleTimeout > 0 {
		if err := netConn.SetReadDeadline(time.Now().Add(s.authIdleTimeout)); err != nil {
			logger.Warn("IMAP: Failed to set auth idle timeout", "name", s.name, "error", err)
		}
	}

	// Initialize session with full server capabilities
	// These will be filtered in GetCapabilities() when JA4 fingerprint becomes available
	session.sessionCaps = make(imap.CapSet)
	for cap := range s.caps {
		session.sessionCaps[cap] = struct{}{}
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	// Need to unwrap connection layers to get to proxyProtocolConn
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
		logger.Debug("IMAP: Received JA4 fingerprint from PROXY v2 TLV", "name", s.name, "ja4", proxyJA4Fingerprint)
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
		// Apply filters to sessionCaps BEFORE greeting is sent
		session.applyCapabilityFilters()
	} else if ja4Conn != nil {
		// Try to perform TLS handshake explicitly if the method is available
		// (Some connection types may have already completed the handshake)
		if handshaker, ok := ja4Conn.(interface{ Handshake() error }); ok {
			if err := handshaker.Handshake(); err != nil {
				logger.Debug("IMAP: TLS handshake failed", "name", s.name, "error", err)
			} else {
				logger.Debug("IMAP: TLS handshake completed via explicit call", "name", s.name)
			}
		}

		// Always try to capture the fingerprint immediately, regardless of whether
		// we called Handshake() explicitly. The handshake may have already completed
		// during connection acceptance.
		fingerprint, err := ja4Conn.GetJA4Fingerprint()

		if err == nil && fingerprint != "" {
			session.ja4Fingerprint = fingerprint
			// Apply filters to sessionCaps BEFORE greeting is sent
			session.applyCapabilityFilters()
		} else {
			// Fingerprint not yet available - store ja4Conn for lazy capture
			// This should be rare since handshake typically completes during accept
			session.ja4Conn = ja4Conn
		}
	}

	clientIP, proxyIP := serverPkg.GetConnectionIPs(netConn, proxyInfo)
	session.RemoteIP = clientIP
	session.ProxyIP = proxyIP
	session.Protocol = "IMAP"
	session.ServerName = s.name
	session.Id = idgen.New()
	session.HostName = s.hostname
	session.Stats = s
	session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "IMAP", session.InfoLog)

	// Log connection at INFO level
	session.InfoLog("connected")

	greeting := &imapserver.GreetingData{
		PreAuth: false,
	}

	// Track active connection for graceful shutdown
	s.trackConnection(conn)

	// Track session in WaitGroup for graceful drain
	s.sessionsWg.Add(1)

	authCount := s.authenticatedConnections.Load()
	// Log proxy session ID if present for end-to-end tracing
	if proxyInfo != nil && proxyInfo.ProxySessionID != "" {
		logger.Debug("IMAP: Received proxy session ID from PROXY v2 TLV", "name", s.name, "session_id", proxyInfo.ProxySessionID)
		session.InfoLog("connected", "conn_total", totalCount, "conn_auth", authCount, "proxy_session", proxyInfo.ProxySessionID)
	} else {
		session.InfoLog("connected", "conn_total", totalCount, "conn_auth", authCount)
	}
	return session, greeting, nil
}

// trackConnection adds a connection to the active connections map
func (s *IMAPServer) trackConnection(conn *imapserver.Conn) {
	s.activeConnsMutex.Lock()
	defer s.activeConnsMutex.Unlock()
	s.activeConns[conn] = struct{}{}
}

// untrackConnection removes a connection from the active connections map
func (s *IMAPServer) untrackConnection(conn *imapserver.Conn) {
	s.activeConnsMutex.Lock()
	defer s.activeConnsMutex.Unlock()
	delete(s.activeConns, conn)
}

func (s *IMAPServer) Serve(imapAddr string) error {
	var listener net.Listener
	var err error

	// Configure SoraConn
	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "imap",
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send BYE message before closing due to timeout (RFC 3501 Section 7.1.5)
			// Using [UNAVAILABLE] response code helps clients recognize this as a normal
			// server condition rather than an error (RFC 5530 Section 3)
			var message string
			switch reason {
			case "idle":
				message = "* BYE [UNAVAILABLE] Idle timeout, please reconnect\r\n"
			case "slow_throughput":
				message = "* BYE [UNAVAILABLE] Connection too slow, please reconnect\r\n"
			case "session_max":
				message = "* BYE [UNAVAILABLE] Maximum session duration exceeded, please reconnect\r\n"
			default:
				message = "* BYE [UNAVAILABLE] Connection timeout, please reconnect\r\n"
			}
			// Write BYE - ignore errors as connection may already be broken
			// This is best-effort to inform the client
			_, _ = fmt.Fprint(conn, message)
		},
	}

	if s.tlsConfig != nil {
		// Create base TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", imapAddr, s.listenBacklog)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
		logger.Debug("IMAP: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		// Use SoraTLSListener for TLS with JA4 capture and timeout protection
		listener = serverPkg.NewSoraTLSListener(tcpListener, s.tlsConfig, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("IMAP server listening with TLS", "name", s.name, "addr", imapAddr, "ja4", true, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("IMAP server listening with TLS", "name", s.name, "addr", imapAddr, "ja4", true)
		}
	} else {
		// Create base TCP listener with custom backlog
		tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", imapAddr, s.listenBacklog)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		logger.Debug("IMAP: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

		// Use SoraListener for non-TLS with timeout protection
		listener = serverPkg.NewSoraListener(tcpListener, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("IMAP server listening", "name", s.name, "addr", imapAddr, "tls", false, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("IMAP server listening", "name", s.name, "addr", imapAddr, "tls", false)
		}
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

	// Wrap listener with connection limiting and rate limiting
	limitedListener := &connectionLimitingListener{
		Listener:    listener,
		limiter:     s.limiter,
		authLimiter: s.authLimiter,
		name:        s.name,
	}

	err = s.server.Serve(limitedListener)

	// Check if this was a graceful shutdown
	if s.appCtx.Err() != nil {
		logger.Info("IMAP server stopped gracefully", "name", s.name)
		return nil
	}

	return err
}

// SetConnTracker sets the connection tracker for this server
func (s *IMAPServer) SetConnTracker(tracker *serverPkg.ConnectionTracker) {
	s.connTracker = tracker
}

func (s *IMAPServer) Close() {
	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	if s.server != nil {
		// Step 1: Send graceful BYE messages to all active sessions
		s.sendGracefulShutdownBye()

		// Step 2: Close listener to stop accepting new connections
		// This will cause s.server.Serve(listener) to return
		s.server.Close()

		// Step 3: Wait for active sessions to finish gracefully (with timeout)
		s.waitForSessionsDrain(30 * time.Second)
	}
}

// waitForSessionsDrain waits for all active sessions to finish with a timeout
func (s *IMAPServer) waitForSessionsDrain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.sessionsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("IMAP: All sessions drained gracefully", "name", s.name)
	case <-time.After(timeout):
		logger.Debug("IMAP: Session drain timeout, forcing shutdown", "name", s.name, "timeout", timeout)
	}
}

// sendGracefulShutdownBye sends a BYE response with UNAVAILABLE code to all active sessions
// This informs clients that the server is shutting down and they should reconnect
func (s *IMAPServer) sendGracefulShutdownBye() {
	// Get snapshot of active connections
	s.activeConnsMutex.RLock()
	activeConns := make([]*imapserver.Conn, 0, len(s.activeConns))
	for conn := range s.activeConns {
		activeConns = append(activeConns, conn)
	}
	s.activeConnsMutex.RUnlock()

	if len(activeConns) == 0 {
		return
	}

	logger.Debug("IMAP: Sending graceful shutdown BYE to active connections", "name", s.name, "count", len(activeConns))

	// Send BYE to all active connections with timeout per connection
	// Use goroutines to send BYE messages in parallel to avoid blocking on stuck connections
	var wg sync.WaitGroup
	for _, conn := range activeConns {
		wg.Add(1)
		go func(c *imapserver.Conn) {
			defer wg.Done()
			// Create a timeout for sending BYE to prevent hanging on stuck connections
			done := make(chan struct{})
			go func() {
				// Send untagged BYE with text message
				// RFC 3501 Section 7.1.5: BYE response indicates the server is closing the connection
				if err := c.Bye("Server shutting down, please reconnect"); err != nil {
					logger.Debug("IMAP: Failed to send BYE", "name", s.name, "remote", server.GetAddrString(c.NetConn().RemoteAddr()), "error", err)
				}
				close(done)
			}()

			// Wait for BYE to be sent or timeout after 500ms
			select {
			case <-done:
				// BYE sent successfully
			case <-time.After(500 * time.Millisecond):
				logger.Debug("IMAP: Timeout sending BYE to connection", "name", s.name, "remote", server.GetAddrString(c.NetConn().RemoteAddr()))
			}
		}(conn)
	}

	// Wait for all BYE messages to be sent (or timeout) with overall timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Overall timeout of 2 seconds for all BYE messages
	select {
	case <-done:
		logger.Debug("IMAP: All BYE messages sent", "name", s.name)
	case <-time.After(2 * time.Second):
		logger.Debug("IMAP: Timeout waiting for all BYE messages", "name", s.name)
	}

	// Give clients a brief moment (200ms) to receive and process the BYE
	// Reduced from 1 second to speed up test cleanup
	time.Sleep(200 * time.Millisecond)

	logger.Debug("IMAP: Proceeding with connection cleanup", "name", s.name)
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
			logger.Debug("IMAP: No PROXY protocol header, treating as direct connection in optional mode", "remote", server.GetAddrString(conn.RemoteAddr()))
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic IMAP
		logger.Debug("IMAP: PROXY protocol error, rejecting connection", "remote", server.GetAddrString(conn.RemoteAddr()), "error", err)
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
// It only runs if enough time has passed since the last warmup for this user (controlled by warmupInterval)
func (s *IMAPServer) WarmupCache(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int, async bool) error {
	if messageCount <= 0 || len(mailboxNames) == 0 || s.cache == nil {
		return nil
	}

	// Check if enough time has passed since last warmup for this user
	now := time.Now()
	if lastWarmupRaw, ok := s.lastWarmupTimes.Load(AccountID); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		timeSinceLastWarmup := now.Sub(lastWarmup)
		if timeSinceLastWarmup < s.warmupInterval {
			logger.Debug("IMAP: Skipping cache warmup - too soon since last warmup", "name", s.name, "account_id", AccountID, "time_since_last", timeSinceLastWarmup.Round(time.Second), "min_interval", s.warmupInterval)
			return nil
		}
	}

	// Update last warmup time immediately to prevent concurrent warmups
	s.lastWarmupTimes.Store(AccountID, now)

	logger.Debug("IMAP: Starting cache warmup", "name", s.name, "account_id", AccountID, "message_count", messageCount, "mailboxes", mailboxNames, "async", async, "timeout", s.warmupTimeout, "interval", s.warmupInterval)

	warmupFunc := func() {
		// Add timeout to prevent runaway warmup operations
		warmupCtx, cancel := context.WithTimeout(ctx, s.warmupTimeout)
		defer cancel()
		// Get recent message content hashes from database through cache
		messageHashes, err := s.cache.GetRecentMessagesForWarmup(warmupCtx, AccountID, mailboxNames, messageCount)
		if err != nil {
			logger.Debug("IMAP: Failed to get recent messages for warmup", "name", s.name, "error", err)
			return
		}

		totalHashes := 0
		for mailbox, hashes := range messageHashes {
			totalHashes += len(hashes)
			logger.Debug("IMAP: Warmup found messages in mailbox", "name", s.name, "count", len(hashes), "mailbox", mailbox)
		}

		if totalHashes == 0 {
			logger.Debug("IMAP: No messages found for warmup", "name", s.name)
			return
		}

		// Get user's primary email for S3 key construction
		address, err := s.rdb.GetPrimaryEmailForAccountWithRetry(warmupCtx, AccountID)
		if err != nil {
			logger.Debug("IMAP: Warmup - failed to get primary address", "name", s.name, "account_id", AccountID, "error", err)
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
					logger.Debug("IMAP: Warmup cancelled", "name", s.name, "account_id", AccountID, "error", warmupCtx.Err())
					return
				default:
					// Continue processing
				}

				// Check if already in cache
				exists, err := s.cache.Exists(contentHash)
				if err != nil {
					logger.Debug("IMAP: Warmup - error checking existence", "name", s.name, "hash", contentHash, "error", err)
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
					logger.Debug("IMAP: Warmup - skipping, failed to fetch from S3", "name", s.name, "hash", contentHash, "error", fetchErr)
					skippedCount++
					continue
				}

				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					logger.Debug("IMAP: Warmup - skipping, failed to read from S3", "name", s.name, "hash", contentHash, "error", err)
					skippedCount++
					continue
				}

				// Store in cache
				err = s.cache.Put(contentHash, data)
				if err != nil {
					if errors.Is(err, cache.ErrObjectTooLarge) {
						logger.Debug("IMAP: Warmup - skipping, object too large for cache", "name", s.name, "hash", contentHash, "size", len(data))
						skippedCount++
					} else {
						logger.Debug("IMAP: Warmup - failed to cache content", "name", s.name, "hash", contentHash, "error", err)
					}
					continue
				}

				warmedCount++
			}
		}

		logger.Debug("IMAP: Warmup completed", "name", s.name, "account_id", AccountID, "cached", warmedCount, "skipped", skippedCount)
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
	logger.Debug("IMAP: Checking capability filters", "name", s.name, "filter_count", len(s.capFilters), "client_name", clientName, "client_version", clientVersion, "tls_fingerprint", tlsFingerprint)
	for i, filter := range s.capFilters {
		// Display JA4 patterns
		ja4Display := strings.Join(filter.JA4Fingerprints, ", ")
		logger.Debug("IMAP: Capability filter details", "name", s.name, "filter_index", i, "client_name", filter.ClientName, "client_version", filter.ClientVersion, "ja4_fingerprints", ja4Display, "disable_caps", filter.DisableCaps)
		if s.clientMatches(clientName, clientVersion, tlsFingerprint, filter) {
			logger.Debug("IMAP: Applying capability filter", "name", s.name, "reason", filter.Reason, "client_name", clientName, "client_version", clientVersion, "ja4", tlsFingerprint)

			// Disable specified capabilities
			for _, capStr := range filter.DisableCaps {
				cap := imap.Cap(capStr)
				if _, exists := sessionCaps[cap]; exists {
					delete(sessionCaps, cap)
					disabledCaps = append(disabledCaps, capStr)
					logger.Debug("IMAP: Disabled capability", "name", s.name, "capability", cap, "reason", filter.Reason)
				}
			}
		}
	}

	return disabledCaps
}

// clientMatches checks if a client matches the filter criteria
// A filter matches if ANY of the following are true:
// 1. JA4 fingerprint matches (if specified in filter) - matches if ANY pattern matches
// 2. Client name/version match (if specified in filter)
func (s *IMAPServer) clientMatches(clientName, clientVersion, tlsFingerprint string, filter ClientCapabilityFilter) bool {
	// Check if JA4 fingerprint matches any of the patterns (if filter specifies them)
	if len(filter.ja4FingerprintRegexps) > 0 && tlsFingerprint != "" {
		for _, ja4Regexp := range filter.ja4FingerprintRegexps {
			if ja4Regexp.MatchString(tlsFingerprint) {
				// JA4 match is sufficient - return true immediately
				return true
			}
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

// monitorActiveConnections periodically logs active connection count for monitoring
func (s *IMAPServer) monitorActiveConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.activeConnsMutex.RLock()
			count := len(s.activeConns)
			s.activeConnsMutex.RUnlock()

			// Also log connection limiter stats
			var limiterStats string
			if s.limiter != nil {
				stats := s.limiter.GetStats()
				limiterStats = fmt.Sprintf(" limiter_total=%d limiter_max=%d", stats.TotalConnections, stats.MaxConnections)
			}

			logger.Info("IMAP server active connections", "name", s.name, "active_connections", count, "limiter_stats", limiterStats)

		case <-s.appCtx.Done():
			return
		}
	}
}

// GetLimiter returns the connection limiter for testing purposes
func (s *IMAPServer) GetLimiter() *serverPkg.ConnectionLimiter {
	return s.limiter
}

// GetLookupCache returns the lookup cache for testing purposes
func (s *IMAPServer) GetLookupCache() *lookupcache.LookupCache {
	return s.lookupCache
}

// Authenticate authenticates a user with caching support.
// This method wraps the database authentication with an optional lookup cache layer.
// The cache decorates the database call - this is the proper architectural pattern.
func (s *IMAPServer) Authenticate(ctx context.Context, address, password string) (accountID int64, err error) {
	// Check context before any work
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	// Check cache first if enabled
	if s.lookupCache != nil {
		cachedAccountID, found, cacheErr := s.lookupCache.Authenticate(address, password)
		if cacheErr != nil {
			// Cached authentication failure - return immediately without querying database
			logger.Debug("Authentication failed (cached)", "address", address, "cache", "hit")
			return 0, cacheErr
		}
		if found {
			// Cache hit with successful authentication - but check context is still valid
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			logger.Info("authentication successful", "address", address, "account_id", cachedAccountID, "cached", true, "method", "cache")
			return cachedAccountID, nil
		}
		// Cache miss - continue to database
		logger.Debug("Authentication: cache miss, checking database", "address", address)
	}

	// Fetch credentials from database (no caching - we handle that here)
	accountID, hashedPassword, err := s.rdb.GetCredentialForAuthWithRetry(ctx, address)
	if err != nil {
		// Cache negative result if enabled (user not found)
		if s.lookupCache != nil {
			// AuthUserNotFound = 1 (from lookupcache package)
			s.lookupCache.SetFailure(address, 1, password)
		}
		logger.Info("authentication failed", "address", address, "reason", "user_not_found", "cached", false, "method", "main_db")
		return 0, err
	}

	// Verify password
	if err := db.VerifyPassword(hashedPassword, password); err != nil {
		// Cache negative result for invalid password if enabled
		if s.lookupCache != nil {
			// AuthInvalidPassword = 2 (from lookupcache package)
			s.lookupCache.SetFailure(address, 2, password)
		}
		logger.Info("authentication failed", "address", address, "reason", "invalid_password", "cached", false, "method", "main_db")
		return 0, err
	}

	// Cache successful authentication if enabled
	if s.lookupCache != nil {
		s.lookupCache.SetSuccess(address, accountID, hashedPassword, password)
	}

	logger.Info("authentication successful", "address", address, "account_id", accountID, "cached", false, "method", "main_db")

	// Asynchronously rehash if needed
	if db.NeedsRehash(hashedPassword) {
		go func() {
			newHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if hashErr != nil {
				logger.Error("Rehash: Failed to generate new hash", "address", address, "error", hashErr)
				return
			}

			// If it's a BLF-CRYPT format, preserve the prefix
			var newHashedPassword string
			if strings.HasPrefix(hashedPassword, "{BLF-CRYPT}") {
				newHashedPassword = "{BLF-CRYPT}" + string(newHash)
			} else {
				newHashedPassword = string(newHash)
			}

			// Use a new context for this background task
			updateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Update password in database
			if err := s.rdb.UpdatePasswordWithRetry(updateCtx, address, newHashedPassword); err != nil {
				logger.Error("Rehash: Failed to update password", "address", address, "error", err)
			} else {
				logger.Info("Rehash: Successfully rehashed and updated password", "address", address)
				// Invalidate cache entry since password hash changed
				if s.lookupCache != nil {
					s.lookupCache.Invalidate(address)
				}
			}
		}()
	}

	return accountID, nil
}
