package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

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
	masterUsername     []byte
	masterPassword     []byte
	masterSASLUsername []byte
	masterSASLPassword []byte
	masterSASLGate     *serverPkg.MasterSASLNetworkGate

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64

	// Connection limiting
	limiter *serverPkg.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// PROXY protocol support
	proxyReader *serverPkg.ProxyProtocolReader

	// Authentication rate limiting
	authLimiter serverPkg.AuthLimiter

	// Authentication cache (wraps rdb authentication calls)
	lookupCache *lookupcache.LookupCache

	// XCLIENT is always enabled but limited to trusted networks
	trustedNetworks []string

	// Auth security
	insecureAuth bool // Allow PLAIN auth over non-TLS connections

	// Memory limiting
	sessionMemoryLimit int64

	// Command timeout and throughput enforcement
	authIdleTimeout        time.Duration // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	commandTimeout         time.Duration // Idle timeout (defaulted to Pop3DefaultIdleTimeout when unset)
	libCommandTimeout      time.Duration // Per-command execution timeout passed to the library (raw config value, 0 = disabled)
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)
	maxMessageAge          time.Duration // Ephemeral-storage retention (cleanup max_age_restriction); 0 = keep forever. Drives the CAPA EXPIRE value.

	// Connection tracking
	connTracker *serverPkg.ConnectionTracker

	// Startup throttle to prevent thundering herd on restart
	startupThrottleUntil time.Time

	// Active session tracking for graceful shutdown
	activeSessionsMutex sync.RWMutex
	activeSessions      map[*POP3Session]struct{}
	sessionsWg          sync.WaitGroup // Tracks active sessions for graceful drain

	// The library server is rebuilt (for new connections only) when runtime
	// settings change on SIGHUP; existing connections keep their snapshot.
	pop3libServer atomic.Pointer[pop3server.Server]
}

type POP3ServerOptions struct {
	Debug                       bool
	TLS                         bool
	TLSCertFile                 string
	TLSKeyFile                  string
	TLSVerify                   bool
	MasterUsername              string
	MasterPassword              string
	MasterSASLUsername          string
	MasterSASLPassword          string
	MasterSASLAllowedNetworks   []string // Source networks allowed to use master SASL (empty = any, anchored to real socket peer)
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
	SessionMemoryLimit          int64                     // Memory limit per session in bytes
	AuthIdleTimeout             time.Duration             // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	CommandTimeout              time.Duration             // Maximum idle time before disconnection
	AbsoluteSessionTimeout      time.Duration             // Maximum total session duration (0 = use default 30m)
	MinBytesPerMinute           int64                     // Minimum throughput to prevent slowloris (0 = use default 512 bytes/min)
	InsecureAuth                bool                      // Allow PLAIN auth over non-TLS connections (default: true for backends behind proxy)
	Config                      *config.Config            // Full config for shared settings like connection tracking timeouts
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
			TrustedProxies: getProxyProtocolTrustedProxies(options.ProxyProtocolTrustedProxies, options.TrustedNetworks),
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
	authLimiter := serverPkg.NewAuthRateLimiterWithTrustedNetworks("POP3", name, hostname, options.AuthRateLimit, options.TrustedNetworks)
	serverPkg.RegisterRateLimiter("pop3", name, authLimiter)

	// Initialize the master SASL network gate. Fail closed on a misconfigured
	// allow-list rather than silently disabling the gate.
	masterSASLGate, err := serverPkg.NewMasterSASLNetworkGate(options.MasterSASLAllowedNetworks)
	if err != nil {
		serverCancel()
		return nil, fmt.Errorf("invalid master_sasl_allowed_networks: %w", err)
	}
	if len(options.MasterSASLPassword) > 0 && !masterSASLGate.Enabled() {
		logger.Warn("POP3: master SASL enabled without master_sasl_allowed_networks; backend trusts any source that knows the secret. Restrict backend ports to proxy hosts or set master_sasl_allowed_networks.", "name", name)
	}

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
		logger.Info("POP3: Lookup cache disabled", "name", name)
	} else {
		positiveTTL, err := time.ParseDuration(lookupCacheConfig.PositiveTTL)
		if err != nil || lookupCacheConfig.PositiveTTL == "" {
			logger.Info("POP3: Using default positive TTL (5m)", "name", name)
			positiveTTL = 5 * time.Minute
		}

		negativeTTL, err := time.ParseDuration(lookupCacheConfig.NegativeTTL)
		if err != nil || lookupCacheConfig.NegativeTTL == "" {
			logger.Info("POP3: Using default negative TTL (1m)", "name", name)
			negativeTTL = 1 * time.Minute
		}

		cleanupInterval, err := time.ParseDuration(lookupCacheConfig.CleanupInterval)
		if err != nil || lookupCacheConfig.CleanupInterval == "" {
			logger.Info("POP3: Using default cleanup interval (5m)", "name", name)
			cleanupInterval = 5 * time.Minute
		}

		maxSize := lookupCacheConfig.MaxSize
		if maxSize == 0 {
			maxSize = 10000
		}

		positiveRevalidationWindow, err := lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("POP3: Invalid positive revalidation window in auth cache config, using default (30s)", "name", name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("POP3: Lookup cache enabled", "name", name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	// Apply default idle timeout if not configured (RFC 1939 §3: at least 10 minutes)
	commandTimeout := options.CommandTimeout
	if commandTimeout == 0 {
		commandTimeout = Pop3DefaultIdleTimeout
		logger.Info("POP3: Using default idle timeout (RFC 1939 §3)", "name", name, "timeout", commandTimeout)
	}

	// Ephemeral-storage retention drives the CAPA EXPIRE value (RFC 2449 §5.1);
	// 0 means messages are kept forever (EXPIRE NEVER).
	var maxMessageAge time.Duration
	if options.Config != nil {
		maxMessageAge = options.Config.Cleanup.GetMaxAgeRestrictionWithDefault()
	}

	// Cleartext auth is auto-enabled when TLS is not configured (the common
	// backend-behind-a-TLS-terminating-proxy deployment). That coupling is a
	// silent security downgrade if the listener is actually public, so make the
	// implicit decision visible at startup. (review: insecureAuth auto-enable)
	insecureAuth := options.InsecureAuth || !options.TLS
	if !options.InsecureAuth && !options.TLS {
		logger.Warn("POP3: TLS not configured; cleartext authentication auto-enabled. Acceptable only behind a TLS-terminating proxy or on trusted networks.", "name", name)
	}

	server := &POP3Server{
		hostname:               hostname,
		name:                   name,
		addr:                   popAddr,
		rdb:                    rdb,
		s3:                     resilientS3,
		appCtx:                 serverCtx,
		cancel:                 serverCancel,
		uploader:               uploadWorker,
		cache:                  cache,
		masterUsername:         []byte(options.MasterUsername),
		masterPassword:         []byte(options.MasterPassword),
		masterSASLUsername:     []byte(options.MasterSASLUsername),
		masterSASLPassword:     []byte(options.MasterSASLPassword),
		masterSASLGate:         masterSASLGate,
		proxyReader:            proxyReader,
		authLimiter:            authLimiter,
		lookupCache:            lookupCache,
		trustedNetworks:        options.TrustedNetworks,
		sessionMemoryLimit:     options.SessionMemoryLimit,
		authIdleTimeout:        options.AuthIdleTimeout,
		commandTimeout:         commandTimeout,
		libCommandTimeout:      options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		insecureAuth:           insecureAuth, // Auto-enabled when TLS not configured (warned above)
		minBytesPerMinute:      options.MinBytesPerMinute,
		maxMessageAge:          maxMessageAge,
		activeSessions:         make(map[*POP3Session]struct{}),
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

	// Set listen backlog with reasonable default
	server.listenBacklog = options.ListenBacklog
	if server.listenBacklog == 0 {
		server.listenBacklog = 1024 // Default backlog
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
			NextProtos:               []string{"pop3"},
			Renegotiation:            tls.RenegotiateNever,
		}

		// Set InsecureSkipVerify if requested (for self-signed certificates)
		// This setting on the server listener is intended to control client certificate
		// verification, which is now explicitly disabled via `ClientAuth: tls.NoClientCert`.
		if !options.TLSVerify {
			// The InsecureSkipVerify field is for client-side verification, so it's not set here.
			logger.Debug("POP3: WARNING - TLS certificate verification not enforced", "name", name)
		}
	}

	// Start connection limiter cleanup
	server.limiter.StartCleanup(serverCtx)

	// Initialize command timeout metrics
	if server.commandTimeout > 0 {
		metrics.CommandTimeoutThresholdSeconds.WithLabelValues("pop3").Set(server.commandTimeout.Seconds())
	}

	// Initialize local connection tracking (no gossip, just local tracking)
	// This enables per-user connection limits and kick functionality on backend servers
	if options.MaxConnectionsPerUser > 0 {
		// Generate unique instance ID for this server instance
		instanceID := fmt.Sprintf("pop3-%s-%d", name, time.Now().UnixNano())

		// Create ConnectionTracker with nil cluster manager (local mode only)
		server.connTracker = serverPkg.NewConnectionTracker(
			"POP3",                             // protocol name
			name,                               // server name
			hostname,                           // hostname
			instanceID,                         // unique instance identifier
			nil,                                // no cluster manager = local mode
			options.MaxConnectionsPerUser,      // per-user connection limit
			options.MaxConnectionsPerUserPerIP, // per-user-per-IP connection limit
			0,                                  // queue size (not used in local mode)
			false,                              // snapshot-only mode (not used in local mode)
		)

		logger.Debug("POP3: Local connection tracking enabled", "name", name, "max", options.MaxConnectionsPerUser)
	} else {
		// Connection tracking disabled (unlimited connections per user)
		server.connTracker = nil
		logger.Debug("POP3: Local connection tracking disabled", "name", name)
	}

	server.pop3libServer.Store(server.buildLibServer())

	return server, nil
}

// knownCommands is the closed set of POP3 verbs used as Prometheus label
// values; anything else is recorded as "UNKNOWN" to keep cardinality bounded.
var knownCommands = map[string]bool{
	"USER": true, "PASS": true, "APOP": true, "AUTH": true, "CAPA": true,
	"STLS": true, "STAT": true, "LIST": true, "UIDL": true, "RETR": true,
	"TOP": true, "DELE": true, "NOOP": true, "RSET": true, "QUIT": true,
	"UTF8": true, "LANG": true, "LAST": true, "XCLIENT": true,
}

// buildLibServer constructs the go-pop3 protocol server from the current
// runtime settings. It is called at startup and again from ReloadConfig so
// SIGHUP-reloaded timeouts apply to new connections (existing connections keep
// the snapshot they were accepted with).
func (s *POP3Server) buildLibServer() *pop3server.Server {
	// Build custom capabilities based on config. Ephemeral-storage retention
	// drives the CAPA EXPIRE value (RFC 2449 §5.1).
	var caps []pop3.Capability
	if s.maxMessageAge <= 0 {
		caps = append(caps, pop3.Capability{Name: "EXPIRE", Params: []string{"NEVER"}})
	} else {
		caps = append(caps, pop3.Capability{Name: "EXPIRE", Params: []string{strconv.Itoa(int(s.maxMessageAge.Hours() / 24))}})
	}
	caps = append(caps, pop3.Capability{Name: "AUTH-RESP-CODE"})
	caps = append(caps, pop3.Capability{Name: "IMPLEMENTATION", Params: []string{"Sora-POP3-Server"}})

	opts := pop3server.Options{
		TLSConfig:              s.tlsConfig,
		IdleTimeout:            s.commandTimeout,
		AuthIdleTimeout:        s.authIdleTimeout,
		AbsoluteSessionTimeout: s.absoluteSessionTimeout,
		CommandTimeout:         s.libCommandTimeout,
		InsecureAuth:           s.insecureAuth,
		MaxLineLength:          Pop3MaxLineLength,
		MaxErrors:              Pop3MaxErrorsAllowed,
		ErrorDelay:             Pop3ErrorDelay,
		StrictSessionErrors:    true, // Session errors are *pop3server.Error; mask anything else (DB/S3 text must not reach clients)
		Caps:                   caps,
		Greeting:               "Sora-POP3-Server ready",
		NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
			// Connection limiting check
			netConn := c.NetConn()
			proxyInfo := serverPkg.GetProxyProtocolInfo(netConn)

			clientIP, proxyIP := serverPkg.GetConnectionIPs(netConn, proxyInfo)

			// Limiter checks. DELIBERATE silent close, no banner: matches the
			// previous accept-loop rejection (drop before any greeting), and
			// an "-ERR too many connections" banner would tell a flooder
			// exactly when the limiter engages so they can pace under it.
			// Test-enforced (connection-limit tests assert the rejected
			// socket never sees "+OK") — do not add a banner.
			releaseConn, err := s.limiter.AcceptWithRealIP(netConn.RemoteAddr(), clientIP)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", pop3server.ErrSilentReject, err)
			}

			// Implicit-TLS listeners (SoraTLSListener) defer the TLS handshake
			// so a PROXY header can be read in plaintext first; the library
			// never triggers it, so complete it here — after the limiter
			// (rejected peers never cost a handshake) and before the greeting
			// is written. This also captures JA4 and registers the connection
			// timeout checker for TLS connections.
			if didTLS, err := serverPkg.PerformDeferredTLSHandshake(netConn); err != nil {
				releaseConn()
				logger.Debug("POP3: TLS handshake failed", "name", s.name, "remote", serverPkg.GetAddrString(netConn.RemoteAddr()), "error", err)
				return nil, fmt.Errorf("%w: TLS handshake: %w", pop3server.ErrSilentReject, err)
			} else if didTLS {
				c.SetTLS(true)
			}

			// Count the connection only once it is past every rejection point,
			// so the decrements in the session close path always balance.
			s.totalConnections.Add(1)
			metrics.ConnectionsTotal.WithLabelValues("pop3", s.name, s.hostname).Inc()
			metrics.ConnectionsCurrent.WithLabelValues("pop3", s.name, s.hostname).Inc()

			sessionCtx, sessionCancel := context.WithCancel(s.appCtx)
			memTracker := serverPkg.NewSessionMemoryTracker(s.sessionMemoryLimit)

			session := &POP3Session{
				server:      s,
				conn:        netConn,
				deleted:     make(map[int]bool),
				ctx:         sessionCtx,
				cancel:      sessionCancel,
				language:    "en",
				releaseConn: releaseConn,
				startTime:   time.Now(),
				memTracker:  memTracker,
			}
			session.RemoteIP = clientIP
			session.ProxyIP = proxyIP
			session.Protocol = "POP3"
			session.ServerName = s.name
			session.Id = idgen.New()
			session.HostName = s.hostname
			session.Stats = s
			session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "POP3", session.InfoLog)

			session.InfoLog("connected")
			s.addSession(session)

			return session, nil
		},
		UnknownCommandHandler: func(ctx context.Context, c *pop3server.Conn, cmd string, args []string) (handled, close bool) {
			if cmd != "XCLIENT" {
				return false, false
			}
			session, ok := c.Session().(*POP3Session)
			if !ok {
				return false, false
			}
			// XCLIENT command for Dovecot-style parameter forwarding
			if session.authenticated.Load() {
				c.Err("[AUTH] XCLIENT not allowed after authentication")
				return true, true
			}
			if session.xclientApplied {
				c.Err("[AUTH] XCLIENT already provided")
				return true, true
			}

			ok, msg := session.handleXCLIENT(strings.Join(args, " "))
			if ok {
				session.xclientApplied = true
				c.OK(msg)
			} else {
				c.Err(msg)
			}
			return true, false
		},
		OnCommand: func(cmd string, dur time.Duration, err error) {
			// The verb comes straight off the client line; bound the metric
			// label set to known commands so clients cannot mint unbounded
			// Prometheus label values.
			if !knownCommands[cmd] {
				cmd = "UNKNOWN"
			}
			status := "success"
			if err != nil {
				status = "failure"
			}
			metrics.CommandsTotal.WithLabelValues("pop3", cmd, status).Inc()
			metrics.CommandDuration.WithLabelValues("pop3", cmd).Observe(dur.Seconds())
		},
	}

	return pop3server.New(opts)
}

func (s *POP3Server) Start(errChan chan error) {
	var listener net.Listener

	// Configure SoraConn with timeout protection
	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "pop3",
		ServerName:           s.name,
		Hostname:             s.hostname,
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0 || s.minBytesPerMinute > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send POP3 error message before closing due to timeout
			// RFC 1939 doesn't define specific timeout response codes, but [IN-USE] is commonly used
			var message string
			switch reason {
			case "idle":
				message = "-ERR [IN-USE] Idle timeout, please reconnect\r\n"
			case "slow_throughput":
				message = "-ERR [IN-USE] Connection too slow, please reconnect\r\n"
			case "session_max":
				message = "-ERR [IN-USE] Maximum session duration exceeded, please reconnect\r\n"
			default:
				message = "-ERR [IN-USE] Connection timeout, please reconnect\r\n"
			}
			// Write error message - ignore errors as connection may already be broken
			// This is best-effort to inform the client
			_, _ = fmt.Fprint(conn, message)
		},
	}

	// Create base TCP listener with custom backlog
	tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
	if err != nil {
		s.cancel()
		errChan <- fmt.Errorf("failed to create TCP listener: %w", err)
		return
	}
	logger.Debug("POP3: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

	// The PROXY protocol header travels in plaintext AHEAD of the TLS
	// ClientHello, so the header reader must sit between the TCP socket and
	// the TLS layer: the header is read from the raw stream, and the deferred
	// TLS handshake then reads THROUGH the PROXY conn, consuming any
	// ClientHello bytes its bufio buffered alongside the header. Wrapping in
	// the other order makes the handshake read the raw socket and miss those
	// bytes (broken PROXY+TLS combo).
	base := serverPkg.WrapProxyProtocol(tcpListener, s.proxyReader, "POP3")

	if s.tlsConfig != nil {
		// Use SoraTLSListener for TLS with timeout protection
		listener = serverPkg.NewSoraTLSListener(base, s.tlsConfig, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("POP3 server listening with TLS", "name", s.name, "addr", s.addr, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("POP3 server listening with TLS", "name", s.name, "addr", s.addr)
		}
	} else {
		// Use SoraListener for non-TLS with timeout protection
		listener = serverPkg.NewSoraListener(base, connConfig)
		if connConfig.EnableTimeoutChecker {
			logger.Info("POP3 server listening", "name", s.name, "addr", s.addr, "tls", false, "idle_timeout", s.commandTimeout, "session_max", s.absoluteSessionTimeout, "min_throughput", s.minBytesPerMinute)
		} else {
			logger.Info("POP3 server listening", "name", s.name, "addr", s.addr, "tls", false)
		}
	}
	defer listener.Close()

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		logger.Debug("POP3: stopping", "name", s.name)
		listener.Close()
	}()

	// Start session monitoring routine
	go s.monitorActiveSessions()

	// Set startup throttle for 30 seconds
	s.startupThrottleUntil = time.Now().Add(30 * time.Second)
	logger.Info("POP3: Startup throttle active for 30s", "name", s.name)

	for {
		// Startup throttle: spread reconnection load after server restart
		if !s.startupThrottleUntil.IsZero() && time.Now().Before(s.startupThrottleUntil) {
			time.Sleep(5 * time.Millisecond) // ~200 new connections/second during startup
		}

		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed (graceful shutdown)
			select {
			case <-s.appCtx.Done():
				logger.Info("POP3 server stopped gracefully", "name", s.name)
				return
			default:
				// For other errors, this might be a fatal server error
				errChan <- err
				return
			}
		}

		// Connection counters are incremented in NewSession once the
		// connection is past the limiter and TLS handshake, so rejected
		// connections never inflate the gauges (they have no session to
		// decrement them).

		s.sessionsWg.Add(1)
		go func() {
			defer s.sessionsWg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("POP3: panic in connection handler", "panic", r, "stack", string(debug.Stack()))
				}
			}()
			s.pop3libServer.Load().ServeConn(conn)
		}()
	}
}

// SetConnTracker sets the connection tracker for this server
func (s *POP3Server) SetConnTracker(tracker *serverPkg.ConnectionTracker) {
	s.connTracker = tracker
}

func (s *POP3Server) Close() {
	// Unregister rate limiter from global registry
	serverPkg.UnregisterRateLimiter("pop3", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Step 1: Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	// Step 2: Cancel context to signal sessions to finish
	// This will propagate to all session contexts
	if s.cancel != nil {
		s.cancel()
	}

	// Also cancel the library-side connection contexts so in-flight
	// per-command work (DB/S3 calls, error delays) aborts instead of running
	// to its own timeout. Sessions accepted under a pre-SIGHUP snapshot are
	// not covered here, but the shutdown broadcast above already closed their
	// sockets.
	if lib := s.pop3libServer.Load(); lib != nil {
		lib.Close()
	}

	// Step 3: Wait for active sessions to finish gracefully (with timeout)
	s.waitForSessionsDrain(30 * time.Second)
}

// waitForSessionsDrain waits for all active sessions to finish with a timeout
func (s *POP3Server) waitForSessionsDrain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.sessionsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("POP3: All sessions drained gracefully", "name", s.name)
	case <-time.After(timeout):
		logger.Debug("POP3: Session drain timeout, forcing shutdown", "name", s.name, "timeout", timeout)
	}
}

// addSession tracks an active session for graceful shutdown
func (s *POP3Server) addSession(session *POP3Session) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *POP3Server) removeSession(session *POP3Session) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a graceful shutdown notice to all active sessions
func (s *POP3Server) sendGracefulShutdownMessage() {
	s.activeSessionsMutex.RLock()
	activeSessions := make([]*POP3Session, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMutex.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("POP3: Sending graceful shutdown message to active connections", "name", s.name, "count", len(activeSessions))

	// Send shutdown message to all active connections
	for _, session := range activeSessions {
		if session.conn != nil {
			writer := bufio.NewWriter(session.conn)
			// POP3 doesn't have a specific "server shutting down" response code
			// But we can send a polite message before disconnection
			writer.WriteString("-ERR Server shutting down, please reconnect\r\n")
			writer.Flush()
		}
	}

	// Give clients a brief moment (1 second) to receive the message
	time.Sleep(1 * time.Second)

	// Close connections to unblock any sessions blocked on reads
	for _, session := range activeSessions {
		if session.conn != nil {
			session.conn.Close()
		}
	}

	logger.Debug("POP3: Proceeding with connection cleanup", "name", s.name)
}

// GetTotalConnections returns the current total connection count
func (s *POP3Server) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *POP3Server) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}

// monitorActiveSessions periodically logs active session count for monitoring
func (s *POP3Server) monitorActiveSessions() {
	// Log every 5 minutes (similar to connection tracker cleanup interval)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.activeSessionsMutex.RLock()
			count := len(s.activeSessions)
			s.activeSessionsMutex.RUnlock()

			// Also log connection limiter stats
			var limiterStats string
			if s.limiter != nil {
				stats := s.limiter.GetStats()
				limiterStats = fmt.Sprintf(" limiter_total=%d limiter_max=%d", stats.TotalConnections, stats.MaxConnections)
			}
			logger.Info("POP3 server active sessions", "name", s.name, "active_sessions", count, "limiter_stats", limiterStats)

		case <-s.appCtx.Done():
			return
		}
	}
}

// GetLimiter returns the connection limiter for testing purposes
func (s *POP3Server) GetLimiter() *serverPkg.ConnectionLimiter {
	return s.limiter
}

// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new connections; existing sessions keep old settings.
func (s *POP3Server) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string

	if timeout, err := cfg.GetCommandTimeout(); err == nil && timeout != s.libCommandTimeout {
		// Mirror construction: the raw value feeds the per-command execution
		// timeout (0 = disabled) while the idle timeout keeps the RFC 1939 §3
		// 10-minute floor.
		s.libCommandTimeout = timeout
		if timeout == 0 {
			timeout = Pop3DefaultIdleTimeout
		}
		s.commandTimeout = timeout
		reloaded = append(reloaded, "command_timeout")
	}
	if timeout, err := cfg.GetAbsoluteSessionTimeout(); err == nil && timeout != s.absoluteSessionTimeout {
		s.absoluteSessionTimeout = timeout
		reloaded = append(reloaded, "absolute_session_timeout")
	}
	if bpm := cfg.GetMinBytesPerMinute(); bpm != s.minBytesPerMinute {
		s.minBytesPerMinute = bpm
		reloaded = append(reloaded, "min_bytes_per_minute")
	}
	if limit, err := cfg.GetSessionMemoryLimit(); err == nil && limit != s.sessionMemoryLimit {
		s.sessionMemoryLimit = limit
		reloaded = append(reloaded, "session_memory_limit")
	}
	if cfg.MasterSASLUsername != string(s.masterSASLUsername) {
		s.masterSASLUsername = []byte(cfg.MasterSASLUsername)
		reloaded = append(reloaded, "master_sasl_username")
	}
	if cfg.MasterSASLPassword != string(s.masterSASLPassword) {
		s.masterSASLPassword = []byte(cfg.MasterSASLPassword)
		reloaded = append(reloaded, "master_sasl_password")
	}
	if gate, err := serverPkg.NewMasterSASLNetworkGate(cfg.MasterSASLAllowedNetworks); err != nil {
		logger.Warn("POP3 config reload: invalid master_sasl_allowed_networks, keeping previous gate", "name", s.name, "error", err)
	} else if !s.masterSASLGate.Equal(gate) {
		s.masterSASLGate = gate
		reloaded = append(reloaded, "master_sasl_allowed_networks")
	}

	if len(reloaded) > 0 {
		// Rebuild the protocol server so new connections pick up the reloaded
		// settings; existing connections keep the snapshot they started with.
		s.pop3libServer.Store(s.buildLibServer())
		logger.Info("POP3 config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

// GetLookupCache returns the lookup cache for testing purposes
func (s *POP3Server) GetLookupCache() *lookupcache.LookupCache {
	return s.lookupCache
}

// Authenticate authenticates a user with caching support.
// This method wraps the database authentication with an optional lookup cache layer.
// The cache decorates the database call - this is the proper architectural pattern.
func (s *POP3Server) Authenticate(ctx context.Context, address, password string) (accountID int64, err error) {
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
		// Equalize response timing with the wrong-password path (which runs bcrypt) so an
		// attacker can't use response time to tell whether the account exists. (security-audit M14)
		if errors.Is(err, consts.ErrUserNotFound) {
			db.DummyVerifyPassword(password)
		}
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
		db.QueueRehash(address, func(updateCtx context.Context) {
			newHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), db.BcryptCost)
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
		})
	}

	return accountID, nil
}
