package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	msieve "github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesieveserver"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/sieveengine"
	"golang.org/x/crypto/bcrypt"
)

// Re-exports of the SIEVE extension vocabulary, which moved to the
// go-managesieve library with the protocol extraction. Kept as package-level
// names for the ManageSieve proxy and the tests that reference them.
var (
	SupportedExtensions      = msieve.SupportedExtensions
	DefaultEnabledExtensions = msieve.DefaultEnabledExtensions
	FilterExtensions         = msieve.FilterExtensions
	GetSieveCapabilities     = msieve.GetSieveCapabilities
)

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

const DefaultMaxScriptSize = 16 * 1024 // 16 KB

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after: a session or a login loads it
// once and uses that copy throughout, so it never mixes the values of two reloads.
type reloadableSettings struct {
	maxScriptSize          int64
	commandTimeout         time.Duration
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput to prevent slowloris (0 = disabled)
	masterSASLUsername     []byte
	masterSASLPassword     []byte
	masterSASLGate         *serverPkg.MasterSASLNetworkGate
}

type ManageSieveServer struct {
	addr                string
	name                string
	hostname            string
	rdb                 *resilient.ResilientDatabase
	appCtx              context.Context
	cancel              context.CancelFunc
	tlsConfig           *tls.Config
	useStartTLS         bool
	insecureAuth        bool
	supportedExtensions []string // List of supported Sieve extensions
	masterUsername      []byte
	masterPassword      []byte

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

	// Command timeout and throughput enforcement
	authIdleTimeout time.Duration    // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	commandTimeouts *CommandTimeouts // Per-command hard execution timeouts (nil = use defaults)

	// The settings ReloadConfig replaces; see reloadableSettings.
	settings atomic.Pointer[reloadableSettings]

	// Connection tracking
	connTracker *serverPkg.ConnectionTracker

	// Startup throttle to prevent thundering herd on restart
	startupThrottleUntil time.Time

	// Active session tracking for graceful shutdown
	activeSessionsMutex sync.RWMutex
	activeSessions      map[*ManageSieveSession]struct{}
	sessionsWg          sync.WaitGroup // Tracks active sessions for graceful drain

	// msLibServer is the go-managesieve protocol server. It is swapped
	// atomically on SIGHUP so reloaded settings apply to new connections
	// (existing connections keep the snapshot they were accepted with).
	msLibServer atomic.Pointer[managesieveserver.Server]
}

type ManageSieveServerOptions struct {
	// AuthLimiterOverride, when non-nil, is used as the session auth limiter
	// instead of constructing one from AuthRateLimit. Dependency-injection seam
	// (nil in all production paths); used by tests to observe what the auth paths
	// record, which is otherwise unobservable from the wire because blocked and
	// failed replies are deliberately byte-identical.
	AuthLimiterOverride         serverPkg.AuthLimiter
	InsecureAuth                bool
	Debug                       bool
	TLS                         bool
	TLSCertFile                 string
	TLSKeyFile                  string
	TLSVerify                   bool
	TLSUseStartTLS              bool
	TLSConfig                   *tls.Config // Global TLS config from TLS manager (optional)
	MaxScriptSize               int64
	SupportedExtensions         []string // List of supported Sieve extensions
	MasterUsername              string
	MasterPassword              string
	MasterSASLUsername          string
	MasterSASLPassword          string
	MasterSASLAllowedNetworks   []string // Source networks allowed to use master SASL and the master-username form (empty = any, anchored to real socket peer)
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
	AuthIdleTimeout             time.Duration             // Idle timeout during authentication phase (pre-auth only, 0 = disabled)
	CommandTimeout              time.Duration             // Maximum idle time before disconnection
	CommandTimeoutOverrides     map[string]time.Duration  // Per-command hard execution timeouts (overrides defaults)
	AbsoluteSessionTimeout      time.Duration             // Maximum total session duration (0 = no limit; go-managesieve enforces it)
	MinBytesPerMinute           int64                     // Minimum throughput to prevent slowloris (0 = use default 512 bytes/min)
	Config                      *config.Config            // Full config for shared settings like connection tracking timeouts
}

func New(appCtx context.Context, name, hostname, addr string, rdb *resilient.ResilientDatabase, options ManageSieveServerOptions) (*ManageSieveServer, error) {
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
		proxyReader, err = serverPkg.NewProxyProtocolReader("ManageSieve", proxyConfig)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Resolve the SIEVE extensions exactly as delivery does (the configured names
	// the engine supports, or the default set), so ManageSieve never accepts a
	// script that delivery then cannot compile. Names that are dropped are
	// warned about once, at startup, by cmd/sora.
	options.SupportedExtensions = sieveengine.EffectiveExtensions(options.SupportedExtensions)

	// Validate TLS configuration: tls_use_starttls only makes sense when tls = true
	if !options.TLS && options.TLSUseStartTLS {
		logger.Debug("ManageSieve: WARNING - tls_use_starttls ignored because tls=false", "name", name)
		// Force TLSUseStartTLS to false to avoid confusion
		options.TLSUseStartTLS = false
	}

	// Initialize authentication rate limiter with trusted networks
	// A non-nil AuthLimiterOverride (tests only) replaces the real limiter; the
	// monitoring registry only accepts the concrete type, so skip it in that case.
	var authLimiter serverPkg.AuthLimiter = options.AuthLimiterOverride
	if authLimiter == nil {
		concrete := serverPkg.NewAuthRateLimiterWithTrustedNetworks("ManageSieve", name, hostname, options.AuthRateLimit, options.TrustedNetworks)
		serverPkg.RegisterRateLimiter("managesieve", name, concrete)
		authLimiter = concrete
	}

	// Initialize the master SASL network gate. Fail closed on a misconfigured
	// allow-list rather than silently disabling the gate.
	masterSASLGate, err := serverPkg.NewMasterSASLNetworkGate(options.MasterSASLAllowedNetworks)
	if err != nil {
		serverCancel()
		return nil, fmt.Errorf("invalid master_sasl_allowed_networks: %w", err)
	}
	if len(options.MasterSASLPassword) > 0 && !masterSASLGate.Enabled() {
		logger.Warn("ManageSieve: master SASL enabled without master_sasl_allowed_networks; backend trusts any source that knows the secret. Restrict backend ports to proxy hosts or set master_sasl_allowed_networks.", "name", name)
	}

	// Initialize authentication cache from config
	// Default to enabled if not explicitly configured
	var lookupCache *lookupcache.LookupCache
	lookupCacheConfig := options.LookupCache

	// If no config provided, use defaults and enable cache
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	// Only disable if explicitly set to false
	if !lookupCacheConfig.Enabled {
		logger.Info("ManageSieve: Lookup cache disabled", "name", name)
	} else {
		positiveTTL := lookupCacheConfig.GetPositiveTTLWithDefault(name)
		negativeTTL := lookupCacheConfig.GetNegativeTTLWithDefault(name)
		cleanupInterval := lookupCacheConfig.GetCleanupIntervalWithDefault(name)

		maxSize := lookupCacheConfig.GetMaxSize()

		positiveRevalidationWindow := lookupCacheConfig.GetPositiveRevalidationWindowWithDefault(name)

		lookupCache = lookupcache.New("managesieve", name, positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("ManageSieve: Lookup cache enabled", "name", name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	}

	// Apply default maxScriptSize if not set
	maxScriptSize := options.MaxScriptSize
	if maxScriptSize == 0 {
		maxScriptSize = DefaultMaxScriptSize
	}

	serverInstance := &ManageSieveServer{
		hostname:            hostname,
		name:                name,
		addr:                addr,
		rdb:                 rdb,
		appCtx:              serverCtx,
		cancel:              serverCancel,
		useStartTLS:         options.TLSUseStartTLS,
		insecureAuth:        options.InsecureAuth || !options.TLS, // Auto-enable when TLS not configured
		supportedExtensions: options.SupportedExtensions,
		masterUsername:      []byte(options.MasterUsername),
		masterPassword:      []byte(options.MasterPassword),
		proxyReader:         proxyReader,
		authLimiter:         authLimiter,
		lookupCache:         lookupCache,
		authIdleTimeout:     options.AuthIdleTimeout,
		commandTimeouts:     defaultCommandTimeouts(),
		activeSessions:      make(map[*ManageSieveSession]struct{}),
	}
	serverInstance.settings.Store(&reloadableSettings{
		maxScriptSize:          maxScriptSize,
		commandTimeout:         options.CommandTimeout,
		absoluteSessionTimeout: options.AbsoluteSessionTimeout,
		minBytesPerMinute:      options.MinBytesPerMinute,
		masterSASLUsername:     []byte(options.MasterSASLUsername),
		masterSASLPassword:     []byte(options.MasterSASLPassword),
		masterSASLGate:         masterSASLGate,
	})

	// Apply operator overrides for per-command execution timeouts
	if len(options.CommandTimeoutOverrides) > 0 {
		serverInstance.commandTimeouts.ApplyOverrides(options.CommandTimeoutOverrides)
	}

	// Create the connection limiter. max_connections_per_ip counts the client a PROXY
	// header names when there is one, else the socket peer, and trusted_networks
	// exempt the counted address: a trusted proxy or load balancer passes the limit
	// on to its clients and is only exempt itself when it names none.
	serverInstance.limiter = serverPkg.NewConnectionLimiterWithTrustedNets("ManageSieve", options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)

	// Set listen backlog with reasonable default
	serverInstance.listenBacklog = options.ListenBacklog
	if serverInstance.listenBacklog == 0 {
		serverInstance.listenBacklog = 1024 // Default backlog
	}

	// One TLS config for implicit TLS and STARTTLS; the certificate source and
	// tls_verify follow the rule every listener shares (serverPkg.ListenerTLS).
	if options.TLS {
		tlsConfig, err := serverPkg.ListenerTLS{
			Protocol: "ManageSieve", Name: name,
			CertFile: options.TLSCertFile, KeyFile: options.TLSKeyFile, Verify: options.TLSVerify,
			Global: options.TLSConfig, ALPN: []string{"sieve"},
		}.Config()
		if err != nil {
			serverCancel()
			return nil, err
		}
		serverInstance.tlsConfig = tlsConfig
	}

	// Start connection limiter cleanup
	serverInstance.limiter.StartCleanup(serverCtx)

	reportCommandTimeout(options.CommandTimeout)

	// Initialize local connection tracking (no gossip, just local tracking)
	// This enables per-user connection limits and kick functionality on backend servers
	if options.MaxConnectionsPerUser > 0 {
		// Generate unique instance ID for this server instance
		instanceID := fmt.Sprintf("managesieve-%s-%d", name, time.Now().UnixNano())

		// Create ConnectionTracker with nil cluster manager (local mode only)
		serverInstance.connTracker = serverPkg.NewConnectionTracker(
			"ManageSieve",                      // protocol name
			name,                               // server name
			hostname,                           // hostname
			instanceID,                         // unique instance identifier
			nil,                                // no cluster manager = local mode
			options.MaxConnectionsPerUser,      // per-user connection limit
			options.MaxConnectionsPerUserPerIP, // per-user-per-IP connection limit
			0,                                  // queue size (not used in local mode)
			false,                              // snapshot-only mode (not used in local mode)
		)

		logger.Debug("ManageSieve: Local connection tracking enabled", "name", name, "max_connections_per_user", options.MaxConnectionsPerUser)
	} else {
		// Connection tracking disabled (unlimited connections per user)
		serverInstance.connTracker = nil
		logger.Debug("ManageSieve: Local connection tracking disabled", "name", name)
	}

	serverInstance.msLibServer.Store(serverInstance.buildLibServer())

	return serverInstance, nil
}

// knownCommands bounds the OnCommand metric label set so clients cannot mint
// unbounded Prometheus label values.
var knownCommands = map[string]bool{
	"CAPABILITY": true, "AUTHENTICATE": true, "LOGIN": true, "STARTTLS": true,
	"HAVESPACE": true, "PUTSCRIPT": true, "LISTSCRIPTS": true, "SETACTIVE": true,
	"GETSCRIPT": true, "DELETESCRIPT": true, "RENAMESCRIPT": true, "CHECKSCRIPT": true,
	"NOOP": true, "LOGOUT": true,
}

// buildLibServer constructs the go-managesieve protocol server from the
// current runtime settings. It is called at startup and again from
// ReloadConfig so SIGHUP-reloaded settings apply to new connections.
func (s *ManageSieveServer) buildLibServer() *managesieveserver.Server {
	settings := s.settings.Load()

	// STARTTLS upgrades are the library's job only on plaintext listeners;
	// implicit-TLS listeners keep TLS outside the library (SoraTLSListener +
	// deferred handshake), and passing a TLSConfig there would wrongly
	// advertise STARTTLS.
	var startTLSConfig *tls.Config
	if s.useStartTLS {
		startTLSConfig = serverPkg.StartTLSConfig(s.tlsConfig, "managesieve") // records JA4, as SoraTLSConn does for implicit TLS
	}

	opts := managesieveserver.Options{
		TLSConfig:              startTLSConfig,
		OnStartTLS:             serverPkg.BeginStartTLS,
		OnTLSHandshakeComplete: serverPkg.CompleteStartTLS,
		Implementation:         "ManageSieve",
		Greeting:               `"Sora" ManageSieve server ready.`,
		GreetingStartTLSHint:   true,
		SieveExtensions:        msieve.GetSieveCapabilities(s.supportedExtensions),
		MaxScriptSize:          settings.maxScriptSize,
		MaxLineLength:          ManageSieveMaxLineLength,
		IdleTimeout:            settings.commandTimeout,
		AuthIdleTimeout:        s.authIdleTimeout,
		AbsoluteSessionTimeout: settings.absoluteSessionTimeout,
		InsecureAuth:           s.insecureAuth,
		MaxErrors:              10,
		// The library owns the idle and absolute-session timers (the SoraConn
		// checker must not duplicate them — see the SoraConnConfig in Start),
		// so timeout disconnects are counted from its hook.
		OnTimeout: func(kind string) {
			reason := "idle"
			if kind == managesieveserver.TimeoutAbsolute {
				reason = "session_max"
			}
			metrics.ConnectionTimeoutsTotal.WithLabelValues("managesieve", s.name, s.hostname, reason).Inc()
		},
		StrictSessionErrors: true, // Session errors are *managesieveserver.Error; mask anything else (DB error text must not reach clients)
		NewSession: func(c *managesieveserver.Conn) (managesieveserver.Session, error) {
			netConn := c.NetConn()
			proxyInfo := serverPkg.GetProxyProtocolInfo(netConn)
			clientIP, proxyIP := serverPkg.GetConnectionIPs(netConn, proxyInfo)

			// Limiter checks. DELIBERATE silent close, no banner: matches the
			// previous accept-loop rejection (drop before any greeting), and
			// a "NO too many connections" banner would tell a flooder exactly
			// when the limiter engages so they can pace under it.
			releaseConn, err := s.limiter.AcceptWithRealIP(netConn.RemoteAddr(), clientIP)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", managesieveserver.ErrSilentReject, err)
			}

			// Implicit-TLS listeners (SoraTLSListener) defer the TLS
			// handshake so a PROXY header can be read in plaintext first; the
			// library never triggers it, so complete it here — after the
			// limiter (rejected peers never cost a handshake) and before the
			// greeting is written.
			if didTLS, err := serverPkg.PerformDeferredTLSHandshake(netConn); err != nil {
				releaseConn()
				logger.Debug("ManageSieve: TLS handshake failed", "name", s.name, "remote", serverPkg.GetAddrString(netConn.RemoteAddr()), "error", err)
				return nil, fmt.Errorf("%w: TLS handshake: %w", managesieveserver.ErrSilentReject, err)
			} else if didTLS {
				c.SetTLS(true)
			}

			// Count the connection only once it is past every rejection
			// point, so the decrements in the session close path always
			// balance.
			s.totalConnections.Add(1)
			metrics.ConnectionsTotal.WithLabelValues("managesieve", s.name, s.hostname).Inc()
			metrics.ConnectionsCurrent.WithLabelValues("managesieve", s.name, s.hostname).Inc()

			sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

			session := &ManageSieveSession{
				server:      s,
				conn:        netConn,
				ctx:         sessionCtx,
				cancel:      sessionCancel,
				releaseConn: releaseConn,
				startTime:   time.Now(),
			}
			session.RemoteIP = clientIP
			session.ProxyIP = proxyIP
			session.Protocol = "ManageSieve"
			session.ServerName = s.name
			session.Id = idgen.New()
			session.HostName = s.hostname
			session.Stats = s // Set the server as the Stats provider

			// Create logging function for the mutex helper
			logFunc := func(format string, args ...any) {
				session.InfoLog(format, args...)
			}
			session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "managesieve", logFunc)

			// Log connection with session context (protocol, remote, session id)
			session.DebugLog("new connection")

			// Track session for graceful shutdown
			s.addSession(session)

			return session, nil
		},
		OnCommand: func(cmd string, dur time.Duration, err error) {
			if !knownCommands[cmd] {
				cmd = "UNKNOWN"
			}
			status := "success"
			if err != nil {
				status = "failure"
			}
			metrics.CommandsTotal.WithLabelValues("managesieve", cmd, status).Inc()
			metrics.CommandDuration.WithLabelValues("managesieve", cmd).Observe(dur.Seconds())
		},
	}

	return managesieveserver.New(opts)
}

// reportCommandTimeout publishes command_timeout's metric, at start-up and whenever a
// reload changes it.
func reportCommandTimeout(timeout time.Duration) {
	metrics.CommandTimeoutThresholdSeconds.WithLabelValues("managesieve").Set(timeout.Seconds())
}

// connConfig is the SoraConn configuration for a connection accepted now. The
// listener asks for it at every accept, so a reloaded min_bytes_per_minute reaches
// the connections accepted after it.
//
// The idle and absolute-session timers are owned by the go-managesieve library: it
// clears the deadline during command execution, distinguishes the two cases in its
// BYE notice, and reports disconnects through the OnTimeout hook wired in the
// library options above. Arming the checker here with the same knobs raced the
// library and could send the client a duplicate BYE, so only the throughput check —
// which the library does not provide — stays at this layer.
func (s *ManageSieveServer) connConfig() serverPkg.SoraConnConfig {
	settings := s.settings.Load()
	return serverPkg.SoraConnConfig{
		Protocol:             "managesieve",
		ServerName:           s.name,
		Hostname:             s.hostname,
		MinBytesPerMinute:    settings.minBytesPerMinute,
		EnableTimeoutChecker: settings.minBytesPerMinute > 0,
		NoAbsoluteTimeout:    true, // the library enforces absolute_session_timeout
		OnTimeout: func(conn net.Conn, reason string) {
			// Best-effort BYE before closing, on the connection the library is
			// using (the TLS one after STARTTLS; see NewSession). RFC 5804
			// Section 1.3; TRYLATER indicates a temporary condition.
			message := "BYE (TRYLATER) \"Connection timeout, please reconnect\"\r\n"
			if reason == "slow_throughput" {
				message = "BYE (TRYLATER) \"Connection too slow, please reconnect\"\r\n"
			}
			_, _ = fmt.Fprint(conn, message)
		},
	}
}

func (s *ManageSieveServer) Start(errChan chan error) {
	var listener net.Listener

	connConfig := s.connConfig()

	// Create TCP listener with custom backlog
	tcpListener, err := serverPkg.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
	if err != nil {
		errChan <- fmt.Errorf("failed to create TCP listener: %w", err)
		return
	}
	logger.Debug("ManageSieve: Using custom listen backlog", "server", s.name, "backlog", s.listenBacklog)

	// The PROXY protocol header travels in plaintext AHEAD of the TLS
	// ClientHello, so the header reader must sit between the TCP socket and
	// the TLS layer: the header is read from the raw stream, and the deferred
	// TLS handshake then reads THROUGH the PROXY conn, consuming any
	// ClientHello bytes its bufio buffered alongside the header. Wrapping in
	// the other order makes the handshake read the raw socket and miss those
	// bytes (broken PROXY+TLS combo). STARTTLS listeners are unaffected (TLS
	// is negotiated in-protocol, long after the header).
	base := serverPkg.WrapProxyProtocol(tcpListener, s.proxyReader, "ManageSieve")

	isImplicitTLS := s.tlsConfig != nil && !s.useStartTLS
	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if isImplicitTLS {
		listener = serverPkg.NewSoraTLSListenerFunc(base, s.tlsConfig, s.connConfig)
		if connConfig.EnableTimeoutChecker {
			settings := s.settings.Load()
			logger.Info("ManageSieve server listening with TLS", "name", s.name, "addr", s.addr, "idle_timeout",
				settings.commandTimeout, "session_max", settings.absoluteSessionTimeout, "min_throughput", connConfig.MinBytesPerMinute)
		} else {
			logger.Info("ManageSieve server listening with TLS", "name", s.name, "addr", s.addr)
		}
	} else {
		listener = serverPkg.NewSoraListenerFunc(base, s.connConfig)
		if connConfig.EnableTimeoutChecker {
			settings := s.settings.Load()
			logger.Info("ManageSieve server listening", "name", s.name, "addr", s.addr, "tls", false, "idle_timeout", settings.commandTimeout, "session_max", settings.absoluteSessionTimeout, "min_throughput", connConfig.MinBytesPerMinute)
		} else {
			logger.Info("ManageSieve server listening", "name", s.name, "addr", s.addr, "tls", false)
		}
	}
	defer listener.Close()

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		logger.Debug("ManageSieve: stopping", "name", s.name)
		listener.Close()
	}()

	// Start session monitoring routine
	go s.monitorActiveSessions()

	// Set startup throttle for 30 seconds
	s.startupThrottleUntil = time.Now().Add(30 * time.Second)
	logger.Info("ManageSieve: Startup throttle active for 30s", "name", s.name)

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
				logger.Info("ManageSieve server stopped gracefully", "name", s.name)
				return
			default:
				// For other errors, this might be a fatal server error
				errChan <- err
				return
			}
		}

		// Connection limiting, TLS handshake completion, counters, and
		// session construction all happen in the library's NewSession
		// callback (see buildLibServer), so rejected connections never
		// inflate the gauges.

		s.sessionsWg.Add(1)
		go func() {
			defer s.sessionsWg.Done()
			// Recover from any panic in the session goroutine. Without this, a single
			// malformed command would propagate an unrecovered panic and crash the entire
			// (multi-protocol) server process, dropping every connection. Mirrors POP3.
			defer func() {
				if r := recover(); r != nil {
					logger.Error("ManageSieve: panic in connection handler", "panic", r, "stack", string(debug.Stack()))
				}
			}()
			s.msLibServer.Load().ServeConn(conn)
		}()
	}
}

// SetConnTracker sets the connection tracker for this server
func (s *ManageSieveServer) SetConnTracker(tracker *serverPkg.ConnectionTracker) {
	s.connTracker = tracker
	// A kick, or logins forgotten after an account change, must reach this
	// server's cached logins too, or they keep signing the account in.
	if tracker != nil && s.lookupCache != nil {
		tracker.SetLookupCache(s.lookupCache)
	}
}

func (s *ManageSieveServer) Close() {
	// Unregister rate limiter from global registry
	serverPkg.UnregisterRateLimiter("managesieve", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Step 1: Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	// Step 2: Cancel context to signal sessions to finish
	if s.cancel != nil {
		s.cancel()
	}

	// Also cancel the library-side connection contexts so in-flight
	// per-command work (DB calls, error delays) aborts instead of running to
	// its own timeout. Sessions accepted under a pre-SIGHUP snapshot are not
	// covered here, but the shutdown broadcast above already closed their
	// sockets.
	if lib := s.msLibServer.Load(); lib != nil {
		lib.Close()
	}

	// Step 3: Wait for active sessions to finish gracefully (with timeout)
	s.waitForSessionsDrain(30 * time.Second)
}

// waitForSessionsDrain waits for all active sessions to finish with a timeout
func (s *ManageSieveServer) waitForSessionsDrain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.sessionsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("ManageSieve: All sessions drained gracefully", "name", s.name)
	case <-time.After(timeout):
		logger.Debug("ManageSieve: Session drain timeout, forcing shutdown", "name", s.name, "timeout", timeout)
	}
}

// addSession tracks an active session for graceful shutdown
func (s *ManageSieveServer) addSession(session *ManageSieveSession) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *ManageSieveServer) removeSession(session *ManageSieveSession) {
	s.activeSessionsMutex.Lock()
	defer s.activeSessionsMutex.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a graceful shutdown notice to all active sessions
func (s *ManageSieveServer) sendGracefulShutdownMessage() {
	s.activeSessionsMutex.RLock()
	activeSessions := make([]*ManageSieveSession, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMutex.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("ManageSieve: Sending graceful shutdown message to active connections", "name", s.name, "count", len(activeSessions))

	// Send shutdown message to all active connections
	// ManageSieve uses BYE response for clean disconnection
	for _, session := range activeSessions {
		// After STARTTLS the client reads through the library's TLS
		// connection, which sits above session.conn; while STARTTLS is
		// negotiating there is nothing to write to.
		serverPkg.WriteNotice(session.conn, func(noticeConn net.Conn) {
			writer := bufio.NewWriter(noticeConn)
			// Send BYE with TRYLATER response code (RFC 5804 Section 1.3)
			writer.WriteString("BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n")
			writer.Flush()
		})
	}

	// Give clients a brief moment (1 second) to receive the message
	time.Sleep(1 * time.Second)

	// Close connections to unblock any sessions blocked on reads
	for _, session := range activeSessions {
		if session.conn != nil {
			session.conn.Close()
		}
	}

	logger.Debug("ManageSieve: Proceeding with connection cleanup", "name", s.name)
}

// GetTotalConnections returns the current total connection count
func (s *ManageSieveServer) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *ManageSieveServer) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}

// monitorActiveSessions periodically logs active session count for monitoring
func (s *ManageSieveServer) monitorActiveSessions() {
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
			logger.Info("ManageSieve server active sessions", "name", s.name, "active_sessions", count, "limiter_stats", limiterStats)

		case <-s.appCtx.Done():
			return
		}
	}
}

// GetLimiter returns the connection limiter for testing purposes
func (s *ManageSieveServer) GetLimiter() *serverPkg.ConnectionLimiter {
	return s.limiter
}

// ReloadConfig updates runtime-configurable settings from new config.
func (s *ManageSieveServer) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string
	next := *s.settings.Load()

	// A value that does not parse keeps the running one (start-up, which has none,
	// uses the default).
	if timeout, err := cfg.GetCommandTimeout(); err != nil {
		logger.Warn("ManageSieve config reload: invalid command_timeout, keeping the running value", "name", s.name, "error", err, "running", next.commandTimeout)
	} else if timeout != next.commandTimeout {
		next.commandTimeout = timeout
		reloaded = append(reloaded, "command_timeout")
		reportCommandTimeout(timeout)
	}
	if timeout, err := cfg.GetAbsoluteSessionTimeout(); err != nil {
		logger.Warn("ManageSieve config reload: invalid absolute_session_timeout, keeping the running value", "name", s.name, "error", err, "running", next.absoluteSessionTimeout)
	} else if timeout != next.absoluteSessionTimeout {
		next.absoluteSessionTimeout = timeout
		reloaded = append(reloaded, "absolute_session_timeout")
	}
	if bpm := cfg.GetMinBytesPerMinute(); bpm != next.minBytesPerMinute {
		next.minBytesPerMinute = bpm
		reloaded = append(reloaded, "min_bytes_per_minute")
	}
	if maxSize := cfg.GetMaxScriptSizeWithDefault(); maxSize != next.maxScriptSize {
		next.maxScriptSize = maxSize
		reloaded = append(reloaded, "max_script_size")
	}
	if cfg.MasterSASLUsername != string(next.masterSASLUsername) {
		next.masterSASLUsername = []byte(cfg.MasterSASLUsername)
		reloaded = append(reloaded, "master_sasl_username")
	}
	if cfg.MasterSASLPassword != string(next.masterSASLPassword) {
		next.masterSASLPassword = []byte(cfg.MasterSASLPassword)
		reloaded = append(reloaded, "master_sasl_password")
	}
	if gate, err := serverPkg.NewMasterSASLNetworkGate(cfg.MasterSASLAllowedNetworks); err != nil {
		logger.Warn("ManageSieve config reload: invalid master_sasl_allowed_networks, keeping previous gate", "name", s.name, "error", err)
	} else if !next.masterSASLGate.Equal(gate) {
		next.masterSASLGate = gate
		reloaded = append(reloaded, "master_sasl_allowed_networks")
	}

	if len(reloaded) > 0 {
		s.settings.Store(&next)
		// Rebuild the library server so new connections pick up the reloaded
		// settings; existing connections keep their snapshot.
		s.msLibServer.Store(s.buildLibServer())
		logger.Info("ManageSieve config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

// GetLookupCache returns the lookup cache for testing purposes
func (s *ManageSieveServer) GetLookupCache() *lookupcache.LookupCache {
	return s.lookupCache
}

// Authenticate authenticates a user with caching support.
// This method wraps the database authentication with an optional lookup cache layer.
// The cache decorates the database call - this is the proper architectural pattern.
func (s *ManageSieveServer) Authenticate(ctx context.Context, address, password string) (accountID int64, err error) {
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
		if serverPkg.IsTemporaryAuthFailure(err) {
			// The database could not be asked: no verdict on the credentials, so nothing
			// is cached and the login is answered as a temporary failure.
			logger.Warn("authentication unavailable", "address", address, "method", "main_db", "error", err)
			return 0, err
		}
		// Equalize response timing with the wrong-password path (which runs bcrypt) so an
		// attacker can't use response time to tell whether the account exists. (security-audit M14)
		if errors.Is(err, consts.ErrUserNotFound) {
			db.DummyVerifyPassword(password)
		}
		// Cache negative result if enabled (user not found)
		if s.lookupCache != nil {
			// AuthUserNotFound = 1 (from lookupcache package)
			s.lookupCache.SetFailure(address, 1)
		}
		logger.Info("authentication failed", "address", address, "reason", "user_not_found", "cached", false, "method", "main_db")
		return 0, err
	}

	// Verify password
	if err := db.VerifyPassword(hashedPassword, password); err != nil {
		reason := "invalid_password"
		if errors.Is(err, db.ErrUnverifiableHash) {
			// No password matches the stored hash: not a wrong password, so nothing is
			// cached. VerifyPassword logged why, without the address.
			reason = "unverifiable_hash"
		} else if s.lookupCache != nil {
			// Cache negative result for invalid password if enabled
			// AuthInvalidPassword = 2 (from lookupcache package)
			s.lookupCache.SetFailure(address, 2)
		}
		logger.Info("authentication failed", "address", address, "reason", reason, "cached", false, "method", "main_db")
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
