package pop3proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

type POP3ProxyServer struct {
	name                   string // Server name for logging
	addr                   string
	hostname               string
	rdb                    *resilient.ResilientDatabase
	appCtx                 context.Context
	cancel                 context.CancelFunc
	tlsConfig              *tls.Config
	masterUsername         string
	masterPassword         string
	masterSASLUsername     string
	masterSASLPassword     string
	connManager            *proxy.ConnectionManager
	connTracker            *server.ConnectionTracker
	wg                     sync.WaitGroup
	enableAffinity         bool
	authLimiter            server.AuthLimiter
	trustedProxies         []string // CIDR blocks for trusted proxies that can forward parameters
	remotelookupConfig     *config.RemoteLookupConfig
	authIdleTimeout        time.Duration
	commandTimeout         time.Duration // Idle timeout
	absoluteSessionTimeout time.Duration // Maximum total session duration
	minBytesPerMinute      int64         // Minimum throughput
	remoteUseXCLIENT       bool          // Whether backend supports XCLIENT command for forwarding

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Auth cache for routing and password validation
	lookupCache                *lookupcache.LookupCache
	positiveRevalidationWindow time.Duration

	// Listen backlog
	listenBacklog int

	// Auth security
	insecureAuth bool

	// Debug logging
	debug       bool
	debugWriter io.Writer

	// Authentication limits
	maxAuthErrors int // Maximum authentication errors before disconnection

	// Active session tracking for graceful shutdown
	activeSessionsMu sync.RWMutex
	activeSessions   map[*POP3ProxySession]struct{}

	// PROXY protocol support for incoming connections
	proxyReader *server.ProxyProtocolReader

	// Startup throttle to prevent thundering herd on restart
	startupThrottleUntil time.Time

	// The library server is rebuilt (for new connections only) when runtime
	// settings change on SIGHUP; existing connections keep their snapshot.
	pop3libServer atomic.Pointer[pop3server.Server]
}

// maskingWriter wraps an io.Writer to mask sensitive information in POP3 commands
type maskingWriter struct {
	w io.Writer
}

// Write inspects the log output, and if it's a client command (prefixed with "C: "),
// it attempts to mask sensitive parts of PASS and AUTH commands.
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
	if len(parts) < 1 {
		return mw.w.Write(p)
	}

	command := strings.ToUpper(parts[0])

	// Use the helper to mask the command line
	maskedCmdLine := helpers.MaskSensitive(trimmedCmdLine, command, "PASS", "AUTH")

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

	// Always return the original length to prevent buffering issues
	return originalLen, nil
}

type POP3ProxyServerOptions struct {
	Name                     string // Server name for logging
	InsecureAuth             bool   // Allow PLAIN auth over non-TLS connections
	Debug                    bool
	TLS                      bool
	TLSCertFile              string
	TLSKeyFile               string
	TLSVerify                bool
	TLSConfig                *tls.Config // Global TLS config from TLS manager (optional)
	RemoteAddrs              []string
	RemotePort               int // Default port for backends if not in address
	RemoteTLS                bool
	RemoteTLSVerify          bool
	RemoteTLSCAFile          string // PEM file with CA certs for backend verification (private-CA / self-signed backends); empty = system roots
	RemoteUseProxyProtocol   bool
	MasterUsername           string
	MasterPassword           string
	MasterSASLUsername       string
	MasterSASLPassword       string
	ConnectTimeout           time.Duration
	AuthIdleTimeout          time.Duration
	CommandTimeout           time.Duration // Idle timeout
	AbsoluteSessionTimeout   time.Duration // Maximum total session duration
	MinBytesPerMinute        int64         // Minimum throughput
	EnableAffinity           bool
	EnableBackendHealthCheck bool // Enable backend health checking (default: true)
	AuthRateLimit            server.AuthRateLimiterConfig
	RemoteLookup             *config.RemoteLookupConfig
	TrustedProxies           []string // CIDR blocks for trusted proxies that can forward parameters
	RemoteUseXCLIENT         bool     // Whether backend supports XCLIENT command for forwarding

	// PROXY protocol for incoming connections (from HAProxy, nginx, etc.)
	ProxyProtocol        bool   // Enable PROXY protocol support for incoming connections
	ProxyProtocolTimeout string // Timeout for reading PROXY protocol headers (e.g., "5s")

	// Connection limiting
	MaxConnections      int      // Maximum total connections per instance (0 = unlimited, local only)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited, cluster-wide if ClusterManager provided)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits
	ListenBacklog       int      // TCP listen backlog size (0 = system default; recommended: 4096-8192)

	// Auth cache configuration
	LookupCache *config.LookupCacheConfig

	// Authentication limits
	MaxAuthErrors int // Maximum authentication errors before disconnection (0 = use default)

	// Cluster support
	ClusterManager *cluster.Manager // Optional: enables cluster-wide per-IP limiting
}

func New(appCtx context.Context, hostname, addr string, rdb *resilient.ResilientDatabase, options POP3ProxyServerOptions) (*POP3ProxyServer, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	// Ensure RemoteLookup config has a default value to avoid nil panics.
	if options.RemoteLookup == nil {
		options.RemoteLookup = &config.RemoteLookupConfig{}
	}

	// Initialize remotelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if options.RemoteLookup != nil && options.RemoteLookup.Enabled {
		remotelookupClient, err := proxy.InitializeRemoteLookup("pop3", options.RemoteLookup)
		if err != nil {
			logger.Debug("POP3 Proxy: Failed to initialize remotelookup client", "proxy", options.Name, "error", err)
			if !options.RemoteLookup.ShouldLookupLocalUsers() {
				serverCancel()
				return nil, fmt.Errorf("failed to initialize remotelookup client: %w", err)
			}
			logger.Debug("POP3 Proxy: Continuing without remotelookup due to lookup_local_users=true", "proxy", options.Name)
		} else {
			routingLookup = remotelookupClient
			if options.Debug {
				logger.Debug("POP3 Proxy: RemoteLookup client initialized successfully", "proxy", options.Name)
			}
		}
	}

	// Default the backend connect timeout when unset, matching the IMAP/LMTP/ManageSieve
	// proxies. This value also bounds the backend greeting/auth read deadlines, so a 0
	// must not leak through: net.Dialer treats Timeout=0 as "no timeout", but a read
	// deadline of time.Now().Add(0) expires immediately (backend greeting i/o timeout).
	connectTimeout := options.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Create connection manager with routing
	connManager, err := proxy.NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(
		options.RemoteAddrs,
		options.RemotePort,
		options.RemoteTLS,
		false,
		options.RemoteTLSVerify,
		options.RemoteUseProxyProtocol,
		connectTimeout,
		routingLookup,
		options.Name,
		!options.EnableBackendHealthCheck,
	)
	if err != nil {
		if routingLookup != nil {
			routingLookup.Close()
		}
		serverCancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// SSRF defense: when enabled, refuse remote-lookup backends not in the configured pool.
	connManager.SetRestrictRemoteLookupToPool(options.RemoteLookup != nil && options.RemoteLookup.RestrictToPool)

	// Custom CA for backend certificate verification (private-CA or
	// self-signed backends): keeps remote_tls_verify usable instead of
	// forcing it off.
	if options.RemoteTLSCAFile != "" {
		pem, err := os.ReadFile(options.RemoteTLSCAFile)
		if err != nil {
			if routingLookup != nil {
				routingLookup.Close()
			}
			serverCancel()
			return nil, fmt.Errorf("failed to read remote_tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			if routingLookup != nil {
				routingLookup.Close()
			}
			serverCancel()
			return nil, fmt.Errorf("remote_tls_ca_file %q contains no usable certificates", options.RemoteTLSCAFile)
		}
		connManager.SetRemoteTLSRootCAs(pool)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Debug("WARNING: Failed to resolve some addresses for POP3 proxy", "proxy", options.Name, "error", err)
	}

	// Initialize authentication rate limiter with trusted networks
	authLimiter := server.NewAuthRateLimiterWithTrustedNetworks("POP3-PROXY", options.Name, hostname, options.AuthRateLimit, options.TrustedProxies)
	server.RegisterRateLimiter("pop3_proxy", options.Name, authLimiter)

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if options.MaxConnections > 0 || options.MaxConnectionsPerIP > 0 {
		if options.ClusterManager != nil {
			// Cluster mode: use cluster-wide per-IP limiting
			instanceID := fmt.Sprintf("pop3-proxy-%s-%d", hostname, time.Now().UnixNano())
			limiter = server.NewConnectionLimiterWithCluster("POP3-PROXY", instanceID, options.ClusterManager, options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)
		} else {
			// Local mode: use local-only limiting
			limiter = server.NewConnectionLimiterWithTrustedNets("POP3-PROXY", options.MaxConnections, options.MaxConnectionsPerIP, options.TrustedNetworks)
		}
	}

	// Setup debug writer with password masking if debug is enabled
	var debugWriter io.Writer
	if options.Debug {
		debugWriter = &maskingWriter{w: os.Stdout}
	}

	// Set listen backlog with reasonable default
	listenBacklog := options.ListenBacklog
	if listenBacklog == 0 {
		listenBacklog = 1024 // Default backlog
	}

	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		// Build config from flat fields (matching backend format)
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Timeout:        options.ProxyProtocolTimeout,
			TrustedProxies: options.TrustedNetworks, // Proxies always use trusted_networks
		}
		var err error
		proxyReader, err = server.NewProxyProtocolReader("POP3-PROXY", proxyConfig)
		if err != nil {
			if routingLookup != nil {
				routingLookup.Close()
			}
			serverCancel()
			return nil, fmt.Errorf("failed to create PROXY protocol reader: %w", err)
		}
		logger.Info("PROXY protocol enabled for incoming connections", "proxy", options.Name)
	}

	// Initialize auth cache for user authentication and routing
	// Initialize authentication cache from config
	// Apply defaults if not configured (enabled by default for performance)
	var lookupCache *lookupcache.LookupCache
	var positiveRevalidationWindow time.Duration
	lookupCacheConfig := options.LookupCache
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	if lookupCacheConfig.Enabled {
		positiveTTL, err := lookupCacheConfig.GetPositiveTTL()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid positive TTL in auth cache config, using default (5m)", "name", options.Name, "error", err)
			positiveTTL = 5 * time.Minute
		}
		negativeTTL, err := lookupCacheConfig.GetNegativeTTL()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid negative TTL in auth cache config, using default (1m)", "name", options.Name, "error", err)
			negativeTTL = 1 * time.Minute
		}
		cleanupInterval, err := lookupCacheConfig.GetCleanupInterval()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid cleanup interval in auth cache config, using default (5m)", "name", options.Name, "error", err)
			cleanupInterval = 5 * time.Minute
		}
		maxSize := lookupCacheConfig.MaxSize
		if maxSize <= 0 {
			maxSize = 10000
		}

		// Parse positive revalidation window from config (used for password change detection)
		positiveRevalidationWindow, err = lookupCacheConfig.GetPositiveRevalidationWindow()
		if err != nil {
			logger.Info("POP3 Proxy: Invalid positive revalidation window in auth cache config, using default (30s)", "name", options.Name, "error", err)
			positiveRevalidationWindow = 30 * time.Second
		}

		lookupCache = lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
		logger.Info("POP3 Proxy: Lookup cache enabled", "name", options.Name, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "positive_revalidation_window", positiveRevalidationWindow)
	} else {
		logger.Info("POP3 Proxy: Lookup cache disabled", "name", options.Name)
	}

	srv := &POP3ProxyServer{
		name:                       options.Name,
		hostname:                   hostname,
		addr:                       addr,
		rdb:                        rdb,
		appCtx:                     serverCtx,
		cancel:                     serverCancel,
		masterUsername:             options.MasterUsername,
		masterPassword:             options.MasterPassword,
		masterSASLUsername:         options.MasterSASLUsername,
		masterSASLPassword:         options.MasterSASLPassword,
		connManager:                connManager,
		enableAffinity:             options.EnableAffinity,
		authLimiter:                authLimiter,
		trustedProxies:             options.TrustedProxies,
		remotelookupConfig:         options.RemoteLookup,
		authIdleTimeout:            options.AuthIdleTimeout,
		commandTimeout:             options.CommandTimeout,
		absoluteSessionTimeout:     options.AbsoluteSessionTimeout,
		minBytesPerMinute:          options.MinBytesPerMinute,
		remoteUseXCLIENT:           options.RemoteUseXCLIENT,
		limiter:                    limiter,
		lookupCache:                lookupCache,
		positiveRevalidationWindow: positiveRevalidationWindow,
		listenBacklog:              listenBacklog,
		maxAuthErrors:              options.MaxAuthErrors,
		insecureAuth:               options.InsecureAuth || !options.TLS, // Auto-enable when TLS not configured
		debug:                      options.Debug,
		debugWriter:                debugWriter,
		activeSessions:             make(map[*POP3ProxySession]struct{}),
		proxyReader:                proxyReader,
	}

	// Setup TLS: Three scenarios
	// 1. Per-server TLS: cert files provided
	// 2. Global TLS: options.TLS=true, no cert files, global TLS config provided
	// 3. No TLS: options.TLS=false
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			serverCancel()
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		clientAuth := tls.NoClientCert
		if options.TLSVerify {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		srv.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"pop3"},
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if options.TLS && options.TLSConfig != nil {
		// Scenario 2: Global TLS manager
		srv.tlsConfig = options.TLSConfig
	} else if options.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		serverCancel()
		return nil, fmt.Errorf("TLS enabled for POP3 proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", options.Name)
	}

	srv.pop3libServer.Store(srv.buildLibServer())

	return srv, nil
}

// buildLibServer constructs the go-pop3 protocol server from the current
// runtime settings. It is called at startup and again from ReloadConfig so
// SIGHUP-reloaded settings apply to new connections (existing connections keep
// the snapshot they were accepted with).
func (s *POP3ProxyServer) buildLibServer() *pop3server.Server {
	// Build capabilities
	var caps []pop3.Capability
	caps = append(caps, pop3.Capability{Name: "AUTH-RESP-CODE"})
	caps = append(caps, pop3.Capability{Name: "IMPLEMENTATION", Params: []string{"Sora-POP3-Proxy"}})

	maxErrors := s.maxAuthErrors
	if maxErrors <= 0 {
		maxErrors = 10
	}

	opts := pop3server.Options{
		TLSConfig:              s.tlsConfig,
		IdleTimeout:            s.commandTimeout,
		AuthIdleTimeout:        s.authIdleTimeout,
		AbsoluteSessionTimeout: s.absoluteSessionTimeout,
		CommandTimeout:         s.commandTimeout,
		InsecureAuth:           s.insecureAuth,
		MaxLineLength:          1024,
		MaxErrors:              maxErrors,
		// Pre-migration parity: failed logins never counted toward the
		// (default 2) error budget on the proxy — the auth rate limiter
		// handles brute-force across connections, so a user who mistypes a
		// password twice must not be disconnected.
		AuthFailuresExemptFromMaxErrors: true,
		StrictSessionErrors:             true, // Session errors are *pop3server.Error; mask anything else
		Caps:                            caps,
		Greeting:                        "Sora-POP3-Proxy ready",
		NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
			netConn := c.NetConn()
			proxyInfo := server.GetProxyProtocolInfo(netConn)

			var releaseConn func()
			var err error
			if s.limiter != nil {
				releaseConn, err = s.limiter.AcceptWithRealIP(netConn.RemoteAddr(), "")
				if err != nil {
					// DELIBERATE silent close, no banner: matches the previous
					// accept-loop rejection (drop before any greeting), and an
					// "-ERR too many connections" banner would tell a flooder
					// exactly when the limiter engages so they can pace under
					// it. Test-enforced (connection-limit tests assert the
					// rejected socket never sees "+OK") — do not add a banner.
					return nil, fmt.Errorf("%w: %w", pop3server.ErrSilentReject, err)
				}
			}

			// Implicit-TLS listeners (SoraTLSListener) defer the TLS handshake;
			// the library never triggers it, so complete it here — after the
			// limiter and before the greeting is written. Also captures JA4 and
			// registers the connection timeout checker for TLS connections.
			if didTLS, err := server.PerformDeferredTLSHandshake(netConn); err != nil {
				if releaseConn != nil {
					releaseConn()
				}
				logger.Debug("POP3 Proxy: TLS handshake failed", "proxy", s.name, "remote", server.GetAddrString(netConn.RemoteAddr()), "error", err)
				return nil, fmt.Errorf("%w: TLS handshake: %w", pop3server.ErrSilentReject, err)
			} else if didTLS {
				c.SetTLS(true)
			}

			// Count the connection only once it is past every rejection point,
			// so the decrements in the session close path always balance.
			metrics.ConnectionsTotal.WithLabelValues("pop3_proxy", s.name, s.hostname).Inc()
			metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy", s.name, s.hostname).Inc()

			sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

			session := &POP3ProxySession{
				server:      s,
				clientConn:  netConn,
				ctx:         sessionCtx,
				cancel:      sessionCancel,
				releaseConn: releaseConn,
				proxyInfo:   proxyInfo,
				sessionID:   idgen.New(),
				pop3Conn:    c,
				startTime:   time.Now(),
			}

			if proxyInfo != nil && proxyInfo.SrcIP != "" {
				session.RemoteIP = proxyInfo.SrcIP
			} else {
				session.RemoteIP = server.GetAddrString(netConn.RemoteAddr())
			}

			session.InfoLog("connected")
			s.addSession(session)
			return session, nil
		},
	}

	return pop3server.New(opts)
}

func (s *POP3ProxyServer) Start() error {
	var listener net.Listener

	// Configure SoraConn with timeout protection
	connConfig := server.SoraConnConfig{
		Protocol:             "pop3_proxy",
		ServerName:           s.name,
		Hostname:             s.hostname,
		IdleTimeout:          s.commandTimeout,
		AbsoluteTimeout:      s.absoluteSessionTimeout,
		MinBytesPerMinute:    s.minBytesPerMinute,
		EnableTimeoutChecker: s.commandTimeout > 0 || s.absoluteSessionTimeout > 0,
		OnTimeout: func(conn net.Conn, reason string) {
			// Send POP3 error response before closing
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
			_, _ = fmt.Fprint(conn, message)
		},
	}

	// Create base TCP listener with custom backlog
	tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", s.addr, s.listenBacklog)
	if err != nil {
		s.cancel()
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}
	logger.Debug("POP3 Proxy: Using listen backlog", "proxy", s.name, "backlog", s.listenBacklog)

	// The PROXY protocol header travels in plaintext AHEAD of the TLS
	// ClientHello, so the header reader must sit between the TCP socket and
	// the TLS layer: the header is read from the raw stream, and the deferred
	// TLS handshake then reads THROUGH the PROXY conn, consuming any
	// ClientHello bytes its bufio buffered alongside the header. Wrapping in
	// the other order makes the handshake read the raw socket and miss those
	// bytes (broken PROXY+TLS combo).
	base := server.WrapProxyProtocol(tcpListener, s.proxyReader, "POP3-PROXY")

	if s.tlsConfig != nil {
		// Use SoraTLSListener for TLS with JA4 capture and timeout protection
		listener = server.NewSoraTLSListener(base, s.tlsConfig, connConfig)
	} else {
		// Use SoraListener for non-TLS with timeout protection
		listener = server.NewSoraListener(base, connConfig)
	}
	defer listener.Close()

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.appCtx)
	}

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		listener.Close()
	}()

	// Startup throttle: spread reconnection load after proxy restart
	// to prevent thundering herd on the database connection pool
	s.startupThrottleUntil = time.Now().Add(30 * time.Second)
	logger.Info("POP3 Proxy: Startup throttle active for 30s (5ms delay between accepts)", "proxy", s.name)

	// Start session monitoring routine
	go s.monitorActiveSessions()

	return s.acceptConnections(listener)
}

func (s *POP3ProxyServer) acceptConnections(listener net.Listener) error {
	for {
		// Startup throttle: spread reconnection load after proxy restart
		// to prevent thundering herd on the database connection pool
		if time.Now().Before(s.startupThrottleUntil) {
			time.Sleep(5 * time.Millisecond)
		}

		conn, err := listener.Accept()
		if err != nil {
			// If context is cancelled, listener.Close() was called, so this is a graceful shutdown.
			if s.appCtx.Err() != nil {
				return nil
			}
			// All Accept() errors are connection-level issues (TLS handshake failures, client disconnects, etc.)
			// They should be logged but not crash the server - the listener itself is still healthy
			logger.Debug("POP3 Proxy: Failed to accept connection", "proxy", s.name, "error", err)
			continue // Continue accepting other connections
		}

		// PROXY protocol handling happens inside the listener chain (the
		// header must be read from the raw stream BEFORE the TLS wrapper);
		// NewSession discovers the proxyProtocolConn via the Unwrap walk.

		// Connection counters are incremented in NewSession once the
		// connection is past the limiter and TLS handshake, so rejected
		// connections never inflate the gauges (they have no session to
		// decrement them).

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("POP3 Proxy: panic in connection handler", "panic", r, "stack", string(debug.Stack()))
				}
			}()
			s.pop3libServer.Load().ServeConn(conn)
		}()
	}
}

// SetConnectionTracker sets the connection tracker for the server.
func (s *POP3ProxyServer) SetConnectionTracker(tracker *server.ConnectionTracker) {
	s.connTracker = tracker
	// Enable cache invalidation on kick events if lookup cache is available
	if tracker != nil && s.lookupCache != nil {
		tracker.SetLookupCache(s.lookupCache)
	}
}

// GetConnectionTracker returns the connection tracker for the server.
func (s *POP3ProxyServer) GetConnectionTracker() *server.ConnectionTracker {
	return s.connTracker
}

// GetConnectionManager returns the connection manager for health checks
func (s *POP3ProxyServer) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

func (s *POP3ProxyServer) Stop() error {
	logger.Debug("POP3 Proxy: Stopping", "proxy", s.name)

	// Unregister rate limiter from global registry
	server.UnregisterRateLimiter("pop3_proxy", s.name)

	// Stop connection tracker first to prevent it from trying to access closed database
	if s.connTracker != nil {
		s.connTracker.Stop()
	}

	// Send graceful shutdown messages to all active sessions
	s.sendGracefulShutdownMessage()

	if s.cancel != nil {
		s.cancel()
	}

	// Also cancel the library-side connection contexts so in-flight pre-auth
	// work aborts instead of running to its own timeout. Sessions accepted
	// under a pre-SIGHUP snapshot are not covered here, but the shutdown
	// broadcast above already closed their sockets.
	if lib := s.pop3libServer.Load(); lib != nil {
		lib.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("POP3 Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Debug("POP3 Proxy: Server stop timeout", "proxy", s.name)
	}

	// Close remotelookup client if it exists
	if s.connManager != nil {
		if routingLookup := s.connManager.GetRoutingLookup(); routingLookup != nil {
			logger.Debug("POP3 Proxy: Closing remotelookup client", "proxy", s.name)
			if err := routingLookup.Close(); err != nil {
				logger.Debug("POP3 Proxy: Error closing remotelookup client", "proxy", s.name, "error", err)
			}
		}
	}

	// Stop auth cache
	if s.lookupCache != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := s.lookupCache.Stop(stopCtx); err != nil {
			logger.Error("Error stopping auth cache", "proxy", s.name, "error", err)
		}
	}

	return nil
}

// addSession tracks an active session for graceful shutdown
func (s *POP3ProxyServer) addSession(session *POP3ProxySession) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	s.activeSessions[session] = struct{}{}
}

// removeSession removes a session from active tracking
func (s *POP3ProxyServer) removeSession(session *POP3ProxySession) {
	s.activeSessionsMu.Lock()
	defer s.activeSessionsMu.Unlock()
	delete(s.activeSessions, session)
}

// sendGracefulShutdownMessage sends a shutdown error message to all active client connections
// and QUIT to backend servers for clean shutdown
func (s *POP3ProxyServer) sendGracefulShutdownMessage() {
	s.activeSessionsMu.RLock()
	activeSessions := make([]*POP3ProxySession, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		activeSessions = append(activeSessions, session)
	}
	s.activeSessionsMu.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	logger.Debug("POP3 Proxy: Sending graceful shutdown messages to active connections", "proxy", s.name, "count", len(activeSessions))

	// Step 1: Set gracefulShutdown flag on all sessions.
	for _, session := range activeSessions {
		session.mutex.Lock()
		session.gracefulShutdown = true
		session.mutex.Unlock()
	}

	// Step 2: Write shutdown message directly to clientConn.
	for _, session := range activeSessions {
		session.mutex.Lock()
		if session.clientConn != nil {
			_, _ = fmt.Fprint(session.clientConn, "-ERR Server shutting down, please reconnect\r\n")
		}
		session.mutex.Unlock()
	}

	// Step 3: Give clients a moment to process the message before closing.
	time.Sleep(1 * time.Second)

	// Step 4: Close all connections.
	for _, session := range activeSessions {
		session.mutex.Lock()
		if session.backendConn != nil {
			session.backendConn.Close()
		}
		if session.clientConn != nil {
			session.clientConn.Close()
		}
		session.mutex.Unlock()
	}

	logger.Debug("POP3 Proxy: Proceeding with connection cleanup", "proxy", s.name)
}

// monitorActiveSessions periodically logs active session count for monitoring
func (s *POP3ProxyServer) monitorActiveSessions() {
	// Log every 5 minutes (similar to connection tracker cleanup interval)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.activeSessionsMu.RLock()
			count := len(s.activeSessions)
			s.activeSessionsMu.RUnlock()

			// Get unique user count from connection tracker (cluster-wide)
			var uniqueUsers int
			if s.connTracker != nil {
				uniqueUsers = s.connTracker.GetUniqueUserCount()
			}

			// Also log connection limiter stats
			var limiterStats string
			if s.limiter != nil {
				stats := s.limiter.GetStats()
				limiterStats = fmt.Sprintf(" limiter_total=%d limiter_max=%d", stats.TotalConnections, stats.MaxConnections)
			}

			logger.Info("POP3 proxy active sessions", "proxy", s.name, "active_sessions", count, "unique_users", uniqueUsers, "limiter_stats", limiterStats)

		case <-s.appCtx.Done():
			return
		}
	}
}

// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new connections; existing sessions keep old settings.
func (s *POP3ProxyServer) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string

	// Update max auth errors
	if newVal := cfg.GetMaxAuthErrors(); newVal != s.maxAuthErrors {
		s.maxAuthErrors = newVal
		reloaded = append(reloaded, "max_auth_errors")
	}

	// Update timeouts (affect new connections only)
	if timeout := cfg.GetAuthIdleTimeoutWithDefault(); timeout != s.authIdleTimeout {
		s.authIdleTimeout = timeout
		reloaded = append(reloaded, "auth_idle_timeout")
	}
	if timeout, err := cfg.GetCommandTimeout(); err == nil && timeout != s.commandTimeout {
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

	// Update master credentials
	if cfg.MasterSASLUsername != s.masterSASLUsername {
		s.masterSASLUsername = cfg.MasterSASLUsername
		reloaded = append(reloaded, "master_sasl_username")
	}
	if cfg.MasterSASLPassword != s.masterSASLPassword {
		s.masterSASLPassword = cfg.MasterSASLPassword
		reloaded = append(reloaded, "master_sasl_password")
	}

	// Update debug flag
	if cfg.Debug != s.debug {
		s.debug = cfg.Debug
		reloaded = append(reloaded, "debug")
	}

	if len(reloaded) > 0 {
		// Rebuild the protocol server so new connections pick up the reloaded
		// settings; existing connections keep the snapshot they started with.
		s.pop3libServer.Store(s.buildLibServer())
		logger.Info("POP3 proxy config reloaded", "name", s.name, "updated", reloaded)
	}
	return nil
}

// GetLimiter returns the connection limiter for testing purposes
func (s *POP3ProxyServer) GetLimiter() *server.ConnectionLimiter {
	return s.limiter
}
