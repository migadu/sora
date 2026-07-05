package lmtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// DefaultMaxMessageSize is the default maximum message size for LMTP (50MB)
const DefaultMaxMessageSize = 50 * 1024 * 1024

// defaultLMTPMaxConnections bounds total concurrent LMTP connections when the operator
// leaves max_connections unset. Generous enough not to throttle legitimate burst delivery
// from internal MTAs, but finite so a single trusted source cannot exhaust resources.
// (security-audit M13)
const defaultLMTPMaxConnections = 1000

// getProxyProtocolTrustedProxies returns proxy_protocol_trusted_proxies if set, otherwise falls back to trusted_networks
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

// connectionLimitingListener wraps a net.Listener to enforce connection limits at the TCP level
type connectionLimitingListener struct {
	net.Listener
	limiter *server.ConnectionLimiter
	name    string
}

// Accept accepts connections and checks connection limits before returning them
func (l *connectionLimitingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Extract real client IP and proxy info if this is a PROXY protocol
		// connection. The PROXY conn sits INSIDE the TLS layer (the header is
		// read from the raw stream before any TLS processing), so on
		// implicit-TLS listeners the accepted conn is a *tls.Conn; the walk
		// traverses it via NetConn(), which never triggers the handshake.
		var realClientIP string
		proxyInfo := server.GetProxyProtocolInfo(conn)
		if proxyInfo != nil && proxyInfo.SrcIP != "" {
			realClientIP = proxyInfo.SrcIP
		}

		// Check connection limits with PROXY protocol support
		releaseConn, limitErr := l.limiter.AcceptWithRealIP(conn.RemoteAddr(), realClientIP)
		if limitErr != nil {
			logger.Debug("connection rejected", "name", l.name, "error", limitErr)
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
	proxyInfo   *server.ProxyProtocolInfo
	closeMu     sync.Mutex
	closed      bool
}

// GetProxyInfo implements the same interface as server.ProxyProtocolConn
func (c *connectionLimitingConn) GetProxyInfo() *server.ProxyProtocolInfo {
	return c.proxyInfo
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

type LMTPServerBackend struct {
	addr           string
	name           string
	hostname       string
	rdb            *resilient.ResilientDatabase
	s3             *storage.S3Storage
	uploader       *uploader.UploadWorker
	server         *smtp.Server
	appCtx         context.Context
	tlsConfig      *tls.Config
	debug          bool
	ftsRetention   time.Duration
	maxMessageSize int64               // Maximum size for incoming messages
	relayQueue     delivery.RelayQueue // Disk-based queue for relay retry
	relayWorker    RelayWorkerNotifier // Optional: notifies worker for immediate processing

	redirectRateLimit  int
	redirectRateWindow time.Duration
	maxRedirectHops    int

	// Per-command hard execution timeouts (nil = use defaults)
	commandTimeouts *CommandTimeouts

	// Connection counters
	totalConnections  atomic.Int64
	activeConnections atomic.Int64

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// Trusted networks for connection admission (NewSession). Defaults to private
	// networks when trusted_networks is unset, since LMTP is internal-only.
	trustedNetworks []*net.IPNet

	// Trusted networks permitted to override the real client IP via XCLIENT/XRCPTFORWARD.
	// Fails closed: empty = trust nobody (no RFC1918 default), unlike trustedNetworks. (M2)
	xclientTrustedNets []*net.IPNet

	// Sieve script caching
	sieveCache           *SieveScriptCache
	defaultSieveExecutor sieveengine.Executor

	// PROXY protocol support
	proxyReader *server.ProxyProtocolReader
}

// RelayWorkerNotifier provides immediate processing notification for relay workers
type RelayWorkerNotifier interface {
	NotifyQueued()
}

type LMTPServerOptions struct {
	RelayQueue                  delivery.RelayQueue // Global relay queue for Sieve redirect/vacation
	RelayWorker                 RelayWorkerNotifier // Optional: notifies worker for immediate processing
	Debug                       bool
	TLS                         bool
	TLSCertFile                 string
	TLSKeyFile                  string
	TLSVerify                   bool
	TLSUseStartTLS              bool
	TLSConfig                   *tls.Config // Global TLS config from TLS manager (optional)
	MaxConnections              int
	MaxConnectionsPerIP         int
	ListenBacklog               int      // TCP listen backlog size (0 = use default 1024)
	ProxyProtocol               bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout        string   // Timeout for reading PROXY headers
	ProxyProtocolTrustedProxies []string // CIDR blocks for PROXY protocol validation (defaults to trusted_networks if empty)
	TrustedNetworks             []string // Global trusted networks for parameter forwarding
	FTSRetention                time.Duration
	MaxMessageSize              int64    // Maximum size for incoming messages in bytes
	SieveExtensions             []string // Sieve extensions to enable (nil/empty = all default extensions)
	InsecureAuth                bool     // Allow PLAIN auth over non-TLS connections (default: true for LMTP behind trusted network)
	RedirectRateLimit           int
	RedirectRateWindow          time.Duration
	MaxRedirectHops             int
	CommandTimeoutOverrides     map[string]time.Duration // Per-command hard execution timeouts (overrides defaults)
	IdleTimeout                 time.Duration            // Maximum idle time between commands (0 = default 5m); enforced by go-smtp with a 421 notice
}

func New(appCtx context.Context, name, hostname, addr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, options LMTPServerOptions) (*LMTPServerBackend, error) {
	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		// Create ProxyProtocolConfig from simplified settings
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Mode:           "required",
			TrustedProxies: getProxyProtocolTrustedProxies(options.ProxyProtocolTrustedProxies, options.TrustedNetworks),
			Timeout:        options.ProxyProtocolTimeout,
		}

		// Proxy protocol is always required when enabled

		var err error
		proxyReader, err = server.NewProxyProtocolReader("LMTP", proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	// Validate TLS configuration: tls_use_starttls only makes sense when tls = true
	if !options.TLS && options.TLSUseStartTLS {
		logger.Debug("tls_use_starttls ignored", "name", name)
		// Force TLSUseStartTLS to false to avoid confusion
		options.TLSUseStartTLS = false
	}

	backend := &LMTPServerBackend{
		addr:               addr,
		name:               name,
		appCtx:             appCtx,
		hostname:           hostname,
		rdb:                rdb,
		s3:                 s3,
		uploader:           uploadWorker,
		debug:              options.Debug,
		ftsRetention:       options.FTSRetention,
		maxMessageSize:     options.MaxMessageSize,
		proxyReader:        proxyReader,
		relayQueue:         options.RelayQueue,
		relayWorker:        options.RelayWorker,
		redirectRateLimit:  options.RedirectRateLimit,
		redirectRateWindow: options.RedirectRateWindow,
		maxRedirectHops:    options.MaxRedirectHops,
		commandTimeouts:    defaultCommandTimeouts(),
	}

	// Apply operator overrides for per-command execution timeouts
	if len(options.CommandTimeoutOverrides) > 0 {
		backend.commandTimeouts.ApplyOverrides(options.CommandTimeoutOverrides)
	}

	// Create connection limiter with trusted networks from proxy configuration.
	// LMTP doesn't use per-IP connection limits (per-IP=0) — internal MTAs legitimately
	// fan many concurrent deliveries through a single trusted source IP, so a per-IP cap
	// would throttle normal traffic. We DO enforce a total ceiling: without one a single
	// trusted source could open unbounded connections and exhaust goroutines/memory. When
	// max_connections is unset (<=0) we apply a generous default rather than "unlimited",
	// matching the listenBacklog default below. (security-audit M13)
	maxConnections := options.MaxConnections
	if maxConnections <= 0 {
		maxConnections = defaultLMTPMaxConnections
		logger.Info("LMTP: max_connections unset; applying default total connection ceiling", "name", name, "max_connections", maxConnections)
	}
	limiterTrustedProxies := server.GetTrustedProxiesForServer(backend.proxyReader)
	backend.limiter = server.NewConnectionLimiterWithTrustedNets("LMTP", maxConnections, 0, limiterTrustedProxies)

	// Set listen backlog with reasonable default
	backend.listenBacklog = options.ListenBacklog
	if backend.listenBacklog == 0 {
		backend.listenBacklog = 1024 // Default backlog
	}

	// Initialize Sieve script cache with a reasonable default size and TTL
	// 5 minute TTL ensures cross-server updates are picked up relatively quickly
	backend.sieveCache = NewSieveScriptCache(100, 5*time.Minute, options.SieveExtensions)

	// Parse and cache the default Sieve script at startup
	// Use the same extensions as configured for user scripts (or all if not specified)
	defaultExtensions := options.SieveExtensions
	if len(defaultExtensions) == 0 {
		defaultExtensions = sieveengine.DefaultSieveExtensions
	}
	defaultExecutor, err := sieveengine.NewSieveExecutorWithExtensions(defaultSieveScript, defaultExtensions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default Sieve script: %w", err)
	}
	backend.defaultSieveExecutor = defaultExecutor
	logger.Debug("default sieve script parsed and cached", "name", backend.name)

	// Set up TLS config: Support both file-based certificates and global TLS manager
	// 1. Per-server TLS: cert files provided (for both implicit TLS and STARTTLS)
	// 2. Global TLS: options.TLS=true, no cert files, global TLS config provided (for both implicit TLS and STARTTLS)
	// 3. No TLS: options.TLS=false
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
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
			NextProtos:               []string{"lmtp"},
			Renegotiation:            tls.RenegotiateNever,
		}

		if !options.TLSVerify {
			backend.tlsConfig.InsecureSkipVerify = true
			logger.Debug("tls certificate verification disabled", "name", name)
		}
	} else if options.TLS && options.TLSConfig != nil {
		// Scenario 2: Global TLS manager (works for both implicit TLS and STARTTLS)
		backend.tlsConfig = options.TLSConfig
	} else if options.TLS {
		// TLS enabled but no cert files and no global TLS config provided
		return nil, fmt.Errorf("TLS enabled for LMTP [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", name)
	}

	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	// Seed every connection's context (smtp.Conn.Context) from the application
	// context: go-smtp cancels the derived context when the client disconnects,
	// the connection ends, or the server shuts down, and BaseContext adds app
	// shutdown on top. Sessions derive their context from it in NewSession.
	s.BaseContext = func(net.Listener) context.Context { return appCtx }
	s.AllowInsecureAuth = options.InsecureAuth
	s.LMTP = true
	s.MaxRecipients = 1 // Enforce single recipient per LMTP transaction.
	// Our session processes one recipient at a time (Rcpt overwrites).
	// This makes the behavior explicit and advertises LIMITS RCPTMAX=1 in LHLO,
	// so the MTA sends each recipient in a separate transaction.

	// Bound idle/slow connections so a held connection cannot pin a goroutine
	// indefinitely (slowloris). Generous values: legit transactions finish in
	// seconds. go-smtp is the single idle owner (it writes the 421 4.4.2
	// notice); its hook below is the only place LMTP timeout disconnects are
	// counted — do NOT add a SoraConn idle checker on top (two owners of the
	// same timer race each other and can duplicate the notice).
	s.ReadTimeout = 5 * time.Minute
	if options.IdleTimeout > 0 {
		s.ReadTimeout = options.IdleTimeout
	}
	s.WriteTimeout = 2 * time.Minute
	s.OnTimeout = func() {
		metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", name, hostname, "idle").Inc()
	}

	// Configure XCLIENT support (always enabled)
	s.EnableXCLIENT = true

	// Configure XRCPTFORWARD support (always enabled)
	// Enable custom RCPT TO parameters like XRCPTFORWARD
	s.EnableRCPTExtensions = true

	// Connection admission (NewSession): LMTP is internal-only, so when trusted_networks
	// is unset we default to private networks. This gate intentionally keeps the RFC1918
	// default — emptying the list must NOT silently reject all delivery.
	admissionProxies := options.TrustedNetworks
	if len(admissionProxies) == 0 {
		admissionProxies = []string{
			"127.0.0.0/8",    // localhost
			"::1/128",        // IPv6 localhost
			"10.0.0.0/8",     // RFC1918 private networks
			"172.16.0.0/12",  // RFC1918 private networks
			"192.168.0.0/16", // RFC1918 private networks
		}
		logger.Info("LMTP: trusted_networks empty; accepting delivery from default private ranges (RFC1918+localhost). Set trusted_networks to restrict.", "name", name)
	}
	admissionNets, err := helpers.ParseTrustedNetworks(admissionProxies)
	if err != nil {
		// Log the error and use empty trusted networks to prevent server crash
		logger.Debug("failed to parse trusted networks, connection admission disabled", "name", name, "error", err)
		admissionNets = []*net.IPNet{}
	}
	backend.trustedNetworks = admissionNets

	// XCLIENT / XRCPTFORWARD source-IP override: fail closed. Use ONLY the explicitly
	// configured trusted_networks (no RFC1918 default), matching IMAP (server/imap/id.go)
	// and POP3 (server/pop3/xclient.go), which deny forwarding when the list is empty.
	// Overriding the client IP is a higher privilege than connecting, so it must be granted
	// explicitly. (security-audit M2)
	xclientNets, err := helpers.ParseTrustedNetworks(options.TrustedNetworks)
	if err != nil {
		logger.Debug("failed to parse XCLIENT trusted networks, XCLIENT disabled", "name", name, "error", err)
		xclientNets = []*net.IPNet{}
	}
	backend.xclientTrustedNets = xclientNets
	s.XCLIENTTrustedNets = xclientNets

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		logger.Debug("starttls enabled", "name", name)
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

// isFromTrustedNetwork checks if an IP address is from a trusted network
func (b *LMTPServerBackend) isFromTrustedNetwork(ip net.IP) bool {
	for _, network := range b.trustedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (b *LMTPServerBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// Check if connection is from a trusted network
	remoteAddr := c.Conn().RemoteAddr()
	var ip net.IP
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	default:
		// Try to parse as string
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			logger.Debug("connection rejected - invalid address format", "name", b.name, "remote_addr", remoteAddr)
			return nil, fmt.Errorf("invalid remote address format")
		}
		ip = net.ParseIP(host)
		if ip == nil {
			logger.Debug("connection rejected - could not parse ip", "name", b.name, "remote_addr", remoteAddr)
			return nil, fmt.Errorf("could not parse remote IP address")
		}
	}

	if !b.isFromTrustedNetwork(ip) {
		logger.Warn("connection rejected - not from trusted network", "name", b.name, "ip", ip, "remote_addr", remoteAddr)
		return nil, fmt.Errorf("LMTP connections only allowed from trusted networks")
	}

	// Connection limits are now handled at the listener level.
	// Derive the session context from the connection's context: go-smtp cancels
	// it when the client disconnects or the server shuts down (it inherits app
	// shutdown via Server.BaseContext), so long-running delivery work — DB
	// inserts, Sieve evaluation, S3 staging — aborts once the client can no
	// longer observe the result.
	sessionCtx, sessionCancel := context.WithCancel(c.Context())

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)
	b.activeConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("lmtp", b.name, b.hostname).Inc()
	metrics.ConnectionsCurrent.WithLabelValues("lmtp", b.name, b.hostname).Inc()

	s := &LMTPSession{
		backend:   b,
		conn:      c,
		ctx:       sessionCtx,
		cancel:    sessionCancel,
		startTime: time.Now(),
	}

	// Extract real client IP and proxy IP from PROXY protocol if available.
	// The walk accepts any layer exposing GetProxyInfo(), so it is satisfied
	// by connectionLimitingConn (which cached the info at accept time).
	netConn := c.Conn()
	proxyInfo := server.GetProxyProtocolInfo(netConn)

	clientIP, proxyIP := server.GetConnectionIPs(netConn, proxyInfo)
	s.RemoteIP = clientIP
	s.ProxyIP = proxyIP

	// Re-apply any XCLIENT identity forwarded by a trusted front proxy. go-smtp records
	// XCLIENT attributes only from XCLIENTTrustedNets peers and preserves them on the Conn
	// across the mandatory post-XCLIENT session reset; the XCLIENT() hook, however, ran on
	// the pre-reset session that was discarded. Applying them here rewrites RemoteIP to the
	// real client and populates ForwardingParams (HELO/LOGIN/PROTO) on the session that
	// actually delivers, so the Received: trace and logs name the client, not the proxy.
	if xd := c.XCLIENTData(); len(xd) > 0 {
		s.applyXCLIENTAttrs(xd)
	}

	s.Id = idgen.New()
	s.HostName = b.hostname
	s.ServerName = b.name
	s.Protocol = "LMTP"
	s.Stats = b // Set the server as the Stats provider

	// Create logging function for the mutex helper
	logFunc := func(format string, args ...any) {
		s.InfoLog(format, args...)
	}

	// Initialize the mutex helper
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "LMTP", logFunc)

	// Log connection with connection counters
	activeCount := b.activeConnections.Load()
	s.InfoLog("new session", "id", s.Id, "active_count", activeCount)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	var listener net.Listener
	var err error

	// Start active connections monitoring
	go b.monitorActiveConnections()

	// Create base TCP listener with custom backlog
	tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", b.server.Addr, b.listenBacklog)
	if err != nil {
		errChan <- fmt.Errorf("failed to create listener: %w", err)
		return
	}
	logger.Debug("using custom listen backlog", "server", b.name, "backlog", b.listenBacklog)

	// The PROXY protocol header travels in plaintext AHEAD of the TLS
	// ClientHello, so the header reader must sit between the TCP socket and
	// the TLS layer: the header is read from the raw stream, and crypto/tls
	// then handshakes lazily THROUGH the PROXY conn on first I/O, consuming
	// any ClientHello bytes its bufio buffered alongside the header. Wrapping
	// in the other order makes the eager TLS conn handshake against the
	// plaintext "PROXY ..." line and fail on every connection. STARTTLS mode
	// (b.server.TLSConfig set) is unaffected: TLS is negotiated in-protocol,
	// long after the header.
	base := server.WrapProxyProtocol(tcpListener, b.proxyReader, "LMTP")

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - wrap PROXY-aware listener with TLS
		listener = tls.NewListener(base, b.tlsConfig)
		logger.Info("lmtp server listening with tls", "name", b.name, "addr", b.server.Addr)
	} else {
		listener = base
		logger.Info("lmtp server listening", "name", b.name, "addr", b.server.Addr, "tls", false)
	}
	defer listener.Close()

	// Wrap listener with connection limiting
	limitedListener := &connectionLimitingListener{
		Listener: listener,
		limiter:  b.limiter,
		name:     b.name,
	}

	if err := b.server.Serve(limitedListener); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		if b.appCtx.Err() != nil {
			logger.Info("lmtp server stopped gracefully", "name", b.name)
		} else {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	} else {
		// Server closed without error (shouldn't normally happen, but handle gracefully)
		logger.Info("lmtp server stopped gracefully", "name", b.name)
	}
}

// ReloadConfig updates runtime-configurable settings from new config.
// Called on SIGHUP. Only affects new deliveries; in-flight messages keep old settings.
func (b *LMTPServerBackend) ReloadConfig(cfg config.ServerConfig) error {
	var reloaded []string

	if maxSize := cfg.GetMaxMessageSizeWithDefault(); maxSize != b.maxMessageSize {
		b.maxMessageSize = maxSize
		reloaded = append(reloaded, "max_message_size")
	}
	if cfg.Debug != b.debug {
		b.debug = cfg.Debug
		reloaded = append(reloaded, "debug")
	}

	if len(reloaded) > 0 {
		logger.Info("LMTP config reloaded", "name", b.name, "updated", reloaded)
	}
	return nil
}

func (b *LMTPServerBackend) Close() error {
	if b.server != nil {
		return b.server.Close()
	}
	return nil
}

// GetTotalConnections returns the cumulative total of all connections ever made
func (b *LMTPServerBackend) GetTotalConnections() int64 {
	return b.totalConnections.Load()
}

// GetActiveConnections returns the current number of active connections
func (b *LMTPServerBackend) GetActiveConnections() int64 {
	return b.activeConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
// For LMTP, all connections are considered authenticated
func (b *LMTPServerBackend) GetAuthenticatedConnections() int64 {
	return 0
}

// monitorActiveConnections periodically logs active connection count for monitoring
func (b *LMTPServerBackend) monitorActiveConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			count := b.activeConnections.Load()

			// Also log connection limiter stats
			var limiterStats string
			if b.limiter != nil {
				stats := b.limiter.GetStats()
				limiterStats = fmt.Sprintf(" limiter_total=%d limiter_max=%d", stats.TotalConnections, stats.MaxConnections)
			}
			logger.Info("lmtp server active connections", "name", b.name, "active_connections", count, "limiter_stats", limiterStats)

		case <-b.appCtx.Done():
			return
		}
	}
}

// GetLimiter returns the connection limiter for testing purposes
func (b *LMTPServerBackend) GetLimiter() *server.ConnectionLimiter {
	return b.limiter
}
