package lmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

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

		// Extract real client IP and proxy info if this is a PROXY protocol connection
		var realClientIP string
		var proxyInfo *server.ProxyProtocolInfo
		if proxyConn, ok := conn.(*proxyProtocolConn); ok {
			proxyInfo = proxyConn.GetProxyInfo()
			if proxyInfo != nil && proxyInfo.SrcIP != "" {
				realClientIP = proxyInfo.SrcIP
			}
		}

		// Check connection limits with PROXY protocol support
		releaseConn, limitErr := l.limiter.AcceptWithRealIP(conn.RemoteAddr(), realClientIP)
		if limitErr != nil {
			logger.Debug("LMTP: Connection rejected", "name", l.name, "error", limitErr)
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
}

// GetProxyInfo implements the same interface as proxyProtocolConn
func (c *connectionLimitingConn) GetProxyInfo() *server.ProxyProtocolInfo {
	return c.proxyInfo
}

func (c *connectionLimitingConn) Close() error {
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

	// Connection counters
	totalConnections  atomic.Int64
	activeConnections atomic.Int64

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// Trusted networks for connection filtering
	trustedNetworks []*net.IPNet

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
	MaxMessageSize              int64 // Maximum size for incoming messages in bytes
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
		logger.Debug("LMTP: WARNING - tls_use_starttls ignored", "name", name)
		// Force TLSUseStartTLS to false to avoid confusion
		options.TLSUseStartTLS = false
	}

	backend := &LMTPServerBackend{
		addr:           addr,
		name:           name,
		appCtx:         appCtx,
		hostname:       hostname,
		rdb:            rdb,
		s3:             s3,
		uploader:       uploadWorker,
		debug:          options.Debug,
		ftsRetention:   options.FTSRetention,
		maxMessageSize: options.MaxMessageSize,
		proxyReader:    proxyReader,
		relayQueue:     options.RelayQueue,
		relayWorker:    options.RelayWorker,
	}

	// Create connection limiter with trusted networks from proxy configuration
	// LMTP doesn't use per-IP connection limits, only total connection limits
	limiterTrustedProxies := server.GetTrustedProxiesForServer(backend.proxyReader)
	backend.limiter = server.NewConnectionLimiterWithTrustedNets("LMTP", options.MaxConnections, 0, limiterTrustedProxies)

	// Set listen backlog with reasonable default
	backend.listenBacklog = options.ListenBacklog
	if backend.listenBacklog == 0 {
		backend.listenBacklog = 1024 // Default backlog
	}

	// Initialize Sieve script cache with a reasonable default size and TTL
	// 5 minute TTL ensures cross-server updates are picked up relatively quickly
	backend.sieveCache = NewSieveScriptCache(100, 5*time.Minute)

	// Parse and cache the default Sieve script at startup
	// The default script uses fileinto extension, so we need to allow it
	defaultExecutor, err := sieveengine.NewSieveExecutorWithExtensions(defaultSieveScript, []string{"fileinto"})
	if err != nil {
		return nil, fmt.Errorf("failed to parse default Sieve script: %w", err)
	}
	backend.defaultSieveExecutor = defaultExecutor
	logger.Debug("LMTP: Default Sieve script parsed and cached", "name", backend.name)

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
			logger.Debug("LMTP: WARNING - TLS certificate verification disabled", "name", name)
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
	s.AllowInsecureAuth = true
	s.LMTP = true

	// Configure XCLIENT support (always enabled)
	s.EnableXCLIENT = true

	// Configure XRCPTFORWARD support (always enabled)
	// Enable custom RCPT TO parameters like XRCPTFORWARD
	s.EnableRCPTExtensions = true

	// Set trusted networks for XCLIENT using global trusted networks
	var trustedProxies []string
	if len(options.TrustedNetworks) > 0 {
		// Use global trusted networks
		trustedProxies = options.TrustedNetworks
	} else {
		// Use safe default trusted networks (RFC1918 private networks + localhost)
		trustedProxies = []string{
			"127.0.0.0/8",    // localhost
			"::1/128",        // IPv6 localhost
			"10.0.0.0/8",     // RFC1918 private networks
			"172.16.0.0/12",  // RFC1918 private networks
			"192.168.0.0/16", // RFC1918 private networks
		}
	}

	trustedNets, err := server.ParseTrustedNetworks(trustedProxies)
	if err != nil {
		// Log the error and use empty trusted networks to prevent server crash
		logger.Debug("LMTP: WARNING - failed to parse trusted networks, XCLIENT disabled", "name", name, "error", err)
		trustedNets = []*net.IPNet{}
	}
	s.XCLIENTTrustedNets = trustedNets

	// Store trusted networks in backend for connection filtering
	backend.trustedNetworks = trustedNets

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		logger.Debug("LMTP: StartTLS is enabled", "name", name)
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
			logger.Debug("LMTP: Connection rejected - invalid address format", "name", b.name, "remote", remoteAddr)
			return nil, fmt.Errorf("invalid remote address format")
		}
		ip = net.ParseIP(host)
		if ip == nil {
			logger.Debug("LMTP: Connection rejected - could not parse IP", "name", b.name, "remote", remoteAddr)
			return nil, fmt.Errorf("could not parse remote IP address")
		}
	}

	if !b.isFromTrustedNetwork(ip) {
		logger.Warn("LMTP: Connection rejected - not from trusted network", "name", b.name, "ip", ip, "remote", remoteAddr)
		return nil, fmt.Errorf("LMTP connections only allowed from trusted networks")
	}

	// Connection limits are now handled at the listener level
	sessionCtx, sessionCancel := context.WithCancel(b.appCtx)

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)
	b.activeConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("lmtp").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("lmtp").Inc()

	s := &LMTPSession{
		backend:   b,
		conn:      c,
		ctx:       sessionCtx,
		cancel:    sessionCancel,
		startTime: time.Now(),
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	// Need to unwrap connection layers to get to proxyProtocolConn
	netConn := c.Conn()
	var proxyInfo *server.ProxyProtocolInfo
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

	clientIP, proxyIP := server.GetConnectionIPs(netConn, proxyInfo)
	s.RemoteIP = clientIP
	s.ProxyIP = proxyIP
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
	s.InfoLog("new session remote=%s id=%s (connections: active=%d)",
		s.RemoteIP, s.Id, activeCount)

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
	logger.Debug("LMTP: Using custom listen backlog", "server", b.name, "backlog", b.listenBacklog)

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - wrap TCP listener with TLS
		listener = tls.NewListener(tcpListener, b.tlsConfig)
		logger.Info("LMTP server listening with TLS", "name", b.name, "addr", b.server.Addr)
	} else {
		listener = tcpListener
		logger.Info("LMTP server listening", "name", b.name, "addr", b.server.Addr, "tls", false)
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if b.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: b.proxyReader,
		}
	}

	// Wrap listener with connection limiting
	limitedListener := &connectionLimitingListener{
		Listener: listener,
		limiter:  b.limiter,
		name:     b.name,
	}

	if err := b.server.Serve(limitedListener); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		if b.appCtx.Err() != nil {
			logger.Info("LMTP server stopped gracefully", "name", b.name)
		} else {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	} else {
		// Server closed without error (shouldn't normally happen, but handle gracefully)
		logger.Info("LMTP server stopped gracefully", "name", b.name)
	}
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

// proxyProtocolListener wraps a listener to handle PROXY protocol
type proxyProtocolListener struct {
	net.Listener
	proxyReader *server.ProxyProtocolReader
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
		// This requires the underlying ProxyProtocolReader to be updated to return a specific error (e.g., server.ErrNoProxyHeader)
		// and to not consume bytes from the connection if no header is found.
		if l.proxyReader.IsOptionalMode() && errors.Is(err, server.ErrNoProxyHeader) {
			// Note: We don't have access to server name in this listener, use generic LMTP
			logger.Debug("LMTP: No PROXY protocol header - treating as direct", "remote", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic LMTP
		logger.Debug("LMTP: PROXY protocol error - rejecting", "remote", conn.RemoteAddr(), "error", err)
		continue
	}
}

// proxyProtocolConn wraps a connection with PROXY protocol information
type proxyProtocolConn struct {
	net.Conn
	proxyInfo *server.ProxyProtocolInfo
}

func (c *proxyProtocolConn) GetProxyInfo() *server.ProxyProtocolInfo {
	return c.proxyInfo
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
			logger.Info("LMTP server active connections", "name", b.name, "active_connections", count, "limiter_stats", limiterStats)

		case <-b.appCtx.Done():
			return
		}
	}
}

// GetLimiter returns the connection limiter for testing purposes
func (b *LMTPServerBackend) GetLimiter() *server.ConnectionLimiter {
	return b.limiter
}
