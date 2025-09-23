package lmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type LMTPServerBackend struct {
	addr          string
	hostname      string
	rdb           *resilient.ResilientDatabase
	s3            *storage.S3Storage
	uploader      *uploader.UploadWorker
	server        *smtp.Server
	appCtx        context.Context
	externalRelay string
	tlsConfig     *tls.Config
	debug         bool
	ftsRetention  time.Duration

	// Connection counters
	totalConnections atomic.Int64

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Trusted networks for connection filtering
	trustedNetworks []*net.IPNet

	// Sieve script caching
	sieveCache           *SieveScriptCache
	defaultSieveExecutor sieveengine.Executor

	// PROXY protocol support
	proxyReader *server.ProxyProtocolReader
}

type LMTPServerOptions struct {
	ExternalRelay        string
	Debug                bool
	TLS                  bool
	TLSCertFile          string
	TLSKeyFile           string
	TLSVerify            bool
	TLSUseStartTLS       bool
	MaxConnections       int
	MaxConnectionsPerIP  int
	ProxyProtocol        bool     // Enable PROXY protocol support (always required when enabled)
	ProxyProtocolTimeout string   // Timeout for reading PROXY headers
	TrustedNetworks      []string // Global trusted networks for parameter forwarding
	FTSRetention         time.Duration
}

func New(appCtx context.Context, hostname, addr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, options LMTPServerOptions) (*LMTPServerBackend, error) {
	// Initialize PROXY protocol reader if enabled
	var proxyReader *server.ProxyProtocolReader
	if options.ProxyProtocol {
		// Create ProxyProtocolConfig from simplified settings
		proxyConfig := server.ProxyProtocolConfig{
			Enabled:        true,
			Mode:           "required",
			TrustedProxies: options.TrustedNetworks,
			Timeout:        options.ProxyProtocolTimeout,
		}

		// Proxy protocol is always required when enabled

		var err error
		proxyReader, err = server.NewProxyProtocolReader("LMTP", proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PROXY protocol reader: %w", err)
		}
	}

	backend := &LMTPServerBackend{
		addr:          addr,
		appCtx:        appCtx,
		hostname:      hostname,
		rdb:           rdb,
		s3:            s3,
		uploader:      uploadWorker,
		externalRelay: options.ExternalRelay,
		debug:         options.Debug,
		ftsRetention:  options.FTSRetention,
		limiter:       server.NewConnectionLimiter("LMTP", options.MaxConnections, options.MaxConnectionsPerIP),
		proxyReader:   proxyReader,
	}

	// Initialize Sieve script cache with a reasonable default size and TTL
	// 5 minute TTL ensures cross-server updates are picked up relatively quickly
	backend.sieveCache = NewSieveScriptCache(100, 5*time.Minute)

	// Parse and cache the default Sieve script at startup
	defaultExecutor, err := sieveengine.NewSieveExecutor(defaultSieveScript)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default Sieve script: %w", err)
	}
	backend.defaultSieveExecutor = defaultExecutor
	log.Printf("LMTP default Sieve script parsed and cached")

	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
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
		}

		if !options.TLSVerify {
			backend.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for LMTP server")
		}
	}

	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	s.AllowInsecureAuth = true
	s.LMTP = true

	// Configure XCLIENT support (always enabled)
	s.EnableXCLIENT = true

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
		log.Printf("WARNING: failed to parse trusted networks for XCLIENT (%v), using empty trusted networks (XCLIENT will be disabled)", err)
		trustedNets = []*net.IPNet{}
	}
	s.XCLIENTTrustedNets = trustedNets

	// Store trusted networks in backend for connection filtering
	backend.trustedNetworks = trustedNets

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		log.Printf("StartTLS is enabled")
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
			log.Printf("[LMTP] Connection rejected from %s: invalid address format", remoteAddr)
			return nil, fmt.Errorf("invalid remote address format")
		}
		ip = net.ParseIP(host)
		if ip == nil {
			log.Printf("[LMTP] Connection rejected from %s: could not parse IP", remoteAddr)
			return nil, fmt.Errorf("could not parse remote IP address")
		}
	}

	if !b.isFromTrustedNetwork(ip) {
		log.Printf("[LMTP] Connection rejected from %s: not from trusted network", ip)
		return nil, fmt.Errorf("LMTP connections only allowed from trusted networks")
	}

	// Check connection limits
	releaseConn, err := b.limiter.Accept(c.Conn().RemoteAddr())
	if err != nil {
		log.Printf("[LMTP] Connection rejected: %v", err)
		return nil, fmt.Errorf("connection limit exceeded: %w", err)
	}

	sessionCtx, sessionCancel := context.WithCancel(b.appCtx)

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)

	// Prometheus metrics - connection established
	metrics.ConnectionsTotal.WithLabelValues("lmtp").Inc()
	metrics.ConnectionsCurrent.WithLabelValues("lmtp").Inc()

	s := &LMTPSession{
		backend:     b,
		conn:        c,
		ctx:         sessionCtx,
		cancel:      sessionCancel,
		releaseConn: releaseConn,
		startTime:   time.Now(),
	}

	// Extract real client IP and proxy IP from PROXY protocol if available
	netConn := c.Conn()
	var proxyInfo *server.ProxyProtocolInfo
	if proxyConn, ok := netConn.(*proxyProtocolConn); ok {
		proxyInfo = proxyConn.GetProxyInfo()
	}

	clientIP, proxyIP := server.GetConnectionIPs(netConn, proxyInfo)
	s.RemoteIP = clientIP
	s.ProxyIP = proxyIP
	s.Id = idgen.New()
	s.HostName = b.hostname
	s.Protocol = "LMTP"
	s.Stats = b // Set the server as the Stats provider

	// Create logging function for the mutex helper
	logFunc := func(format string, args ...interface{}) {
		s.Log(format, args...)
	}

	// Initialize the mutex helper
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "LMTP", logFunc)

	// Log connection with connection counters
	totalCount := b.totalConnections.Load()
	s.Log("new session remote=%s id=%s (connections: total=%d)",
		s.RemoteIP, s.Id, totalCount)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	var listener net.Listener
	var err error

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - use TLS listener
		listener, err = tls.Listen("tcp", b.server.Addr, b.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* LMTP listening with implicit TLS on %s", b.server.Addr)
	} else {
		listener, err = net.Listen("tcp", b.server.Addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* LMTP listening on %s", b.server.Addr)
	}
	defer listener.Close()

	// Wrap listener with PROXY protocol support if enabled
	if b.proxyReader != nil {
		listener = &proxyProtocolListener{
			Listener:    listener,
			proxyReader: b.proxyReader,
		}
	}

	if err := b.server.Serve(listener); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		if b.appCtx.Err() == nil {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	}
}

func (b *LMTPServerBackend) Close() error {
	if b.server != nil {
		return b.server.Close()
	}
	return nil
}

// GetTotalConnections returns the current total connection count
func (b *LMTPServerBackend) GetTotalConnections() int64 {
	return b.totalConnections.Load()
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
			log.Printf("[LMTP] No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		log.Printf("[LMTP] PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
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

// getTrustedProxies returns the list of trusted proxy CIDR blocks for parameter forwarding
func (b *LMTPServerBackend) getTrustedProxies() []string {
	if b.proxyReader != nil {
		// Get trusted proxies from PROXY protocol configuration
		// Access the configuration from the ProxyProtocolReader
		// Note: This assumes the ProxyProtocolReader has access to the config
		// For now, we'll use default safe values that match PROXY protocol defaults
	}

	// Return default trusted proxy networks (RFC1918 private networks + localhost)
	// These are safe defaults that match the PROXY protocol configuration
	return []string{
		"127.0.0.0/8",    // localhost
		"10.0.0.0/8",     // RFC1918 private networks
		"172.16.0.0/12",  // RFC1918 private networks
		"192.168.0.0/16", // RFC1918 private networks
	}
}
