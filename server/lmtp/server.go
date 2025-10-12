// Package lmtp implements an LMTP (Local Mail Transfer Protocol) server.
//
// LMTP is a variant of SMTP designed for local mail delivery. This package
// provides an LMTP server with:
//   - RFC 2033 LMTP protocol support
//   - SIEVE script execution (RFC 5228)
//   - Vacation responses (RFC 5230)
//   - TLS support (STARTTLS)
//   - Authentication (PLAIN, LOGIN)
//   - Content deduplication via BLAKE3 hashing
//   - Async S3 upload of message bodies
//
// # LMTP vs SMTP
//
// LMTP differs from SMTP in two key ways:
//  1. Returns per-recipient status (not single final status)
//  2. Does not perform mail queuing (immediate delivery)
//
// This makes LMTP ideal for local delivery where the MTA (e.g., Postfix)
// handles queuing and retries.
//
// # Starting an LMTP Server
//
//	cfg := &config.LMTPConfig{
//		Addr:    ":24",
//		MaxConnections: 100,
//	}
//	srv, err := lmtp.NewServer(cfg, db, s3)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Start listener
//	go srv.ListenAndServe(ctx)
//
// # Message Delivery Flow
//
//  1. Client connects and sends LHLO
//  2. Client sends MAIL FROM and RCPT TO
//  3. Client sends DATA with message content
//  4. Server computes BLAKE3 hash of message body
//  5. Server executes SIEVE scripts for filtering
//  6. Server stores message metadata in PostgreSQL
//  7. Server queues message body for S3 upload
//  8. Server returns per-recipient status
//
// # SIEVE Script Execution
//
// SIEVE scripts are executed during delivery for each recipient:
//
//	require ["fileinto", "reject", "vacation"];
//
//	# File messages from boss into Important folder
//	if address :is "from" "boss@example.com" {
//	    fileinto "Important";
//	}
//
//	# Send vacation response
//	vacation :days 7 "I'm on vacation";
//
// Supported SIEVE extensions:
//   - fileinto: Deliver to specific mailbox
//   - reject: Reject message with error
//   - vacation: Send auto-reply (with tracking)
//   - envelope: Test envelope addresses
//
// # Content Deduplication
//
// Messages are deduplicated using BLAKE3 hashes. When the same message
// is delivered to multiple recipients, it's stored once in S3 and
// referenced multiple times in the database.
//
// # Error Handling
//
// LMTP returns per-recipient status codes:
//   - 250: Message delivered successfully
//   - 450: Temporary failure (retry)
//   - 550: Permanent failure (reject)
//
// # Integration with Postfix
//
// Configure Postfix to use LMTP for local delivery:
//
//	# main.cf
//	mailbox_transport = lmtp:inet:127.0.0.1:24
//	lmtp_destination_concurrency_limit = 10
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
			log.Printf("LMTP [%s] Connection rejected: %v", l.name, limitErr)
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
	externalRelay  string
	tlsConfig      *tls.Config
	debug          bool
	ftsRetention   time.Duration
	maxMessageSize int64 // Maximum size for incoming messages

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
	MaxMessageSize       int64 // Maximum size for incoming messages in bytes
}

func New(appCtx context.Context, name, hostname, addr string, s3 *storage.S3Storage, rdb *resilient.ResilientDatabase, uploadWorker *uploader.UploadWorker, options LMTPServerOptions) (*LMTPServerBackend, error) {
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
		addr:           addr,
		name:           name,
		appCtx:         appCtx,
		hostname:       hostname,
		rdb:            rdb,
		s3:             s3,
		uploader:       uploadWorker,
		externalRelay:  options.ExternalRelay,
		debug:          options.Debug,
		ftsRetention:   options.FTSRetention,
		maxMessageSize: options.MaxMessageSize,
		proxyReader:    proxyReader,
	}

	// Create connection limiter with trusted networks from proxy configuration
	// LMTP doesn't use per-IP connection limits, only total connection limits
	limiterTrustedProxies := server.GetTrustedProxiesForServer(backend.proxyReader)
	backend.limiter = server.NewConnectionLimiterWithTrustedNets("LMTP", options.MaxConnections, 0, limiterTrustedProxies)

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
	log.Printf("LMTP [%s] default Sieve script parsed and cached", backend.name)

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
			log.Printf("LMTP [%s] WARNING: TLS certificate verification disabled", name)
		}
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
		log.Printf("LMTP [%s] WARNING: failed to parse trusted networks for XCLIENT (%v), using empty trusted networks (XCLIENT will be disabled)", name, err)
		trustedNets = []*net.IPNet{}
	}
	s.XCLIENTTrustedNets = trustedNets

	// Store trusted networks in backend for connection filtering
	backend.trustedNetworks = trustedNets

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		log.Printf("LMTP [%s] StartTLS is enabled", name)
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
			log.Printf("LMTP [%s] Connection rejected from %s: invalid address format", b.name, remoteAddr)
			return nil, fmt.Errorf("invalid remote address format")
		}
		ip = net.ParseIP(host)
		if ip == nil {
			log.Printf("LMTP [%s] Connection rejected from %s: could not parse IP", b.name, remoteAddr)
			return nil, fmt.Errorf("could not parse remote IP address")
		}
	}

	if !b.isFromTrustedNetwork(ip) {
		log.Printf("LMTP [%s] Connection rejected from %s: not from trusted network", b.name, ip)
		return nil, fmt.Errorf("LMTP connections only allowed from trusted networks")
	}

	// Connection limits are now handled at the listener level
	sessionCtx, sessionCancel := context.WithCancel(b.appCtx)

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)

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
	netConn := c.Conn()
	var proxyInfo *server.ProxyProtocolInfo
	if proxyConn, ok := netConn.(*proxyProtocolConn); ok {
		proxyInfo = proxyConn.GetProxyInfo()
	} else if limitingConn, ok := netConn.(*connectionLimitingConn); ok {
		proxyInfo = limitingConn.GetProxyInfo()
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
		log.Printf("LMTP [%s] listening with implicit TLS on %s", b.name, b.server.Addr)
	} else {
		listener, err = net.Listen("tcp", b.server.Addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("LMTP [%s] listening on %s", b.name, b.server.Addr)
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
			log.Printf("LMTP [%s] server stopped gracefully", b.name)
		} else {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	} else {
		// Server closed without error (shouldn't normally happen, but handle gracefully)
		log.Printf("LMTP [%s] server stopped gracefully", b.name)
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
			// Note: We don't have access to server name in this listener, use generic LMTP
			log.Printf("LMTP No PROXY protocol header from %s; treating as direct connection in optional mode", conn.RemoteAddr())
			// The wrappedConn should be the original connection, possibly with a buffered reader.
			return wrappedConn, nil
		}

		// For all other errors (e.g., malformed header), or if in "required" mode, reject the connection.
		conn.Close()
		// Note: We don't have access to server name in this listener, use generic LMTP
		log.Printf("LMTP PROXY protocol error, rejecting connection from %s: %v", conn.RemoteAddr(), err)
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
