package lmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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

// DefaultDataTimeout bounds one message's content transfer (DATA body or BDAT
// chunk). The idle timeout applies to each read within it, so a sender that keeps
// sending is not cut off by the idle timeout; this only stops one that trickles a
// message in. An hour lets the default 50 MiB message arrive at about 15 KB/s.
const DefaultDataTimeout = time.Hour

// defaultLMTPMaxConnections bounds total concurrent LMTP connections when the operator
// leaves max_connections unset. Generous enough not to throttle legitimate burst delivery
// from internal MTAs, but finite so a single trusted source cannot exhaust resources.
// (security-audit M13)
const defaultLMTPMaxConnections = 1000

// getProxyProtocolTrustedProxies returns the hosts trusted to send PROXY headers: the
// ProxyProtocolTrustedProxies option if set, otherwise trusted_networks. No config key
// sets that option (there is no proxy_protocol_trusted_proxies, #542), so in a running
// server PROXY trust is always [servers] trusted_networks.
func getProxyProtocolTrustedProxies(proxyProtocolTrusted, trustedNetworks []string) []string {
	if len(proxyProtocolTrusted) > 0 {
		return proxyProtocolTrusted
	}
	return trustedNetworks
}

// connectionLimitingListener wraps a net.Listener to enforce connection admission and
// limits at the TCP level
type connectionLimitingListener struct {
	net.Listener
	limiter *server.ConnectionLimiter
	name    string
	// trusted reports whether a socket peer is in the admission networks.
	trusted func(net.Addr) bool
}

// Accept accepts connections and checks admission and connection limits before
// returning them
func (l *connectionLimitingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// A peer outside trusted_networks is closed here, as lmtp_proxy closes it:
		// before it takes a max_connections slot, before the TLS handshake and with
		// nothing sent. No SMTP session is opened, so there is no QUIT to wait for
		// (RFC 5321 §3.1), and the client treats the closed connection as a
		// temporary failure (§3.8). NewSession checks the same socket peer again.
		if !l.trusted(conn.RemoteAddr()) {
			logger.Warn("connection rejected - not from trusted network", "name", l.name, "remote_addr", server.GetAddrString(conn.RemoteAddr()))
			conn.Close()
			continue
		}

		// Extract real client IP and proxy info if this is a PROXY protocol
		// connection. The PROXY conn sits INSIDE the TLS layer (the header is
		// read from the raw stream before any TLS processing), so on
		// implicit-TLS listeners the accepted conn is a SoraTLSConn; the walk
		// traverses it via Unwrap(), which never triggers the handshake.
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

	handshakeOnce sync.Once
	handshakeErr  error
}

// handshake completes the deferred TLS handshake of a connection accepted from the
// implicit-TLS listener (SoraTLSListener), and does nothing on a plain-text one. The
// other servers run it from their protocol library's per-connection hook, before the
// greeting; go-smtp has no such hook, so the connection's first Read or Write runs it:
// the greeting, written from go-smtp's per-connection goroutine, not the accept loop.
// SoraTLSConn bounds the handshake with its own deadline, so a client that never
// sends a ClientHello gives back its slot, and rejects plain text on the TLS port.
//
// The handshake clears the deadlines when it ends, including the write deadline
// go-smtp set for the greeting. That greeting is one short record sent right after
// a completed handshake, which the socket buffer takes without waiting for the
// client, and go-smtp sets its deadlines again for every later read and reply.
func (c *connectionLimitingConn) handshake() error {
	c.handshakeOnce.Do(func() {
		_, c.handshakeErr = server.PerformDeferredTLSHandshake(c.Conn)
	})
	return c.handshakeErr
}

func (c *connectionLimitingConn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *connectionLimitingConn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
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

// reloadableSettings are the settings a config reload (SIGHUP) replaces. ReloadConfig
// publishes a new one whole and none is changed after: a delivery loads it once and
// uses that copy throughout, so it never mixes the values of two reloads. Debug
// is included in the snapshot but fixed at startup, like the protocol writer.
type reloadableSettings struct {
	maxMessageSize int64 // Maximum size for incoming messages
	debug          bool
}

// messageSizeLimit is the largest message accepted: max_message_size, or
// DefaultMaxMessageSize when it is unset or zero.
func (s *reloadableSettings) messageSizeLimit() int64 {
	if s.maxMessageSize > 0 {
		return s.maxMessageSize
	}
	return DefaultMaxMessageSize
}

type LMTPServerBackend struct {
	addr     string
	name     string
	hostname string
	// instanceID keys the upload lease (pending_uploads.instance_id). Distinct from
	// hostname, which is published in the Received header this server stamps.
	instanceID   string
	rdb          *resilient.ResilientDatabase
	s3           *storage.S3Storage
	uploader     *uploader.UploadWorker
	server       *smtp.Server
	appCtx       context.Context
	cancel       context.CancelFunc
	tlsConfig    *tls.Config
	ftsRetention time.Duration
	relayQueue   delivery.RelayQueue // Disk-based queue for relay retry
	relayWorker  RelayWorkerNotifier // Optional: notifies worker for immediate processing

	// The settings ReloadConfig replaces; see reloadableSettings.
	settings atomic.Pointer[reloadableSettings]

	redirectRateLimit  int
	redirectRateWindow time.Duration
	maxRedirectHops    int

	// sharedMailboxes is [shared_mailboxes]: Sieve fileinto :create never makes a
	// personal mailbox in its namespace, and neither a fileinto nor Sieve
	// mailboxexists resolves its root (delivery.FileintoTarget).
	sharedMailboxes config.SharedMailboxesConfig

	// Per-command hard execution timeouts (nil = use defaults)
	commandTimeouts *CommandTimeouts

	// Connection counters
	totalConnections  atomic.Int64
	activeConnections atomic.Int64

	// Transactions (MAIL to the end of DATA or RSET) under way, admitted by the maintenance
	// gate, which refuses new ones while this backend is in maintenance.
	transactionsOpen atomic.Int64
	maintenanceGate  *server.MaintenanceGate

	// Connection limiting
	limiter *server.ConnectionLimiter

	// Listen backlog
	listenBacklog int

	// Trusted networks for connection admission (at accept). Defaults to private
	// networks when trusted_networks is unset, since LMTP is internal-only.
	trustedNetworks []*net.IPNet

	// Trusted networks permitted to override the real client IP via XCLIENT/XRCPTFORWARD.
	// Fails closed: empty = trust nobody (no RFC1918 default), unlike trustedNetworks. (M2)
	xclientTrustedNets []*net.IPNet

	// Sieve extensions enabled for user scripts, and the default script (parsed once at
	// startup). User scripts are compiled through sieveengine.SharedScriptCache().
	sieveExtensions    []string
	defaultSieveScript *sieveengine.CompiledScript

	// PROXY protocol support
	proxyReader *server.ProxyProtocolReader
}

// RelayWorkerNotifier provides immediate processing notification for relay workers
type RelayWorkerNotifier interface {
	NotifyQueued()
}

type LMTPServerOptions struct {
	// InstanceID is the upload-lease key. Empty falls back to the hostname argument,
	// which is what every caller used before the two identities were separated.
	InstanceID string
	// MaintenanceGate admits transactions, and refuses them while this backend is in
	// maintenance. nil admits every transaction.
	MaintenanceGate             *server.MaintenanceGate
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
	InsecureAuth                bool     // Allow plaintext authentication over non-TLS connections
	RedirectRateLimit           int
	RedirectRateWindow          time.Duration
	MaxRedirectHops             int
	SharedMailboxes             config.SharedMailboxesConfig // [shared_mailboxes]; Sieve fileinto :create makes no personal mailbox in its namespace
	CommandTimeoutOverrides     map[string]time.Duration     // Per-command hard execution timeouts (overrides defaults)
	IdleTimeout                 time.Duration                // Maximum wait for the next command or for more message content (0 = default 5m); enforced by go-smtp
	DataTimeout                 time.Duration                // Maximum time to receive one DATA body or BDAT chunk (0 = DefaultDataTimeout)
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

	serverCtx, serverCancel := context.WithCancel(appCtx)
	created := false
	defer func() {
		if !created {
			serverCancel()
		}
	}()

	backend := &LMTPServerBackend{
		addr:               addr,
		name:               name,
		appCtx:             serverCtx,
		cancel:             serverCancel,
		hostname:           hostname,
		instanceID:         instanceIDOrHostname(options.InstanceID, hostname),
		maintenanceGate:    options.MaintenanceGate,
		rdb:                rdb,
		s3:                 s3,
		uploader:           uploadWorker,
		ftsRetention:       options.FTSRetention,
		proxyReader:        proxyReader,
		relayQueue:         options.RelayQueue,
		relayWorker:        options.RelayWorker,
		redirectRateLimit:  options.RedirectRateLimit,
		redirectRateWindow: options.RedirectRateWindow,
		maxRedirectHops:    options.MaxRedirectHops,
		sharedMailboxes:    options.SharedMailboxes,
		commandTimeouts:    defaultCommandTimeouts(),
	}
	backend.settings.Store(&reloadableSettings{
		maxMessageSize: options.MaxMessageSize,
		debug:          options.Debug,
	})

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

	// Sieve extensions for both the default script and the users' scripts (or the
	// default set if not configured)
	backend.sieveExtensions = sieveengine.EffectiveExtensions(options.SieveExtensions)

	// Parse and cache the default Sieve script at startup
	compiledDefault, err := sieveengine.CompileScript(defaultSieveScript, backend.sieveExtensions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default Sieve script: %w", err)
	}
	backend.defaultSieveScript = compiledDefault
	logger.Debug("default sieve script parsed and cached", "name", backend.name)

	// One TLS config for implicit TLS and STARTTLS; the certificate source and
	// tls_verify follow the rule every listener shares (server.ListenerTLS).
	if options.TLS {
		tlsConfig, err := server.ListenerTLS{
			Protocol: "LMTP", Name: name,
			CertFile: options.TLSCertFile, KeyFile: options.TLSKeyFile, Verify: options.TLSVerify,
			Global: options.TLSConfig, ALPN: []string{"lmtp"},
		}.Config()
		if err != nil {
			return nil, err
		}
		backend.tlsConfig = tlsConfig
	}

	s := smtp.NewServer(backend)
	s.ErrorLog = smtpErrorLog{name: name}
	s.Addr = addr
	s.Domain = hostname
	// Seed every connection's context (smtp.Conn.Context) from the application
	// context: go-smtp cancels the derived context when the client disconnects,
	// the connection ends, or the server shuts down, and BaseContext adds app
	// shutdown on top. Sessions derive their context from it in NewSession.
	s.BaseContext = func(net.Listener) context.Context { return serverCtx }
	s.AllowInsecureAuth = options.InsecureAuth
	s.LMTP = true
	s.MaxRecipients = 1 // Enforce single recipient per LMTP transaction.
	// Our session processes one recipient at a time (Rcpt overwrites).
	// This makes the behavior explicit and advertises LIMITS RCPTMAX=1 in LHLO,
	// so the MTA sends each recipient in a separate transaction.

	// The message size limit, asked for at every use so a reload of max_message_size
	// applies: LHLO advertises it as "SIZE <n>", MAIL refuses a larger SIZE= declaration
	// with 552 5.3.4 before any body is sent (RFC 1870 sections 4 and 6.1), and the DATA
	// reader stops at it (Data still checks its own copy of the settings).
	s.MaxMessageBytesFunc = func() int64 { return backend.settings.Load().messageSizeLimit() }

	// Bound idle/slow connections so a held connection cannot pin a goroutine
	// indefinitely (slowloris). Generous values: legit transactions finish in
	// seconds. go-smtp is the single idle owner (it writes the 421 4.4.2
	// notice, and closes the connection after a timeout during message
	// content); its hook below is the only place LMTP timeout disconnects are
	// counted — do NOT add a SoraConn idle checker on top (two owners of the
	// same timer race each other and can duplicate the notice).
	//
	// ReadTimeout bounds each wait for input, also during DATA and BDAT
	// content (the model RFC 5321 section 4.5.3.2 gives the sending side: "a
	// timer is set ... for each buffer of the data transfer"), so a large
	// message on a slow link is not cut off after 5 minutes. DataTimeout
	// bounds one DATA body or one BDAT chunk as a whole.
	s.ReadTimeout = 5 * time.Minute
	if options.IdleTimeout > 0 {
		s.ReadTimeout = options.IdleTimeout
	}
	s.DataTimeout = DefaultDataTimeout
	if options.DataTimeout > 0 {
		s.DataTimeout = options.DataTimeout
	}
	s.WriteTimeout = 2 * time.Minute
	s.OnTimeout = func() {
		metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", name, hostname, "idle").Inc()
	}

	// Configure XCLIENT support (always enabled)
	s.EnableXCLIENT = true

	// XRCPTFORWARD (always enabled) is the only custom RCPT parameter taken. go-smtp
	// refuses any other with 555 where it stands among the parameters, so the first
	// parameter refused decides the reply, as on the LMTP proxy. RFC 5321 section
	// 4.1.1.11: "If the server SMTP does not recognize or cannot implement one or more
	// of the parameters associated with a particular MAIL FROM or RCPT TO command, it
	// will return code 555."
	s.EnableRCPTExtensions = true
	s.RCPTExtensions = []string{"XRCPTFORWARD"}

	// SMTPUTF8 (RFC 6531): advertise the extension and accept its MAIL parameter, so an
	// internationalized envelope (non-ASCII local part, U-label domain) is delivered
	// instead of bounced with a syntax error. server.NewAddress (NewReversePath for the
	// sender) validates the UTF-8 of every address; go-smtp only parses the delimiters
	// around it.
	s.EnableSMTPUTF8 = true

	// Connection admission (at accept): LMTP is internal-only, so when trusted_networks
	// is unset we default to private networks. This gate intentionally keeps the RFC1918
	// default — emptying the list must NOT silently reject all delivery.
	admissionProxies := server.LMTPAdmissionNetworks(options.TrustedNetworks)
	if len(options.TrustedNetworks) == 0 {
		logger.Info("LMTP: trusted_networks empty; accepting delivery from default private ranges (RFC1918+localhost). Set trusted_networks to restrict.", "name", name)
	}
	// A malformed entry is a configuration error: dropping the list would admit no peer
	// and refuse every delivery.
	admissionNets, err := helpers.ParseTrustedNetworks(admissionProxies)
	if err != nil {
		return nil, fmt.Errorf("invalid trusted_networks for LMTP [%s]: %w", name, err)
	}
	backend.trustedNetworks = admissionNets

	// XCLIENT / XRCPTFORWARD source-IP override: fail closed. Use ONLY the explicitly
	// configured trusted_networks (no RFC1918 default), matching IMAP (server/imap/id.go)
	// and POP3 (server/pop3/xclient.go), which deny forwarding when the list is empty.
	// Overriding the client IP is a higher privilege than connecting, so it must be granted
	// explicitly. (security-audit M2)
	xclientNets, err := helpers.ParseTrustedNetworks(options.TrustedNetworks)
	if err != nil {
		return nil, fmt.Errorf("invalid trusted_networks for LMTP [%s]: %w", name, err)
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
		debugWriter = logger.Stdout()
		s.Debug = debugWriter
	}

	// Start connection limiter cleanup
	backend.limiter.StartCleanup(serverCtx)
	created = true

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

// isTrustedPeer reports whether the socket peer addr is in a trusted network. An
// address without an IP is not.
func (b *LMTPServerBackend) isTrustedPeer(addr net.Addr) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			ip = net.ParseIP(host)
		}
	}
	return ip != nil && b.isFromTrustedNetwork(ip)
}

func (b *LMTPServerBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// The listener closes a peer outside trusted_networks at accept; this checks the
	// same socket peer for a connection that reached go-smtp another way.
	if remoteAddr := c.Conn().RemoteAddr(); !b.isTrustedPeer(remoteAddr) {
		logger.Warn("connection rejected - not from trusted network", "name", b.name, "remote_addr", server.GetAddrString(remoteAddr))
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
	//
	// go-smtp records the attributes after its own checks (a trusted_networks peer, valid
	// values) and before calling the hook, so they stay recorded even when the hook refuses
	// the command. Neither hook refusal can disagree with those checks: its trust check
	// passes for every peer go-smtp trusts (the same socket peer and trusted_networks, or
	// with proxy_protocol any peer the PROXY reader admitted), and the session lock fails
	// only once the connection is closing, when no further session is created.
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
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "lmtp", logFunc)

	// Log connection with connection counters, and the session an lmtp_proxy's PROXY v2
	// header names (TLV 0xE1): it leads from the proxy's session=<id> to this session.
	keyvals := []any{"id", s.Id, "active_count", b.activeConnections.Load()}
	if proxyInfo != nil && proxyInfo.ProxySessionID != "" {
		keyvals = append(keyvals, "proxy_session", proxyInfo.ProxySessionID)
	}
	s.InfoLog("new session", keyvals...)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	if b.appCtx.Err() != nil {
		return
	}

	var listener net.Listener
	var err error

	// Start active connections monitoring
	go b.monitorActiveConnections()

	// Create base TCP listener with custom backlog
	tcpListener, err := server.ListenWithBacklog(context.Background(), "tcp", b.server.Addr, b.listenBacklog)
	if err != nil {
		if b.cancel != nil {
			b.cancel()
		}
		errChan <- fmt.Errorf("failed to create listener: %w", err)
		return
	}
	logger.Debug("using custom listen backlog", "server", b.name, "backlog", b.listenBacklog)

	// The PROXY protocol header travels in plaintext AHEAD of the TLS
	// ClientHello, so the header reader must sit between the TCP socket and
	// the TLS layer: the header is read from the raw stream, and the deferred
	// TLS handshake then reads THROUGH the PROXY conn, consuming any
	// ClientHello bytes its bufio buffered alongside the header. Wrapping in
	// the other order makes the handshake read the raw socket and miss those
	// bytes, or run against the plaintext "PROXY ..." line. STARTTLS mode
	// (b.server.TLSConfig set) is unaffected: TLS is negotiated in-protocol,
	// long after the header.
	base := server.WrapProxyProtocol(tcpListener, b.proxyReader, "LMTP")

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - wrap PROXY-aware listener with TLS. The handshake is
		// deferred to the connection's first I/O (connectionLimitingConn.handshake).
		// No timeout checker: go-smtp owns the idle timeout (see New).
		listener = server.NewSoraTLSListener(base, b.tlsConfig, server.SoraConnConfig{
			Protocol:   "lmtp",
			ServerName: b.name,
			Hostname:   b.hostname,
		})
		logger.Info("lmtp server listening with tls", "name", b.name, "addr", b.server.Addr)
	} else {
		listener = base
		logger.Info("lmtp server listening", "name", b.name, "addr", b.server.Addr, "tls", false)
	}
	defer listener.Close()

	// cmd/sora calls Close from a watcher on the application context that
	// races Start, and go-smtp's Close closes only the listeners Serve has
	// already registered: a listener created after it would be served until
	// the process exits. Close it on shutdown, as the POP3 and ManageSieve
	// servers do.
	go func() {
		<-b.appCtx.Done()
		listener.Close()
	}()

	// Wrap listener with connection limiting
	limitedListener := &connectionLimitingListener{
		Listener: listener,
		limiter:  b.limiter,
		name:     b.name,
		trusted:  b.isTrustedPeer,
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
	next := *b.settings.Load()

	// A value that does not parse keeps the running limit (start-up, which has none,
	// uses the default).
	if maxSize, err := cfg.GetMaxMessageSize(); err != nil {
		logger.Warn("LMTP config reload: invalid max_message_size, keeping the running value", "name", b.name, "error", err, "running", next.maxMessageSize)
	} else if maxSize != next.maxMessageSize {
		next.maxMessageSize = maxSize
		reloaded = append(reloaded, "max_message_size")
	}
	// Debug configures the protocol writer at startup and requires a restart.

	if len(reloaded) > 0 {
		b.settings.Store(&next)
		logger.Info("LMTP config reloaded", "name", b.name, "updated", reloaded)
	}
	return nil
}

func (b *LMTPServerBackend) Close() error {
	if b.cancel != nil {
		b.cancel()
	}
	if b.server != nil {
		err := b.server.Close()
		// Start's context watcher can close the listener before go-smtp's
		// registered-listener loop reaches it. That is a completed shutdown.
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
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

// DrainSessions reports the transactions, the only part of an LMTP session that stages
// uploads: how many are under way. Not connections: one that only greeted (a monitoring
// probe) or sits idle between transactions (an MTA's connection cache) holds nothing up.
// See imap.IMAPServer.DrainSessions.
func (b *LMTPServerBackend) DrainSessions() int64 {
	return b.transactionsOpen.Load()
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

// instanceIDOrHostname resolves the upload-lease identity, defaulting to the SMTP-visible
// hostname. The fallback exists so that a caller which never learned about the split keeps
// a self-consistent identity rather than writing an empty instance_id, which no upload
// worker would ever claim.
func instanceIDOrHostname(instanceID, hostname string) string {
	if instanceID != "" {
		return instanceID
	}
	return hostname
}
