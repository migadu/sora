package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exaring/ja4plus"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// copyBufPool provides reusable 32KB buffers for CopyWithDeadline to avoid per-call allocations
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// GetAddrString safely extracts address string without triggering reverse DNS lookup.
// This should be used instead of addr.String() to avoid slow reverse DNS lookups.
func GetAddrString(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return net.JoinHostPort(a.IP.String(), fmt.Sprintf("%d", a.Port))
	case *net.UDPAddr:
		return net.JoinHostPort(a.IP.String(), fmt.Sprintf("%d", a.Port))
	default:
		// For unknown types, must use String() which may trigger DNS lookup
		return addr.String()
	}
}

// CopyWithDeadline copies data from src to dst with write deadlines to prevent blocking on slow clients.
// This is a generic utility function used by all proxy protocols to prevent indefinite blocking
// when clients are not reading data fast enough (which causes TCP send buffers to fill).
//
// Optimizations:
//   - Uses a global buffer pool to avoid per-call allocations
//   - Coarsens write deadline updates to ~1 second intervals to reduce syscall frequency
//
// Parameters:
//   - ctx: Context for cancellation
//   - dst: Destination connection (must support SetWriteDeadline)
//   - src: Source connection to read from
//   - direction: Description for logging (e.g., "client-to-backend")
//
// Returns total bytes copied and any error encountered.
func CopyWithDeadline(ctx context.Context, dst net.Conn, src net.Conn, direction string) (int64, error) {
	const writeDeadline = 30 * time.Second
	const readDeadline = 30 * time.Minute // Detect stale connections while supporting IMAP IDLE (29min RFC 2177)

	// Use buffered copy with pooled buffer
	bufp := copyBufPool.Get().(*[]byte)
	buf := *bufp
	defer copyBufPool.Put(bufp)

	var totalBytes int64
	nextDeadline := time.Now()

	// Enable TCP keepalive to detect dead connections without disrupting IDLE
	// Keepalive probes detect truly dead TCP connections while allowing legitimate silence
	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(2 * time.Minute) // Send keepalive probe every 2 minutes
	}

	for {
		select {
		case <-ctx.Done():
			return totalBytes, ctx.Err()
		default:
		}

		// Set read deadline to detect stale connections
		// This prevents goroutines from hanging indefinitely when the peer stops responding
		// 30 minutes accommodates IMAP IDLE (RFC 2177: up to 29 minutes of silence is valid)
		// while still detecting truly hung connections within a reasonable timeframe
		// Note: TCP keepalive (set above) provides faster detection (~12 min) for dead connections
		if err := src.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			// Don't fail on deadline errors - continue without deadline
			// This handles connections that don't support deadlines
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			// Only update write deadline once per second to reduce syscall frequency
			now := time.Now()
			if now.After(nextDeadline) {
				if err := dst.SetWriteDeadline(now.Add(writeDeadline)); err != nil {
					return totalBytes, fmt.Errorf("failed to set write deadline: %w", err)
				}
				nextDeadline = now.Add(time.Second)
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				totalBytes += int64(nw)
			}
			if ew != nil {
				if netErr, ok := ew.(net.Error); ok && netErr.Timeout() {
					return totalBytes, fmt.Errorf("write timeout in %s: %w", direction, ew)
				}
				return totalBytes, ew
			}
			if nr != nw {
				return totalBytes, io.ErrShortWrite
			}
		}
		if err != nil {
			// Check if this is a read timeout error (stale connection)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return totalBytes, fmt.Errorf("read timeout in %s after %v (connection appears stale): %w", direction, readDeadline, err)
			}
			if err != io.EOF {
				return totalBytes, err
			}
			return totalBytes, nil
		}
	}
}

// SoraConn is a unified connection wrapper that handles all Sora-specific connection features:
// - Timeout protection (idle, absolute session, minimum throughput)
// - JA4 TLS fingerprint capture and storage
// - PROXY protocol information storage
// - Connection metadata (protocol, username)
//
// This replaces multiple nested wrappers (timeoutConn, ja4CaptureConn, proxyProtocolConn)
// with a single, unified implementation.
type SoraConn struct {
	net.Conn // Underlying connection (TLS or plain TCP)
	// Cached remote address string to avoid touching the underlying connection
	// during shutdown/unregister which could race with Close()
	remoteAddr string

	// Buffered reader (created if TLS detection is used)
	reader *bufio.Reader

	// probeTLSOnFirstRead, when armed by SoraListener, makes the first Read
	// check the inbound stream for a TLS ClientHello signature (a TLS client
	// mistakenly pointed at a plaintext port) and reject it. Running the
	// probe inside the first protocol-issued Read costs nothing: TLS clients
	// send their ClientHello immediately, and the read blocks under the
	// session's own deadlines either way. Probing in the ACCEPT path instead
	// (the old design) charged the innocent: sora's protocols are
	// server-speaks-first, so legitimate clients send nothing until the
	// greeting and every accept burned the probe's full 100ms peek deadline,
	// serially — the same accept-path stall class as the 2026-07-05 incident.
	probeTLSOnFirstRead atomic.Bool

	// Server context for metrics
	protocol   string
	serverName string
	hostname   string

	// Timeout protection
	idleTimeout         time.Duration // Maximum idle time (e.g., 5 minutes)
	absoluteTimeout     time.Duration // Maximum session duration (e.g., 30 minutes)
	minBytesPerMinute   int64         // Minimum throughput (0 = disabled)
	lastActivity        time.Time
	sessionStart        time.Time
	lastThroughputCheck time.Time
	bytesTransferred    int64
	// Slowloris protection: rolling window tracking
	throughputHistory           [3]int64 // Last 3 minutes of throughput measurements
	throughputHistoryIndex      int      // Current position in ring buffer
	consecutiveSlowMinutes      int      // Counter for consecutive slow periods
	throughputCheckingSuspended bool     // True when in IDLE mode (IMAP)

	// JA4 TLS fingerprinting
	ja4Fingerprint string
	ja4Mutex       sync.RWMutex

	// PROXY protocol information
	proxyInfo      *ProxyProtocolInfo
	proxyInfoMutex sync.RWMutex

	// Connection metadata
	username string // Set after authentication

	// Timeout callback
	onTimeout func(conn net.Conn, reason string) // Called before closing due to timeout

	// Lifecycle management
	closed     bool
	closeMutex sync.Mutex
	cancelIdle chan struct{}
	mu         sync.RWMutex
}

// SoraConnConfig holds configuration for creating a SoraConn
type SoraConnConfig struct {
	Protocol             string        // Protocol name for logging/metrics
	ServerName           string        // Server name for metrics
	Hostname             string        // Hostname for metrics
	IdleTimeout          time.Duration // 0 = no idle timeout
	AbsoluteTimeout      time.Duration // 0 = no absolute timeout
	MinBytesPerMinute    int64         // 0 = no throughput checking
	InitialJA4           string        // Pre-captured JA4 fingerprint
	InitialProxyInfo     *ProxyProtocolInfo
	EnableTimeoutChecker bool // If false, caller must handle timeouts

	// OnTimeout is called before closing connection due to timeout.
	// The reason will be one of: "idle", "slow_throughput", or "session_max".
	// The handler should send a protocol-specific goodbye message and return quickly.
	// If nil, the connection will be closed without sending any message.
	// The conn parameter is the underlying net.Conn for writing goodbye messages.
	OnTimeout func(conn net.Conn, reason string)
}

// NewSoraConn creates a new SoraConn wrapping the given connection
func NewSoraConn(conn net.Conn, config SoraConnConfig) *SoraConn {
	now := time.Now()

	// Apply defaults (MinBytesPerMinute default is protocol-specific, set by caller)
	if config.AbsoluteTimeout == 0 {
		config.AbsoluteTimeout = 30 * time.Minute // Default: 30 minutes
	}
	if config.Protocol == "" {
		config.Protocol = "unknown"
	}

	sc := &SoraConn{
		Conn:                conn,
		remoteAddr:          "",
		idleTimeout:         config.IdleTimeout,
		absoluteTimeout:     config.AbsoluteTimeout,
		minBytesPerMinute:   config.MinBytesPerMinute,
		lastActivity:        now,
		sessionStart:        now,
		lastThroughputCheck: now,
		bytesTransferred:    0,
		ja4Fingerprint:      config.InitialJA4,
		proxyInfo:           config.InitialProxyInfo,
		protocol:            config.Protocol,
		serverName:          config.ServerName,
		hostname:            config.Hostname,
		username:            "",
		onTimeout:           config.OnTimeout,
		closed:              false,
		cancelIdle:          make(chan struct{}),
	}

	// Cache remote address early to avoid touching the underlying net.Conn later
	if conn != nil && conn.RemoteAddr() != nil {
		sc.remoteAddr = GetAddrString(conn.RemoteAddr())
	}

	// Register with global timeout scheduler if enabled
	if config.EnableTimeoutChecker && (sc.idleTimeout > 0 || sc.absoluteTimeout > 0 || sc.minBytesPerMinute > 0) {
		registerConn(sc)
	}

	return sc
}

// checkTimeouts is called periodically by the global scheduler to check timeout conditions
// This method performs a single check without looping or sleeping
func (c *SoraConn) checkTimeouts(now time.Time) {
	// Check if connection is closed using closeMutex (same lock used in Close())
	c.closeMutex.Lock()
	closed := c.closed
	c.closeMutex.Unlock()

	if closed {
		return
	}

	c.mu.RLock()
	idleTime := now.Sub(c.lastActivity)
	sessionDuration := now.Sub(c.sessionStart)
	throughputDuration := now.Sub(c.lastThroughputCheck)
	bytesTransferred := c.bytesTransferred
	username := c.username
	suspended := c.throughputCheckingSuspended
	c.mu.RUnlock()

	// Check absolute session timeout (highest priority)
	if c.absoluteTimeout > 0 && sessionDuration >= c.absoluteTimeout {
		remoteAddr := c.remoteAddr
		logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "session_max", "duration", sessionDuration.Round(time.Second), "max", c.absoluteTimeout)
		metrics.ConnectionTimeoutsTotal.WithLabelValues(c.protocol, c.serverName, c.hostname, "session_max").Inc()

		// Call timeout handler before closing (if provided)
		if c.onTimeout != nil {
			c.onTimeout(c.Conn, "session_max")
		}

		c.Close()
		return
	}

	// Check minimum throughput (protects against slowloris attacks)
	// IMPROVED: Uses 3-minute rolling average and requires 2 consecutive slow periods
	// Skip if throughput checking is suspended (e.g., during IMAP IDLE)
	if c.minBytesPerMinute > 0 && throughputDuration >= time.Minute {
		if suspended {
			// Throughput checking is suspended - skip check
			return
		}
		sessionDurationSinceStart := now.Sub(c.sessionStart)

		// Only enforce throughput after the first 2 minutes of the session
		// to allow time for TLS handshake, greeting, and initial authentication
		if sessionDurationSinceStart >= 2*time.Minute {
			minutesElapsed := throughputDuration.Minutes()
			bytesPerMinute := int64(float64(bytesTransferred) / minutesElapsed)

			// Add current measurement to rolling history
			c.mu.Lock()
			c.throughputHistory[c.throughputHistoryIndex] = bytesPerMinute
			c.throughputHistoryIndex = (c.throughputHistoryIndex + 1) % 3

			// Calculate average over last 3 measurements (or fewer if we don't have 3 yet)
			var sum int64
			var count int
			for i := 0; i < 3; i++ {
				if c.throughputHistory[i] > 0 {
					sum += c.throughputHistory[i]
					count++
				}
			}
			avgBytesPerMin := int64(0)
			if count > 0 {
				avgBytesPerMin = sum / int64(count)
			}

			// Check if current measurement is slow
			if bytesPerMinute < c.minBytesPerMinute {
				c.consecutiveSlowMinutes++
			} else {
				c.consecutiveSlowMinutes = 0
			}

			consecutiveSlow := c.consecutiveSlowMinutes
			c.mu.Unlock()

			// Disconnect only if:
			// 1. Average over 3 minutes is below threshold, AND
			// 2. We've had 2 consecutive slow minutes
			// This reduces false positives for legitimate users
			if avgBytesPerMin < c.minBytesPerMinute && consecutiveSlow >= 2 {
				remoteAddr := c.remoteAddr
				logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "slow_throughput", "bytes_per_min_avg", int(avgBytesPerMin), "bytes_per_min_current", int(bytesPerMinute), "required", c.minBytesPerMinute, "consecutive_slow", consecutiveSlow)
				metrics.ConnectionTimeoutsTotal.WithLabelValues(c.protocol, c.serverName, c.hostname, "slow_throughput").Inc()

				// Call timeout handler before closing (if provided)
				if c.onTimeout != nil {
					c.onTimeout(c.Conn, "slow_throughput")
				}

				c.Close()
				return
			}
		}

		// Reset throughput counters for next measurement period
		c.mu.Lock()
		c.lastThroughputCheck = now
		c.bytesTransferred = 0
		c.mu.Unlock()
	}

	// Check idle timeout
	if c.idleTimeout > 0 && idleTime >= c.idleTimeout {
		remoteAddr := c.remoteAddr
		logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "idle", "idle_time", idleTime.Round(time.Second), "max_idle", c.idleTimeout)
		metrics.ConnectionTimeoutsTotal.WithLabelValues(c.protocol, c.serverName, c.hostname, "idle").Inc()

		// Call timeout handler before closing (if provided)
		if c.onTimeout != nil {
			c.onTimeout(c.Conn, "idle")
		}

		c.Close()
		return
	}
}

// Read implements net.Conn.Read with activity tracking
func (c *SoraConn) Read(b []byte) (int, error) {
	var n int
	var err error

	// First protocol-issued read on a direct plaintext connection: check for
	// a TLS ClientHello before handing bytes to the protocol parser.
	if c.probeTLSOnFirstRead.CompareAndSwap(true, false) {
		if err := c.probeTLSSignature(); err != nil {
			return 0, err
		}
	}

	// If we have a buffered reader (from TLS detection), use it
	if c.reader != nil {
		n, err = c.reader.Read(b)
	} else {
		n, err = c.Conn.Read(b)
	}

	if n > 0 {
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.bytesTransferred += int64(n)
		c.mu.Unlock()
	}

	return n, err
}

// Write implements net.Conn.Write with activity tracking
func (c *SoraConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)

	if n > 0 {
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.bytesTransferred += int64(n)
		c.mu.Unlock()
	}

	return n, err
}

// Close stops the timeout checker and closes the connection
func (c *SoraConn) Close() error {
	c.closeMutex.Lock()
	if !c.closed {
		c.closed = true
		close(c.cancelIdle)
		// Unregister from global timeout scheduler
		unregisterConn(c)
	}
	c.closeMutex.Unlock()

	return c.Conn.Close()
}

// GetJA4Fingerprint returns the captured JA4 TLS fingerprint
func (c *SoraConn) GetJA4Fingerprint() (string, error) {
	c.ja4Mutex.RLock()
	defer c.ja4Mutex.RUnlock()
	return c.ja4Fingerprint, nil
}

// SetJA4Fingerprint sets the JA4 fingerprint (called during TLS handshake)
func (c *SoraConn) SetJA4Fingerprint(fingerprint string) {
	c.ja4Mutex.Lock()
	c.ja4Fingerprint = fingerprint
	c.ja4Mutex.Unlock()
}

// GetProxyInfo returns the PROXY protocol information
func (c *SoraConn) GetProxyInfo() *ProxyProtocolInfo {
	c.proxyInfoMutex.RLock()
	defer c.proxyInfoMutex.RUnlock()
	return c.proxyInfo
}

// SetProxyInfo sets the PROXY protocol information
func (c *SoraConn) SetProxyInfo(info *ProxyProtocolInfo) {
	c.proxyInfoMutex.Lock()
	c.proxyInfo = info
	c.proxyInfoMutex.Unlock()
}

// SuspendThroughputChecking disables slowloris throughput checks
// Used when entering IDLE mode where low throughput is expected and legitimate
func (c *SoraConn) SuspendThroughputChecking() {
	c.mu.Lock()
	c.throughputCheckingSuspended = true
	c.bytesTransferred = 0 // Reset counter as well
	c.mu.Unlock()
	logger.Info("Throughput checking suspended", "proto", c.protocol, "remote", c.remoteAddr)
}

// ResumeThroughputChecking re-enables slowloris throughput checks
// Used when exiting IDLE mode to restore normal protection
func (c *SoraConn) ResumeThroughputChecking() {
	c.mu.Lock()
	c.throughputCheckingSuspended = false
	c.bytesTransferred = 0             // Reset counter for fresh start
	c.lastThroughputCheck = time.Now() // Reset timing
	c.consecutiveSlowMinutes = 0       // Clear slow minute counter
	// Clear throughput history
	c.throughputHistory = [3]int64{}
	c.throughputHistoryIndex = 0
	c.mu.Unlock()
	logger.Info("Throughput checking resumed", "proto", c.protocol, "remote", c.remoteAddr)
}

// SetUsername sets the authenticated username (for logging)
func (c *SoraConn) SetUsername(username string) {
	c.mu.Lock()
	c.username = username
	c.mu.Unlock()
}

// GetUsername returns the authenticated username
func (c *SoraConn) GetUsername() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.username
}

// GetProtocol returns the protocol name
func (c *SoraConn) GetProtocol() string {
	return c.protocol
}

// Unwrap returns the underlying connection (for compatibility with unwrapping patterns)
func (c *SoraConn) Unwrap() net.Conn {
	return c.Conn
}

// ConnIsTLS reports whether conn is, or wraps, a *tls.Conn.
//
// Sora's listeners hand protocol handlers a connection wrapped in several
// layers (connection limiter, SoraTLSConn, PROXY-protocol reader, ...), so a
// bare `conn.(*tls.Conn)` type assertion fails even on implicit-TLS ports. This
// helper walks the Unwrap() chain to find the real *tls.Conn. It is the single
// source of truth used to gate authentication when insecure_auth is false; a
// wrong "not TLS" answer would reject auth on a perfectly secure connection.
//
// Note: for SoraTLSConn the underlying *tls.Conn only becomes reachable after
// PerformHandshake() has run, so call this after the handshake completes.
func ConnIsTLS(conn net.Conn) bool {
	for conn != nil {
		if _, ok := conn.(*tls.Conn); ok {
			return true
		}
		if wrapper, ok := conn.(interface{ Unwrap() net.Conn }); ok {
			conn = wrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}

// ErrTLSOnPlainPort is returned when TLS traffic is detected on a plain-text port
var ErrTLSOnPlainPort = errors.New("TLS connection attempted on plain-text port")

// ErrPlainTextOnTLSPort is returned when plain-text traffic is detected on a TLS port
var ErrPlainTextOnTLSPort = errors.New("plain-text connection attempted on TLS port")

// probeTLSSignature checks the inbound stream for a TLS ClientHello signature
// (0x16 0x03 …: a TLS client mistakenly pointed at a plain-text port) and
// rejects the connection with a helpful message when found. It runs inside
// the first protocol-issued Read (see probeTLSOnFirstRead), so it adds no
// latency of its own: the peek blocks exactly as the read it replaces would,
// under the session's own deadlines. Peeked bytes stay in c.reader for
// subsequent reads. Peek errors (EOF, timeout) are returned as the read
// result, matching what the caller's Read would have seen.
func (c *SoraConn) probeTLSSignature() error {
	if c.reader == nil {
		c.reader = bufio.NewReader(c.Conn)
	}

	first, err := c.reader.Peek(1)
	if err != nil {
		return err
	}
	// Text protocols never start a line with 0x16, so a single byte decides
	// the fast path without waiting for more input.
	if first[0] != 0x16 {
		return nil
	}
	hdr, err := c.reader.Peek(3)
	if err != nil || len(hdr) < 3 {
		// Cannot confirm; let the protocol parser produce its own error.
		return nil
	}

	// TLS records start with 0x16 (handshake) followed by version 0x03 0x0x.
	if hdr[1] == 0x03 {
		logger.Warn("TLS handshake detected on plain-text port - rejecting", "proto", c.protocol, "remote", c.remoteAddr)

		// Write a helpful error message
		// Note: The client's TLS stack won't display this, but it helps with debugging
		c.Conn.Write([]byte("ERROR: TLS connection attempted on plain-text port. Use STARTTLS or connect to the TLS port.\r\n"))

		metrics.ConnectionTimeoutsTotal.WithLabelValues(c.protocol, c.serverName, c.hostname, "tls_on_plain_port").Inc()
		c.Close()

		return ErrTLSOnPlainPort
	}

	return nil
}

// SoraListener wraps a net.Listener to create SoraConn instances
type SoraListener struct {
	net.Listener
	config SoraConnConfig
}

// NewSoraListener creates a listener that wraps accepted connections with SoraConn
func NewSoraListener(listener net.Listener, config SoraConnConfig) *SoraListener {
	return &SoraListener{
		Listener: listener,
		config:   config,
	}
}

// Accept wraps accepted connections with SoraConn and detects TLS on plain-text port
func (l *SoraListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		soraConn := NewSoraConn(conn, l.config)

		// Arm TLS-on-plaintext-port detection for the connection's FIRST
		// Read (see probeTLSSignature) — never probe here in the accept
		// loop, where any blocking peek runs serially and stalls every other
		// client (the 2026-07-05 accept-path collapse). Connections that
		// came through the PROXY protocol reader skip detection entirely:
		// the header parse already validated the initial bytes (a TLS
		// ClientHello instead of a header fails it).
		if GetProxyProtocolInfo(conn) == nil {
			soraConn.probeTLSOnFirstRead.Store(true)
		}

		return soraConn, nil
	}
}

// SoraTLSListener wraps a TCP listener to perform TLS handshake and capture JA4
type SoraTLSListener struct {
	net.Listener
	tlsConfig  *tls.Config
	connConfig SoraConnConfig
}

// NewSoraTLSListener creates a TLS listener that captures JA4 and returns SoraConn
func NewSoraTLSListener(tcpListener net.Listener, tlsConfig *tls.Config, connConfig SoraConnConfig) *SoraTLSListener {
	return &SoraTLSListener{
		Listener:   tcpListener,
		tlsConfig:  tlsConfig,
		connConfig: connConfig,
	}
}

// Accept accepts TCP connection and returns SoraTLSConn without performing handshake.
// The TLS handshake is deferred until PerformHandshake() is explicitly called.
// This prevents blocking the accept loop when slow clients connect.
func (l *SoraTLSListener) Accept() (net.Conn, error) {
	tcpConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Return SoraTLSConn that will perform handshake when PerformHandshake() is called
	return NewSoraTLSConn(tcpConn, l.tlsConfig, l.connConfig), nil
}

// SoraTLSConn wraps a TCP connection and performs TLS handshake + JA4 capture on demand.
// This allows the accept loop to remain non-blocking while handshakes happen in goroutines.
type SoraTLSConn struct {
	*SoraConn
	tcpConn           net.Conn
	tlsConfig         *tls.Config
	connConfig        SoraConnConfig
	handshakeComplete bool
	handshakeMutex    sync.Mutex
	tlsConn           *tls.Conn
	handshakeErr      error
}

// NewSoraTLSConn creates a new SoraTLSConn that requires explicit PerformHandshake() call
func NewSoraTLSConn(tcpConn net.Conn, tlsConfig *tls.Config, connConfig SoraConnConfig) *SoraTLSConn {
	// Create SoraConn wrapper (timeout checker will start after handshake)
	configWithoutChecker := connConfig
	configWithoutChecker.EnableTimeoutChecker = false
	soraConn := NewSoraConn(tcpConn, configWithoutChecker)

	return &SoraTLSConn{
		SoraConn:   soraConn,
		tcpConn:    tcpConn,
		tlsConfig:  tlsConfig,
		connConfig: connConfig,
	}
}

// PerformDeferredTLSHandshake completes the deferred TLS handshake on a
// connection accepted from a SoraTLSListener, walking the Unwrap() chain so
// wrappers such as PROXY-protocol conns don't hide the SoraTLSConn. It
// returns (false, nil) when the chain has no deferred handshake (plaintext
// listener). It must be called before any other Read/Write on the connection.
func PerformDeferredTLSHandshake(conn net.Conn) (bool, error) {
	for conn != nil {
		if hs, ok := conn.(interface{ PerformHandshake() error }); ok {
			return true, hs.PerformHandshake()
		}
		w, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			return false, nil
		}
		conn = w.Unwrap()
	}
	return false, nil
}

// ErrTLSHandshakeNotPerformed is returned by SoraTLSConn.Read/Write when
// protocol code attempts connection I/O before the deferred TLS handshake has
// been triggered. See requireHandshake.
var ErrTLSHandshakeNotPerformed = errors.New("deferred TLS handshake not performed before connection I/O")

// Read refuses I/O until the deferred TLS handshake has been attempted.
func (c *SoraTLSConn) Read(b []byte) (int, error) {
	if err := c.requireHandshake("read"); err != nil {
		return 0, err
	}
	return c.SoraConn.Read(b)
}

// Write refuses I/O until the deferred TLS handshake has been attempted.
func (c *SoraTLSConn) Write(b []byte) (int, error) {
	if err := c.requireHandshake("write"); err != nil {
		return 0, err
	}
	return c.SoraConn.Write(b)
}

// requireHandshake is a fail-loud guard against the listener-composition bug
// where the deferred handshake is never triggered (e.g. a wrapper hides the
// SoraTLSConn from a `conn.(interface{ PerformHandshake() error })` assertion)
// and the server would otherwise write its greeting in PLAINTEXT on a TLS
// port. That failure mode is silent from the server's perspective — clients
// just hang waiting for a ServerHello — so instead of degrading, refuse the
// I/O and log an error naming the missing call. After a failed handshake the
// cached handshake error is returned (never plaintext onto a broken stream).
//
// Callers that block here while another goroutine runs PerformHandshake
// simply serialize behind handshakeMutex and proceed once it finishes.
func (c *SoraTLSConn) requireHandshake(op string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.handshakeComplete {
		logger.Error("TLS listener: connection I/O before deferred TLS handshake - refusing (call server.PerformDeferredTLSHandshake before any read/write)",
			"proto", c.connConfig.Protocol, "op", op, "remote", c.SoraConn.remoteAddr)
		return ErrTLSHandshakeNotPerformed
	}
	return c.handshakeErr
}

// PerformHandshake performs the TLS handshake with timeout and JA4 capture.
// This method is idempotent and thread-safe - calling it multiple times is safe.
// Must be called before any Read/Write operations.
func (c *SoraTLSConn) PerformHandshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	// Already attempted handshake - return cached result
	if c.handshakeComplete {
		return c.handshakeErr
	}
	c.handshakeComplete = true

	// Prefer cached remoteAddr
	remoteAddr := c.remoteAddr

	// Detect and reject plain-text connections before attempting TLS handshake
	if err := c.detectAndRejectPlainText(); err != nil {
		c.handshakeErr = err
		return err
	}

	// Clone TLS config and add GetConfigForClient callback to capture JA4
	tlsConfig := c.tlsConfig.Clone()
	originalGetConfig := tlsConfig.GetConfigForClient

	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Capture JA4 fingerprint with panic recovery
		// The ja4plus library can panic on malformed ClientHello messages
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Warn("JA4 fingerprinting panic recovered (likely malformed ClientHello)", "proto", c.connConfig.Protocol, "error", r)
					// Set empty fingerprint on panic
					c.SetJA4Fingerprint("")
				}
			}()
			ja4 := ja4plus.JA4(hello)
			c.SetJA4Fingerprint(ja4)
		}()

		// Call original callback if it exists
		if originalGetConfig != nil {
			return originalGetConfig(hello)
		}
		return nil, nil
	}

	// Create TLS server connection
	// If we used a buffered reader for plain-text detection, we need to pass it to TLS
	// so that the peeked bytes are available for the TLS handshake
	var connForTLS net.Conn = c.tcpConn
	var bufferedConnForTLS *bufferedConn
	if c.SoraConn.reader != nil {
		// Wrap the reader and connection together so TLS can read the buffered data
		bufferedConnForTLS = &bufferedConn{
			reader: c.SoraConn.reader,
			Conn:   c.tcpConn,
		}
		connForTLS = bufferedConnForTLS
		// Clear the reader from SoraConn - we don't want it after TLS handshake
		c.SoraConn.reader = nil
	}
	c.tlsConn = tls.Server(connForTLS, tlsConfig)

	// Set a deadline for the TLS handshake (10 seconds should be more than enough)
	handshakeDeadline := time.Now().Add(10 * time.Second)
	if err := c.tcpConn.SetDeadline(handshakeDeadline); err != nil {
		logger.Warn("Failed to set handshake deadline", "proto", c.connConfig.Protocol, "error", err)
		c.handshakeErr = fmt.Errorf("failed to set handshake deadline: %w", err)
		return c.handshakeErr
	}

	// Perform TLS handshake
	handshakeStart := time.Now()
	if err := c.tlsConn.Handshake(); err != nil {
		handshakeDuration := time.Since(handshakeStart)
		logger.Info("TLS handshake failed", "proto", c.connConfig.Protocol, "remote", remoteAddr, "duration", handshakeDuration, "error", err)
		c.handshakeErr = err
		return err
	}

	// Clear the deadline after successful handshake
	if err := c.tlsConn.SetDeadline(time.Time{}); err != nil {
		logger.Warn("Failed to clear handshake deadline", "proto", c.connConfig.Protocol, "error", err)
	}

	// Replace the underlying connection in SoraConn with the TLS connection
	c.SoraConn.Conn = c.tlsConn

	// NOW register with timeout scheduler, after TLS handshake is complete
	if c.connConfig.EnableTimeoutChecker && (c.SoraConn.idleTimeout > 0 || c.SoraConn.absoluteTimeout > 0 || c.SoraConn.minBytesPerMinute > 0) {
		registerConn(c.SoraConn)
	}

	return nil
}

// detectAndRejectPlainText checks if the connection is attempting to use plain-text on a TLS port.
// It peeks at the first byte to detect non-TLS traffic (anything other than 0x14-0x17).
// If plain-text is detected, it writes a rejection message and returns ErrPlainTextOnTLSPort.
// If TLS is detected, it returns nil WITHOUT creating a buffered reader (TLS handshake reads directly).
// This should be called before attempting the TLS handshake.
func (c *SoraTLSConn) detectAndRejectPlainText() error {
	// Create a temporary buffered reader just for peeking
	tempReader := bufio.NewReader(c.tcpConn)

	// Set a very short deadline just for peeking to avoid blocking on slow clients
	// TLS handshakes send the Client Hello immediately, so 100ms is generous
	originalDeadline := time.Now().Add(100 * time.Millisecond)
	if err := c.tcpConn.SetReadDeadline(originalDeadline); err != nil {
		// If we can't set deadline, skip detection (better to proceed than fail)
		logger.Warn("Plain-text detection: cannot set read deadline", "proto", c.connConfig.Protocol, "error", err)
		c.tcpConn.SetReadDeadline(time.Time{}) // Clear deadline
		return nil
	}

	// Peek at first byte (does not consume it from the buffer)
	peekBuf, err := tempReader.Peek(1)

	// Clear the deadline immediately
	c.tcpConn.SetReadDeadline(time.Time{})

	if err != nil {
		// Timeout or other error during peek
		if err == io.EOF {
			// Connection closed before any data - not our concern
			return err
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout means no immediate data - might be a slow client
			// Let the TLS handshake fail naturally
			return nil
		}
		// Check for "buffer full" error - shouldn't happen with 1 byte
		if err == bufio.ErrBufferFull {
			return nil
		}
		// Other errors will be caught by TLS handshake
		return nil
	}

	if len(peekBuf) < 1 {
		// Not enough bytes available - cannot definitively detect
		return nil
	}

	// Check for TLS record type byte
	// Valid TLS record types: 0x14 (change_cipher_spec), 0x15 (alert), 0x16 (handshake), 0x17 (application_data)
	// Most initial connections will be 0x16 (handshake)
	// Anything else is likely plain-text (ASCII printable chars are 0x20-0x7E)
	firstByte := peekBuf[0]
	if firstByte != 0x14 && firstByte != 0x15 && firstByte != 0x16 && firstByte != 0x17 {
		// This is likely plain-text
		remoteAddr := c.SoraConn.remoteAddr
		logger.Warn("Plain-text connection detected on TLS port - rejecting", "proto", c.connConfig.Protocol, "remote", remoteAddr, "first_byte", fmt.Sprintf("0x%02x", firstByte))

		// Write a helpful error message
		c.tcpConn.Write([]byte("ERROR: Plain-text connection attempted on TLS port. Use STARTTLS or connect to the plain-text port.\r\n"))

		// Record metric
		metrics.ConnectionTimeoutsTotal.WithLabelValues(c.SoraConn.protocol, c.SoraConn.serverName, c.SoraConn.hostname, "plain_text_on_tls_port").Inc()

		// Close the connection
		c.SoraConn.Close()

		return ErrPlainTextOnTLSPort
	}

	// Looks like TLS - proceed with handshake
	// Store the buffered reader so TLS can consume the peeked byte
	c.SoraConn.reader = tempReader
	return nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader to preserve peeked data
type bufferedConn struct {
	reader *bufio.Reader
	net.Conn
}

// Read reads from the buffered reader first, then from the underlying connection
func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

// Unwrap keeps the wrapper chain walkable (e.g. tls.Conn.NetConn() returns a
// bufferedConn when the plaintext probe peeked bytes; PROXY-info discovery
// must be able to continue through it to the ProxyProtocolConn underneath).
func (bc *bufferedConn) Unwrap() net.Conn {
	return bc.Conn
}
