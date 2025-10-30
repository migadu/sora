package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/exaring/ja4plus"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

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

	// Buffered reader (created if TLS detection is used)
	reader *bufio.Reader

	// Timeout protection
	idleTimeout         time.Duration // Maximum idle time (e.g., 5 minutes)
	absoluteTimeout     time.Duration // Maximum session duration (e.g., 30 minutes)
	minBytesPerMinute   int64         // Minimum throughput (0 = disabled)
	lastActivity        time.Time
	sessionStart        time.Time
	lastThroughputCheck time.Time
	bytesTransferred    int64

	// JA4 TLS fingerprinting
	ja4Fingerprint string
	ja4Mutex       sync.RWMutex

	// PROXY protocol information
	proxyInfo      *ProxyProtocolInfo
	proxyInfoMutex sync.RWMutex

	// Connection metadata
	protocol string // "imap", "pop3", "lmtp", "managesieve", "imap_proxy", etc.
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

	// Apply defaults
	if config.MinBytesPerMinute == 0 {
		config.MinBytesPerMinute = 512 // Default: 512 bytes/minute (balanced slowloris protection)
	}
	if config.AbsoluteTimeout == 0 {
		config.AbsoluteTimeout = 30 * time.Minute // Default: 30 minutes
	}
	if config.Protocol == "" {
		config.Protocol = "unknown"
	}

	sc := &SoraConn{
		Conn:                conn,
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
		username:            "",
		onTimeout:           config.OnTimeout,
		closed:              false,
		cancelIdle:          make(chan struct{}),
	}

	// Start background timeout checker if enabled
	if config.EnableTimeoutChecker && (sc.idleTimeout > 0 || sc.absoluteTimeout > 0 || sc.minBytesPerMinute > 0) {
		go sc.timeoutChecker()
	}

	return sc
}

// timeoutChecker runs in background and enforces timeout protections
func (c *SoraConn) timeoutChecker() {
	// Check frequency: every 1 minute for throughput, or more frequently for idle/absolute timeout
	checkInterval := 1 * time.Minute
	if c.idleTimeout > 0 && c.idleTimeout/4 < checkInterval {
		checkInterval = c.idleTimeout / 4
	}
	if c.absoluteTimeout > 0 && c.absoluteTimeout/4 < checkInterval {
		checkInterval = c.absoluteTimeout / 4
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.RLock()
			idleTime := time.Since(c.lastActivity)
			sessionDuration := time.Since(c.sessionStart)
			throughputDuration := time.Since(c.lastThroughputCheck)
			bytesTransferred := c.bytesTransferred
			closed := c.closed
			username := c.username
			c.mu.RUnlock()

			if closed {
				return
			}

			// Check absolute session timeout (highest priority)
			if c.absoluteTimeout > 0 && sessionDuration >= c.absoluteTimeout {
				remoteAddr := c.Conn.RemoteAddr().String()
				logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "session_max", "duration", sessionDuration.Round(time.Second), "max", c.absoluteTimeout)
				metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "session_max").Inc()

				// Call timeout handler before closing (if provided)
				if c.onTimeout != nil {
					c.onTimeout(c.Conn, "session_max")
				}

				c.Close()
				return
			}

			// Check minimum throughput (protects against slowloris attacks)
			// Skip the first check to allow time for initial handshake and greeting
			if c.minBytesPerMinute > 0 && throughputDuration >= time.Minute {
				sessionDurationSinceStart := time.Since(c.sessionStart)

				// Only enforce throughput after the first 2 minutes of the session
				// to allow time for TLS handshake, greeting, and initial authentication
				if sessionDurationSinceStart >= 2*time.Minute {
					minutesElapsed := throughputDuration.Minutes()
					bytesPerMinute := float64(bytesTransferred) / minutesElapsed

					if bytesPerMinute < float64(c.minBytesPerMinute) {
						remoteAddr := c.Conn.RemoteAddr().String()
						logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "slow_throughput", "bytes_per_min", int(bytesPerMinute), "required", c.minBytesPerMinute)
						metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "slow_throughput").Inc()

						// Call timeout handler before closing (if provided)
						if c.onTimeout != nil {
							c.onTimeout(c.Conn, "slow_throughput")
						}

						c.Close()
						return
					}
				}

				// Reset throughput counters (even if we didn't enforce the check yet)
				c.mu.Lock()
				c.lastThroughputCheck = time.Now()
				c.bytesTransferred = 0
				c.mu.Unlock()
			}

			// Check idle timeout
			if c.idleTimeout > 0 && idleTime >= c.idleTimeout {
				remoteAddr := c.Conn.RemoteAddr().String()
				logger.Info("Connection closed - timeout", "proto", c.protocol, "remote", remoteAddr, "user", username, "reason", "idle", "idle_time", idleTime.Round(time.Second), "max_idle", c.idleTimeout)
				metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "idle").Inc()

				// Call timeout handler before closing (if provided)
				if c.onTimeout != nil {
					c.onTimeout(c.Conn, "idle")
				}

				c.Close()
				return
			}

		case <-c.cancelIdle:
			return
		}
	}
}

// Read implements net.Conn.Read with activity tracking
func (c *SoraConn) Read(b []byte) (int, error) {
	var n int
	var err error

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

// ResetThroughputCounter resets the bytes transferred counter
// Used when entering IDLE mode to avoid false positives for slowloris detection
func (c *SoraConn) ResetThroughputCounter() {
	c.mu.Lock()
	c.bytesTransferred = 0
	c.mu.Unlock()
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

// ErrTLSOnPlainPort is returned when TLS traffic is detected on a plain-text port
var ErrTLSOnPlainPort = errors.New("TLS connection attempted on plain-text port")

// DetectAndRejectTLS checks if the connection is attempting to use TLS on a plain-text port.
// It peeks at the first 3 bytes to detect the TLS handshake signature (0x16 0x03 0x01/0x02/0x03).
// If TLS is detected, it writes a rejection message and returns ErrTLSOnPlainPort.
// This should be called early in protocol handlers for plain-text ports, before sending greetings.
//
// After calling this method, subsequent Read() calls will use a buffered reader to ensure
// peeked bytes are not lost.
func (c *SoraConn) DetectAndRejectTLS() error {
	// Create a buffered reader for peeking (if not already created)
	if c.reader == nil {
		c.reader = bufio.NewReader(c.Conn)
	}

	// Set a very short deadline just for peeking to avoid blocking on slow clients
	// TLS handshakes send the Client Hello immediately, so 100ms is generous
	originalDeadline := time.Now().Add(100 * time.Millisecond)
	if err := c.Conn.SetReadDeadline(originalDeadline); err != nil {
		// If we can't set deadline, skip detection (better to proceed than fail)
		logger.Warn("TLS detection: cannot set read deadline", "proto", c.protocol, "error", err)
		c.Conn.SetReadDeadline(time.Time{}) // Clear deadline
		return nil
	}

	// Peek at first 3 bytes (does not consume them from the buffer)
	peekBuf, err := c.reader.Peek(3)

	// Clear the deadline immediately
	c.Conn.SetReadDeadline(time.Time{})

	if err != nil {
		// Timeout or other error during peek
		if err == io.EOF {
			// Connection closed before any data - not our concern
			return err
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout means no immediate data - not a TLS handshake
			// (TLS clients send Client Hello immediately upon connect)
			return nil
		}
		// Check for "buffer full" error - might indicate partial read
		if err == bufio.ErrBufferFull {
			// This shouldn't happen with 3 bytes, but proceed anyway
			return nil
		}
		// Other errors will be caught by protocol handler
		return nil
	}

	if len(peekBuf) < 3 {
		// Not enough bytes available - cannot definitively detect TLS
		// This might happen if connection is very slow
		return nil
	}

	// Check for TLS handshake signature
	// TLS records start with: 0x16 (handshake) followed by version (0x03 0x01/0x02/0x03)
	// SSLv3: 0x16 0x03 0x00
	// TLS 1.0: 0x16 0x03 0x01
	// TLS 1.1: 0x16 0x03 0x02
	// TLS 1.2: 0x16 0x03 0x03
	// TLS 1.3: 0x16 0x03 0x03 (legacy version field)
	if peekBuf[0] == 0x16 && peekBuf[1] == 0x03 {
		// This is very likely a TLS Client Hello
		remoteAddr := c.Conn.RemoteAddr().String()
		logger.Warn("TLS handshake detected on plain-text port - rejecting", "proto", c.protocol, "remote", remoteAddr)

		// Write a helpful error message
		// Note: The client's TLS stack won't display this, but it helps with debugging
		c.Conn.Write([]byte("ERROR: TLS connection attempted on plain-text port. Use STARTTLS or connect to the TLS port.\r\n"))

		// Record metric
		metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "tls_on_plain_port").Inc()

		// Close the connection
		c.Close()

		return ErrTLSOnPlainPort
	}

	// Not TLS - normal plain-text connection
	// The peeked bytes remain in the buffer for subsequent reads
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

// Accept wraps accepted connections with SoraConn
func (l *SoraListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return NewSoraConn(conn, l.config), nil
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

	remoteAddr := c.tcpConn.RemoteAddr().String()

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
	c.tlsConn = tls.Server(c.tcpConn, tlsConfig)

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

	// NOW start the timeout checker, after TLS handshake is complete
	if c.connConfig.EnableTimeoutChecker && (c.SoraConn.idleTimeout > 0 || c.SoraConn.absoluteTimeout > 0 || c.SoraConn.minBytesPerMinute > 0) {
		go c.SoraConn.timeoutChecker()
	}

	return nil
}
