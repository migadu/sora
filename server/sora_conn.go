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

// Timeout notices are best effort. A peer that does not read must not hold a
// scheduler shard, its connection, or the notice goroutine open indefinitely.
const timeoutNoticeGrace = 100 * time.Millisecond

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

	checked   atomic.Bool // registered with the timeout checker (see CheckedTimeouts)
	timingOut atomic.Bool // one owner for timeout notification and teardown

	// Server context for metrics
	protocol   string
	serverName string
	hostname   string

	// Timeout protection
	idleTimeout         time.Duration // Maximum idle time (e.g., 5 minutes)
	absoluteTimeout     time.Duration // Maximum session duration (e.g., 30 minutes)
	minBytesPerMinute   int64         // Minimum throughput (0 = disabled)
	throughputWindow    time.Duration // Slowloris measurement window (see checkTimeouts)
	throughputGrace     time.Duration // Session age before a window counts against the connection
	lastActivity        time.Time
	sessionStart        time.Time
	lastThroughputCheck time.Time
	// Slowloris protection: bytes moved in the current measurement window, per
	// direction. The direction matters: a window with client bytes in and no
	// server bytes out is a command that never completed (the slowloris
	// signature); a window with any server output is a command that did.
	bytesRead                   int64
	bytesWritten                int64
	consecutiveStalledWindows   int  // Consecutive windows with input but no completed command
	throughputCheckingSuspended bool // True when in IDLE mode (IMAP)

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
	// currentConn reports the connection the protocol is using (see
	// SetTimeoutNoticeConn). It is called only on the goroutine that reads, which
	// records its answer in noticeConn, under mu, for the timeout goroutine:
	// the connection a library layered above this one, nil while there is none.
	// noticeTLS, under mu too, is whether that connection's handshake is done.
	currentConn func() net.Conn
	noticeConn  net.Conn
	noticeTLS   handshakeCheck
	// startTLS is where a STARTTLS upgrade of a connection with a provider
	// stands, under mu; startTLSScan finds the command in what the reading
	// goroutine reads. See noticeTarget.
	startTLS     startTLSPhase
	startTLSScan startTLSScanner
	// noticeMu is held while an asynchronous notice is chosen a writer and
	// written, so that the read of a STARTTLS command can wait for a plaintext
	// notice to finish before the library gets to acknowledge the command.
	noticeMu sync.Mutex

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
	AbsoluteTimeout      time.Duration // 0 = the 30m default, unless NoAbsoluteTimeout
	MinBytesPerMinute    int64         // 0 = no throughput checking
	InitialJA4           string        // Pre-captured JA4 fingerprint
	InitialProxyInfo     *ProxyProtocolInfo
	EnableTimeoutChecker bool // If false, caller must handle timeouts

	// NoAbsoluteTimeout has the checker enforce no session limit (AbsoluteTimeout is
	// ignored): for a caller whose protocol library owns that limit.
	NoAbsoluteTimeout bool

	// ThroughputWindow is the window the slowloris check samples a connection's
	// throughput over, and ThroughputGrace the session age before a window counts
	// against it (see checkTimeouts); 0 = one minute and two minutes. Production
	// leaves both at their defaults; a test shortens them so a multi-minute
	// measurement history runs in under a second.
	ThroughputWindow time.Duration
	ThroughputGrace  time.Duration

	// OnTimeout is called before closing connection due to timeout.
	// The reason will be one of: "idle", "slow_throughput", or "session_max".
	// The handler should send a protocol-specific goodbye message and return quickly.
	// It runs outside the scheduler, with a bounded write deadline and transport
	// closure to unblock pending I/O. It must not wait on anything other than conn I/O.
	// If nil, the connection will be closed without sending any message.
	// The conn parameter is the connection to write the goodbye message to: the
	// underlying transport, or the connection registered with SetTimeoutNoticeConn.
	OnTimeout func(conn net.Conn, reason string)
}

// NewSoraConn creates a new SoraConn wrapping the given connection
func NewSoraConn(conn net.Conn, config SoraConnConfig) *SoraConn {
	now := time.Now()

	// Apply defaults (MinBytesPerMinute default is protocol-specific, set by caller)
	if config.NoAbsoluteTimeout {
		config.AbsoluteTimeout = 0
	} else if config.AbsoluteTimeout == 0 {
		config.AbsoluteTimeout = 30 * time.Minute // Default: 30 minutes
	}
	if config.Protocol == "" {
		config.Protocol = "unknown"
	}
	if config.ThroughputWindow <= 0 {
		config.ThroughputWindow = time.Minute
	}
	if config.ThroughputGrace <= 0 {
		config.ThroughputGrace = 2 * time.Minute
	}

	sc := &SoraConn{
		Conn:                conn,
		remoteAddr:          "",
		idleTimeout:         config.IdleTimeout,
		absoluteTimeout:     config.AbsoluteTimeout,
		minBytesPerMinute:   config.MinBytesPerMinute,
		throughputWindow:    config.ThroughputWindow,
		throughputGrace:     config.ThroughputGrace,
		lastActivity:        now,
		sessionStart:        now,
		lastThroughputCheck: now,
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

	if closed || c.timingOut.Load() {
		return
	}

	c.mu.RLock()
	idleTime := now.Sub(c.lastActivity)
	sessionDuration := now.Sub(c.sessionStart)
	throughputDuration := now.Sub(c.lastThroughputCheck)
	bytesRead := c.bytesRead
	bytesWritten := c.bytesWritten
	username := c.username
	suspended := c.throughputCheckingSuspended
	c.mu.RUnlock()

	// Check absolute session timeout (highest priority)
	if c.absoluteTimeout > 0 && sessionDuration >= c.absoluteTimeout {
		c.closeForTimeout(username, "session_max", "duration", sessionDuration.Round(time.Second), "max", c.absoluteTimeout)
		return
	}

	// Slowloris protection. A slowloris holds a connection by feeding the
	// command parser bytes that never complete a command, so the signature is
	// a whole window of client input with no server output. Raw bytes per
	// minute alone are NOT the signal: a client that completes a tiny command
	// every few seconds (Alpine's NOOP poll, any client without IDLE) moves
	// well under 512 bytes/min and is healthy, and a silent client is the idle
	// timer's business. Measuring volume alone cut every Alpine session four
	// minutes in as "too slow" (2026-10-01).
	//
	// Rules per window, once the two-minute post-handshake grace is over:
	//   - any server output: a command completed, stall count resets;
	//   - client input under the threshold and no output: a stalled window;
	//   - no bytes either way: left to the idle timeout, count unchanged.
	// Two consecutive stalled windows disconnect.
	// Skipped while suspended (IMAP IDLE), where client silence is expected.
	if c.minBytesPerMinute > 0 && throughputDuration >= c.throughputWindow {
		if suspended {
			// Throughput checking is suspended - skip check
			return
		}

		if sessionDuration >= c.throughputGrace {
			bytesPerMinute := int64(float64(bytesRead+bytesWritten) / throughputDuration.Minutes())

			c.mu.Lock()
			switch {
			case bytesWritten > 0:
				c.consecutiveStalledWindows = 0
			case bytesRead > 0 && bytesPerMinute < c.minBytesPerMinute:
				c.consecutiveStalledWindows++
			}
			stalled := c.consecutiveStalledWindows
			c.mu.Unlock()

			if stalled >= 2 {
				c.closeForTimeout(username, "slow_throughput", "bytes_read", bytesRead, "bytes_written", bytesWritten, "bytes_per_min", bytesPerMinute, "required", c.minBytesPerMinute, "stalled_windows", stalled)
				return
			}
		}

		c.openNextThroughputWindow(now, bytesRead, bytesWritten)
	}

	// Check idle timeout
	if c.idleTimeout > 0 && idleTime >= c.idleTimeout {
		c.closeForTimeout(username, "idle", "idle_time", idleTime.Round(time.Second), "max_idle", c.idleTimeout)
	}
}

// closeForTimeout claims the timeout once before handing off any socket work.
// A blocked peer must never prevent the shard from checking another connection.
func (c *SoraConn) closeForTimeout(username, reason string, details ...any) {
	if !c.timingOut.CompareAndSwap(false, true) {
		return
	}
	attrs := []any{"proto", c.protocol, "remote", c.remoteAddr, "user", username, "reason", reason}
	logger.Info("Connection closed - timeout", append(attrs, details...)...)
	metrics.ConnectionTimeoutsTotal.WithLabelValues(c.protocol, c.serverName, c.hostname, reason).Inc()

	go func() {
		// Unregister here too: Stop may hold the scheduler mutex while waiting
		// for the shard to exit, so the shard must not perform this operation.
		unregisterConn(c)
		transport := c.Conn
		// A concurrent protocol writer can replace the deadline, and TLS Close
		// can wait while sending close_notify. Close the underlying transport
		// at the same bound so neither can strand this goroutine.
		timer := time.AfterFunc(timeoutNoticeGrace, func() { closeTimeoutTransport(transport) })
		defer timer.Stop()
		defer c.Close()
		if c.onTimeout == nil {
			return
		}
		// The notice goes to the connection the protocol is using: the
		// transport, unless a library layered its own connection above this
		// one (STARTTLS) and registered it with SetTimeoutNoticeConn. Both
		// reach the socket through transport, whose deadline bounds the write.
		c.writeNotice(transport, func(notice net.Conn) {
			if err := transport.SetWriteDeadline(time.Now().Add(timeoutNoticeGrace)); err == nil {
				c.onTimeout(notice, reason)
			}
		})
	}()
}

// startTLSPhase is where the STARTTLS upgrade of a connection stands, as far
// as the bytes its client sends show it.
type startTLSPhase int

const (
	// startTLSNone: the session is plaintext, and a plaintext notice is safe.
	startTLSNone startTLSPhase = iota
	// startTLSRequested: the last thing read was a STARTTLS command. The
	// library may acknowledge it at any moment, and the client then expects TLS.
	startTLSRequested
	// startTLSHandshaking: the client has started the TLS handshake.
	startTLSHandshaking
)

// startTLSVerbs are the commands that start the upgrade: POP3's (RFC 2595) and
// that of IMAP, ManageSieve and LMTP.
var startTLSVerbs = [...]string{"STLS", "STARTTLS"}

// startTLSScanner finds a STARTTLS command in the plaintext a client sends. The
// verb is the first word of a line, or the second behind an IMAP tag.
type startTLSScanner struct {
	words   int                      // words completed on the current line
	length  int                      // bytes of the word being read, 0 between words
	matches [len(startTLSVerbs)]bool // the word so far is the start of that verb
	found   bool                     // a word of the current line was a verb
}

// scan consumes data and reports whether it ends with a complete STARTTLS
// command line. A command with anything behind it was pipelined, which the
// library refuses.
func (s *startTLSScanner) scan(data []byte) bool {
	ended := false
	for _, b := range data {
		ended = false
		switch b {
		case '\n':
			s.endWord()
			ended = s.found
			*s = startTLSScanner{}
		case ' ', '\t', '\r':
			s.endWord()
		default:
			if s.words >= 2 {
				continue
			}
			for i, verb := range startTLSVerbs {
				s.matches[i] = (s.length == 0 || s.matches[i]) && s.length < len(verb) && verb[s.length] == b&^0x20
			}
			s.length++
		}
	}
	return ended
}

func (s *startTLSScanner) endWord() {
	if s.length == 0 {
		return
	}
	for i, verb := range startTLSVerbs {
		if s.matches[i] && s.length == len(verb) {
			s.found = true
		}
	}
	s.words++
	s.length = 0
}

// trackStartTLS follows a possible STARTTLS upgrade through data, which the
// reading goroutine has just read in plaintext. A library offers no hook
// between reading the command and acknowledging it, so the command itself is
// the last moment at which a plaintext notice can be ruled out.
func (c *SoraConn) trackStartTLS(data []byte) {
	c.mu.RLock()
	phase := c.startTLS
	c.mu.RUnlock()
	if phase == startTLSHandshaking {
		return
	}
	next := startTLSNone
	if phase == startTLSRequested && data[0] == 0x16 {
		// A TLS handshake record, where a refused STARTTLS would be followed
		// by the next command: the upgrade is under way.
		next = startTLSHandshaking
	} else if c.startTLSScan.scan(data) {
		next = startTLSRequested
	}
	if next == phase {
		return
	}
	c.mu.Lock()
	if c.startTLS != startTLSHandshaking {
		c.startTLS = next
	}
	c.mu.Unlock()
	if next != startTLSNone {
		// A notice that chose the plaintext writer before the change is being
		// written under noticeMu: let it finish before the library sees the
		// command.
		c.noticeMu.Lock()
		c.noticeMu.Unlock()
	}
}

// markStartTLSHandshake records that a TLS handshake above this connection has
// begun (StartTLSConfig calls it with the ClientHello), whether or not the
// STARTTLS command was recognised in the stream.
func (c *SoraConn) markStartTLSHandshake() {
	c.mu.Lock()
	c.startTLS = startTLSHandshaking
	c.mu.Unlock()
}

// noticeTarget returns the connection an asynchronous notice may be written to
// right now, plain being the plaintext one, and nil when there is none: from
// the STARTTLS command until the library's TLS connection has completed its
// handshake the client reads neither plaintext nor, yet, TLS.
func (c *SoraConn) noticeTarget(plain net.Conn) net.Conn {
	c.mu.RLock()
	upgraded, phase := c.noticeConn, c.startTLS
	handshaken := c.noticeTLS.ready
	c.mu.RUnlock()
	if upgraded != nil {
		// A library may publish its *tls.Conn before the handshake has run
		// (go-imap does); a Write would then run, or wait for, the server
		// handshake on this goroutine.
		if _, isTLS := upgraded.(*tls.Conn); isTLS && !handshaken {
			return nil
		}
		return upgraded
	}
	if phase != startTLSNone {
		return nil
	}
	return plain
}

// writeNotice calls write with the connection an asynchronous notice may be
// written to, and returns false without calling it when there is none.
func (c *SoraConn) writeNotice(plain net.Conn, write func(net.Conn)) bool {
	c.noticeMu.Lock()
	defer c.noticeMu.Unlock()
	target := c.noticeTarget(plain)
	if target == nil {
		return false
	}
	write(target)
	return true
}

// notices returns the SoraConn itself; a type embedding one promotes it, which
// is how soraConnUnder finds the SoraConn of a wrapper.
func (c *SoraConn) notices() *SoraConn { return c }

// soraConnUnder returns the SoraConn that conn is or wraps, or nil.
func soraConnUnder(conn net.Conn) *SoraConn {
	for conn != nil {
		if sc, ok := conn.(interface{ notices() *SoraConn }); ok {
			return sc.notices()
		}
		w, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			return nil
		}
		conn = w.Unwrap()
	}
	return nil
}

// recordNoticeConn asks the registered provider for the connection the
// protocol is using and records it for the notice writers. Only the goroutine
// that reads may call it: a library swaps in its STARTTLS connection on that
// goroutine, with nothing the timeout goroutine could synchronise with. It
// reports whether the session may still upgrade: there is a provider, and it
// has no upgraded connection yet.
func (c *SoraConn) recordNoticeConn() bool {
	return c.recordNoticeConnDuring(false)
}

// recordNoticeConnDuring is recordNoticeConn; reading says the caller is Read.
//
// A *tls.Conn is a writer for notices only once its handshake is complete,
// which ConnectionState tells, but not without waiting for a handshake in
// progress, and it is the handshake that issues the Read in which go-imap's
// connection is first seen: the question is then asked on a goroutine of its
// own, which gets its answer when the handshake ends. Elsewhere the reading
// goroutine is not inside a handshake and asks directly.
func (c *SoraConn) recordNoticeConnDuring(reading bool) bool {
	if c.currentConn == nil {
		return false
	}
	current := c.currentConn()
	tlsConn, _ := current.(*tls.Conn)
	c.mu.Lock()
	c.noticeConn = current
	if c.noticeTLS.conn != tlsConn {
		c.noticeTLS = handshakeCheck{conn: tlsConn}
	}
	check := tlsConn != nil && !c.noticeTLS.ready && !c.noticeTLS.checking
	if check {
		c.noticeTLS.checking = true
	}
	c.mu.Unlock()
	if check {
		ask := func() {
			ready := tlsConn.ConnectionState().HandshakeComplete
			c.mu.Lock()
			if c.noticeTLS.conn == tlsConn {
				c.noticeTLS.ready, c.noticeTLS.checking = ready, false
			}
			c.mu.Unlock()
		}
		if reading {
			go ask()
		} else {
			ask()
		}
	}
	return current == nil
}

// handshakeCheck is what is known of the handshake of the *tls.Conn a provider
// reported.
type handshakeCheck struct {
	conn     *tls.Conn
	ready    bool // the handshake is complete
	checking bool // a goroutine is waiting to learn whether it is
}

// SetTimeoutNoticeConn tells the SoraConn that conn is or wraps where the
// protocol library's own connection is, for a listener whose library upgrades
// the stream with STARTTLS. The library layers its TLS connection ABOVE the
// SoraConn, so a notice written to the transport after the upgrade lands in
// plaintext under the TLS records and the client sees a TLS error in place of
// it (#163). current is the library's accessor for that connection: the TLS
// connection once there is one, nil before. While it returns nil the SoraConn
// follows the client's side of the stream itself: a notice goes to the
// transport in plaintext until the client sends STARTTLS, and nowhere from
// then until the TLS connection is there with its handshake complete (the hard
// close stays). A STARTTLS the library refuses shows in the plaintext command
// that follows it.
//
// Call it on the goroutine that reads conn (a library's NewSession). current is
// called only there, at registration and as each Read starts, never by the
// timeout goroutine, so it may read the library's state without
// synchronisation; the read that follows an upgrade picks up the new
// connection, and RefreshTimeoutNoticeConn does where none follows. It returns
// false when there is no SoraConn under conn.
func SetTimeoutNoticeConn(conn net.Conn, current func() net.Conn) bool {
	sc := soraConnUnder(conn)
	if sc == nil {
		return false
	}
	sc.currentConn = current
	sc.recordNoticeConn()
	return true
}

// RefreshTimeoutNoticeConn asks the provider registered with
// SetTimeoutNoticeConn again. A TLS 1.3 client may send its first command with
// the end of its handshake; the library then runs that command without a read
// of the SoraConn in between, which is where the provider is otherwise asked.
// Call it on the goroutine that reads conn, from a command that can take long.
func RefreshTimeoutNoticeConn(conn net.Conn) {
	if sc := soraConnUnder(conn); sc != nil {
		sc.recordNoticeConn()
	}
}

// NoticeConn returns the connection an asynchronous notice to the session on
// conn may be written to: conn itself, or the TLS connection a library layered
// above its SoraConn on STARTTLS. It returns nil while that upgrade is being
// negotiated; callers must omit the notice in that case and retain normal
// closure. WriteNotice also keeps the upgrade from starting under the notice.
func NoticeConn(conn net.Conn) net.Conn {
	if sc := soraConnUnder(conn); sc != nil {
		return sc.noticeTarget(conn)
	}
	return conn
}

// WriteNotice calls write with the connection NoticeConn returns for conn, and
// returns false without calling it when there is none. A STARTTLS command that
// arrives meanwhile is not handed to the library until write has returned, so
// the notice cannot follow the acknowledgement of the upgrade in plaintext.
func WriteNotice(conn net.Conn, write func(net.Conn)) bool {
	if sc := soraConnUnder(conn); sc != nil {
		return sc.writeNotice(conn, write)
	}
	write(conn)
	return true
}

// closeTimeoutTransport bypasses TLS close_notify and wrapper cleanup, which
// c.Close performs afterwards. Closing the innermost socket unblocks its I/O.
func closeTimeoutTransport(conn net.Conn) {
	if raw := RawConn(conn); raw != nil {
		raw.Close()
	}
}

// openNextThroughputWindow starts a new measurement window at now. It
// subtracts what the check observed (seenRead/seenWritten) rather than
// zeroing, so bytes that landed between the snapshot and this call are not
// lost. A Suspend/Resume that zeroed the counters in that gap would drive
// them negative; clamp so the next window starts from zero instead of having
// to earn the deficit back before its input counts.
func (c *SoraConn) openNextThroughputWindow(now time.Time, seenRead, seenWritten int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastThroughputCheck = now
	if c.bytesRead -= seenRead; c.bytesRead < 0 {
		c.bytesRead = 0
	}
	if c.bytesWritten -= seenWritten; c.bytesWritten < 0 {
		c.bytesWritten = 0
	}
}

// Read implements net.Conn.Read with activity tracking
func (c *SoraConn) Read(b []byte) (int, error) {
	var n int
	var err error

	upgradeable := c.recordNoticeConnDuring(true)

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
		c.bytesRead += int64(n)
		c.mu.Unlock()
		if upgradeable {
			c.trackStartTLS(b[:n])
		}
	}

	return n, err
}

// Write implements net.Conn.Write with activity tracking
func (c *SoraConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)

	if n > 0 {
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.bytesWritten += int64(n)
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
	c.bytesRead = 0 // Reset counters as well
	c.bytesWritten = 0
	c.mu.Unlock()
	logger.Info("Throughput checking suspended", "proto", c.protocol, "remote", c.remoteAddr)
}

// ResumeThroughputChecking re-enables slowloris throughput checks
// Used when exiting IDLE mode to restore normal protection
func (c *SoraConn) ResumeThroughputChecking() {
	c.mu.Lock()
	c.throughputCheckingSuspended = false
	c.bytesRead = 0 // Reset counters for fresh start
	c.bytesWritten = 0
	c.lastThroughputCheck = time.Now() // Reset timing
	c.consecutiveStalledWindows = 0    // Clear stall counter
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

// CheckedTimeouts are the limits the timeout checker enforces on a connection; a zero
// value is a limit it does not enforce.
type CheckedTimeouts struct {
	Idle              time.Duration
	Absolute          time.Duration
	MinBytesPerMinute int64
}

// CheckedTimeouts returns the limits the timeout checker enforces on this connection,
// as its listener configured it when it accepted the connection: none while it is not
// checked (the checker is off for it, or its TLS handshake has not completed).
func (c *SoraConn) CheckedTimeouts() CheckedTimeouts {
	if !c.checked.Load() {
		return CheckedTimeouts{}
	}
	return CheckedTimeouts{Idle: c.idleTimeout, Absolute: c.absoluteTimeout, MinBytesPerMinute: c.minBytesPerMinute}
}

// ConnCheckedTimeouts returns the CheckedTimeouts of the SoraConn that conn is or wraps,
// walking the Unwrap chain (and a *tls.Conn on top of it, after STARTTLS). ok is false
// when there is no SoraConn under conn.
func ConnCheckedTimeouts(conn net.Conn) (timeouts CheckedTimeouts, ok bool) {
	for conn != nil {
		if sc, isSora := conn.(interface{ CheckedTimeouts() CheckedTimeouts }); isSora {
			return sc.CheckedTimeouts(), true
		}
		switch c := conn.(type) {
		case interface{ Unwrap() net.Conn }:
			conn = c.Unwrap()
		case *tls.Conn:
			conn = c.NetConn()
		default:
			return CheckedTimeouts{}, false
		}
	}
	return CheckedTimeouts{}, false
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
	config func() SoraConnConfig
}

// NewSoraListener creates a listener that wraps accepted connections with SoraConn
func NewSoraListener(listener net.Listener, config SoraConnConfig) *SoraListener {
	return NewSoraListenerFunc(listener, func() SoraConnConfig { return config })
}

// NewSoraListenerFunc is NewSoraListener with the configuration asked for at every
// accepted connection, so the timeouts a config reload changes reach the connections
// accepted after it. Connections already accepted keep theirs.
func NewSoraListenerFunc(listener net.Listener, config func() SoraConnConfig) *SoraListener {
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

		soraConn := NewSoraConn(conn, l.config())

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
	connConfig func() SoraConnConfig
}

// NewSoraTLSListener creates a TLS listener that captures JA4 and returns SoraConn
func NewSoraTLSListener(tcpListener net.Listener, tlsConfig *tls.Config, connConfig SoraConnConfig) *SoraTLSListener {
	return NewSoraTLSListenerFunc(tcpListener, tlsConfig, func() SoraConnConfig { return connConfig })
}

// NewSoraTLSListenerFunc is NewSoraTLSListener with the connection configuration asked
// for at every accepted connection (see NewSoraListenerFunc).
func NewSoraTLSListenerFunc(tcpListener net.Listener, tlsConfig *tls.Config, connConfig func() SoraConnConfig) *SoraTLSListener {
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
	return NewSoraTLSConn(tcpConn, l.tlsConfig, l.connConfig()), nil
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
		captureJA4(c.connConfig.Protocol, hello, c.SetJA4Fingerprint)

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

// captureJA4 hands hello's JA4 fingerprint to record, or "" when the ja4plus
// library panics, as it can on a malformed ClientHello.
func captureJA4(protocol string, hello *tls.ClientHelloInfo, record func(string)) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("JA4 fingerprinting panic recovered (likely malformed ClientHello)", "proto", protocol, "error", r)
			record("")
		}
	}()
	record(ja4plus.JA4(hello))
}

// StartTLSConfig returns a copy of config for a protocol library to upgrade a
// plaintext connection with on STARTTLS. Its handshake records the client's JA4
// fingerprint on the SoraConn under the upgraded connection, as SoraTLSConn's
// does for implicit TLS, so client filters keyed on JA4 apply to STARTTLS
// sessions too. It is nil when config is.
func StartTLSConfig(config *tls.Config, protocol string) *tls.Config {
	if config == nil {
		return nil
	}
	cfg := config.Clone()
	original := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// hello.Conn is the connection the library handed tls.Server: the
		// plaintext one, which is or wraps the SoraConn.
		for conn := hello.Conn; conn != nil; {
			if sc, ok := conn.(interface{ SetJA4Fingerprint(string) }); ok {
				captureJA4(protocol, hello, sc.SetJA4Fingerprint)
				if sc := soraConnUnder(conn); sc != nil {
					sc.markStartTLSHandshake()
				}
				break
			}
			w, ok := conn.(interface{ Unwrap() net.Conn })
			if !ok {
				break
			}
			conn = w.Unwrap()
		}
		if original != nil {
			return original(hello)
		}
		return nil, nil
	}
	return cfg
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
