package imap

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
)

// timeoutConn wraps a net.Conn to enforce multiple timeout protections for IMAP:
// - Idle timeout: protects against completely idle connections
// - Absolute timeout: enforces maximum session duration (30 minutes)
// - Minimum throughput: protects against slowloris attacks (slow byte-by-byte transmission)
type timeoutConn struct {
	net.Conn
	idleTimeout         time.Duration
	absoluteTimeout     time.Duration // Maximum total session duration (30 minutes)
	minBytesPerMinute   int64         // Minimum bytes/minute to avoid slowloris (0 = disabled)
	mu                  sync.Mutex
	lastActivity        time.Time
	sessionStart        time.Time
	lastThroughputCheck time.Time
	bytesTransferred    int64  // Bytes since last throughput check
	protocol            string // For metrics labeling
	closed              bool
	cancelIdle          chan struct{} // Signal to stop timeout checker
}

// newTimeoutConn creates a connection wrapper that enforces multiple timeout protections
func newTimeoutConn(conn net.Conn, idleTimeout time.Duration, absoluteTimeout time.Duration, minBytesPerMinute int64, protocol string) *timeoutConn {
	now := time.Now()

	// Use defaults if not specified
	if minBytesPerMinute == 0 {
		minBytesPerMinute = 1024 // Default: 1KB/minute (very lenient)
	}
	if absoluteTimeout == 0 {
		absoluteTimeout = 30 * time.Minute // Default: 30 minutes
	}

	tc := &timeoutConn{
		Conn:                conn,
		idleTimeout:         idleTimeout,
		absoluteTimeout:     absoluteTimeout,
		minBytesPerMinute:   minBytesPerMinute,
		lastActivity:        now,
		sessionStart:        now,
		lastThroughputCheck: now,
		bytesTransferred:    0,
		protocol:            protocol,
		closed:              false,
		cancelIdle:          make(chan struct{}),
	}

	// Start background timeout checker
	if idleTimeout > 0 || tc.absoluteTimeout > 0 || tc.minBytesPerMinute > 0 {
		go tc.timeoutChecker()
	}

	return tc
}

// timeoutChecker runs in background and closes connection if:
// 1. Idle too long (no activity for idleTimeout duration)
// 2. Session too long (total duration exceeds absoluteTimeout)
// 3. Throughput too slow (less than minBytesPerMinute)
func (c *timeoutConn) timeoutChecker() {
	// Check frequency: every 1 minute for throughput, or more frequently for idle timeout
	checkInterval := 1 * time.Minute // Check throughput every minute
	if c.idleTimeout > 0 && c.idleTimeout/4 < checkInterval {
		checkInterval = c.idleTimeout / 4
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			idleTime := time.Since(c.lastActivity)
			sessionDuration := time.Since(c.sessionStart)
			throughputDuration := time.Since(c.lastThroughputCheck)
			bytesTransferred := c.bytesTransferred
			closed := c.closed
			c.mu.Unlock()

			if closed {
				return
			}

			// Check absolute session timeout first (highest priority)
			if c.absoluteTimeout > 0 && sessionDuration >= c.absoluteTimeout {
				// Session has exceeded maximum duration
				remoteAddr := c.Conn.RemoteAddr().String()
				log.Printf("[%s-TIMEOUT] remote=%s reason=session_max duration=%v: Connection closed - exceeded maximum session duration (%v)",
					c.protocol, remoteAddr, sessionDuration.Round(time.Second), c.absoluteTimeout)
				metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "session_max").Inc()
				c.Conn.Close() // Force close the underlying connection
				return
			}

			// Check minimum throughput (protects against slowloris byte-by-byte attacks)
			if c.minBytesPerMinute > 0 && throughputDuration >= time.Minute {
				// Calculate bytes per minute for this check period
				minutesElapsed := throughputDuration.Minutes()
				bytesPerMinute := float64(bytesTransferred) / minutesElapsed

				if bytesPerMinute < float64(c.minBytesPerMinute) {
					// Throughput is too slow - this is a slowloris attack
					remoteAddr := c.Conn.RemoteAddr().String()
					log.Printf("[%s-TIMEOUT] remote=%s reason=slow_throughput bytes_per_min=%.0f required=%d: Connection closed - throughput too slow (possible slowloris attack)",
						c.protocol, remoteAddr, bytesPerMinute, c.minBytesPerMinute)
					metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "slow_throughput").Inc()
					c.Conn.Close() // Force close the underlying connection
					return
				}

				// Reset throughput counters for next check period
				c.mu.Lock()
				c.lastThroughputCheck = time.Now()
				c.bytesTransferred = 0
				c.mu.Unlock()
			}

			// Check idle timeout (no activity at all)
			if c.idleTimeout > 0 && idleTime >= c.idleTimeout {
				// Connection has been completely idle too long
				remoteAddr := c.Conn.RemoteAddr().String()
				log.Printf("[%s-TIMEOUT] remote=%s reason=idle idle_time=%v max_idle=%v: Connection closed - no activity detected",
					c.protocol, remoteAddr, idleTime.Round(time.Second), c.idleTimeout)
				metrics.CommandTimeoutsTotal.WithLabelValues(c.protocol, "idle").Inc()
				c.Conn.Close() // Force close the underlying connection
				return
			}

		case <-c.cancelIdle:
			// Connection closed normally
			return
		}
	}
}

// Read implements net.Conn.Read and tracks activity and throughput
func (c *timeoutConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)

	// Update activity time and bytes transferred on successful read
	if n > 0 {
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.bytesTransferred += int64(n)
		c.mu.Unlock()
	}

	return n, err
}

// Write implements net.Conn.Write and tracks activity and throughput
func (c *timeoutConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)

	// Update activity time and bytes transferred on successful write
	if n > 0 {
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.bytesTransferred += int64(n)
		c.mu.Unlock()
	}

	return n, err
}

// ResetThroughputCounter resets the throughput measurement counters.
// This should be called when entering IMAP IDLE or other states where
// minimal traffic is expected and legitimate.
func (c *timeoutConn) ResetThroughputCounter() {
	c.mu.Lock()
	c.lastThroughputCheck = time.Now()
	c.bytesTransferred = 0
	c.mu.Unlock()
}

// Close stops the idle checker and closes the connection
func (c *timeoutConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.cancelIdle) // Stop idle checker goroutine
	}
	c.mu.Unlock()

	return c.Conn.Close()
}

// Unwrap returns the underlying connection, allowing connection unwrapping
// to work properly for JA4 fingerprint extraction
func (c *timeoutConn) Unwrap() net.Conn {
	return c.Conn
}

// timeoutListener wraps a net.Listener to apply timeout to accepted connections
type timeoutListener struct {
	net.Listener
	timeout           time.Duration
	absoluteTimeout   time.Duration
	minBytesPerMinute int64
	protocol          string
}

// Accept wraps accepted connections with timeout enforcement
func (l *timeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Wrap the connection with timeout enforcement
	if l.timeout > 0 || l.absoluteTimeout > 0 || l.minBytesPerMinute > 0 {
		return newTimeoutConn(conn, l.timeout, l.absoluteTimeout, l.minBytesPerMinute, l.protocol), nil
	}

	return conn, nil
}
