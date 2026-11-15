package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// ErrDelayQueueFull is returned when the delay queue is full (too many concurrent delays for an IP)
var ErrDelayQueueFull = errors.New("delay queue full for IP")

// AuthDelayHelper provides delay functionality for authentication rate limiting
type AuthDelayHelper interface {
	GetAuthenticationDelay(remoteAddr net.Addr) time.Duration
}

// DelayManager manages per-IP concurrent auth delay counts to prevent goroutine exhaustion
type DelayManager struct {
	maxConcurrentDelaysPerIP int
	ipCounts                 map[string]int
	mu                       sync.Mutex
}

// NewDelayManager creates a DelayManager with the specified max concurrent delays per IP
func NewDelayManager(maxConcurrentDelaysPerIP int) *DelayManager {
	if maxConcurrentDelaysPerIP <= 0 {
		maxConcurrentDelaysPerIP = 10 // Default: max 10 concurrent delays per IP
	}
	return &DelayManager{
		maxConcurrentDelaysPerIP: maxConcurrentDelaysPerIP,
		ipCounts:                 make(map[string]int),
	}
}

// tryAcquire attempts to acquire a delay slot for the IP (non-blocking)
func (dm *DelayManager) tryAcquire(ip string) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	count := dm.ipCounts[ip]
	if count >= dm.maxConcurrentDelaysPerIP {
		return false // Queue full
	}
	dm.ipCounts[ip] = count + 1
	return true
}

// release releases a delay slot for the IP
func (dm *DelayManager) release(ip string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	count, exists := dm.ipCounts[ip]
	if !exists {
		return
	}
	if count <= 1 {
		delete(dm.ipCounts, ip)
	} else {
		dm.ipCounts[ip] = count - 1
	}
}

// Global delay manager (initialized on first use)
var (
	globalDelayManager     *DelayManager
	globalDelayManagerOnce sync.Once
)

// getDelayManager returns the global delay manager (lazy initialization)
func getDelayManager() *DelayManager {
	globalDelayManagerOnce.Do(func() {
		globalDelayManager = NewDelayManager(10) // Max 10 concurrent delays per IP
	})
	return globalDelayManager
}

// ApplyAuthenticationDelay applies progressive delays before authentication attempts
// Returns ErrDelayQueueFull if too many concurrent delays are already in progress for this IP.
// protocol labels the sora_auth_delay_* metrics: the caller's server type, spelled as
// its other metrics spell it ("imap", "imap_proxy", "userapi", ...).
func ApplyAuthenticationDelay(ctx context.Context, limiter any, remoteAddr net.Addr, protocol string) error {
	return applyAuthenticationDelayWithManager(ctx, limiter, remoteAddr, protocol, getDelayManager())
}

// ApplyHTTPAuthenticationDelay is ApplyAuthenticationDelay for a login an HTTP handler
// answers. net/http sets the request's write deadline (http.Server WriteTimeout) when it
// has read the request, before the handler runs, and a delay up to max_delay can outlast
// it: the answer written after the delay was then dropped and the connection closed, so
// the client got no response at all, not even for the right password (#1074). Before it
// waits, it moves the write deadline of w to the end of the delay plus budget, the time
// left for the rest of the login and its answer: the server's WriteTimeout, which is what
// a login without a delay has. The delay is never shortened to fit a deadline, and the
// deadline stays bounded, by max_delay plus budget.
func ApplyHTTPAuthenticationDelay(ctx context.Context, w http.ResponseWriter, limiter any, remoteAddr net.Addr, protocol string, budget time.Duration) error {
	rc := http.NewResponseController(w)
	return delayAuthentication(ctx, limiter, remoteAddr, protocol, getDelayManager(), func(delay time.Duration) {
		if err := rc.SetWriteDeadline(time.Now().Add(delay + budget)); err != nil {
			logger.Warn("Auth delay: could not move the HTTP write deadline past the delay", "protocol", protocol, "delay", delay, "error", err)
		}
	})
}

// applyAuthenticationDelayWithManager is the internal implementation that accepts a DelayManager
// This allows for testing with custom delay managers
func applyAuthenticationDelayWithManager(ctx context.Context, limiter any, remoteAddr net.Addr, protocol string, dm *DelayManager) error {
	return delayAuthentication(ctx, limiter, remoteAddr, protocol, dm, nil)
}

// delayAuthentication waits out the delay of limiter for remoteAddr in a slot of dm.
// beforeWait, if not nil, is called with the delay once the slot is taken, just before
// the wait.
func delayAuthentication(ctx context.Context, limiter any, remoteAddr net.Addr, protocol string, dm *DelayManager, beforeWait func(delay time.Duration)) error {
	delayHelper, ok := limiter.(AuthDelayHelper)
	if !ok || delayHelper == nil {
		return nil
	}

	delay := delayHelper.GetAuthenticationDelay(remoteAddr)
	if delay <= 0 {
		return nil
	}

	// One slot count per client, however its address is spelled (see clientIPOf).
	ip := clientIPOf(remoteAddr.String())

	// Try to acquire a delay slot (non-blocking)
	if !dm.tryAcquire(ip) {
		// Queue full for this IP - fast-reject to prevent goroutine exhaustion
		metrics.AuthDelayRejections.WithLabelValues(protocol).Inc()
		logger.Info("Auth delay: Queue full, rejecting connection", "protocol", protocol, "ip", ip, "delay", delay)
		return ErrDelayQueueFull
	}
	defer dm.release(ip)

	// Track queue depth
	metrics.AuthDelayQueueDepth.WithLabelValues(protocol).Inc()
	defer metrics.AuthDelayQueueDepth.WithLabelValues(protocol).Dec()

	logger.Debug("Auth delay: Applying delay", "protocol", protocol, "delay", delay, "ip", ip)
	if beforeWait != nil {
		beforeWait(delay)
	}

	// Use context-aware delay to allow cancellation
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Delay completed normally
		metrics.AuthDelayCompleted.WithLabelValues(protocol).Inc()
		logger.Debug("Auth delay: Delay completed", "protocol", protocol, "ip", ip)
		return nil
	case <-ctx.Done():
		// Context cancelled (connection closed, server shutdown, etc.)
		metrics.AuthDelayCancelled.WithLabelValues(protocol).Inc()
		logger.Debug("Auth delay: Delay cancelled", "protocol", protocol, "ip", ip, "error", ctx.Err())
		return ctx.Err()
	}
}

// GetIPString safely extracts IP address from net.Addr
func GetIPString(addr net.Addr) string {
	if ip, _, err := net.SplitHostPort(addr.String()); err == nil {
		return ip
	}
	return addr.String()
}
