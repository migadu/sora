package server

import (
	"context"
	"errors"
	"net"
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
// Returns ErrDelayQueueFull if too many concurrent delays are already in progress for this IP
func ApplyAuthenticationDelay(ctx context.Context, limiter any, remoteAddr net.Addr, protocol string) error {
	return applyAuthenticationDelayWithManager(ctx, limiter, remoteAddr, protocol, getDelayManager())
}

// applyAuthenticationDelayWithManager is the internal implementation that accepts a DelayManager
// This allows for testing with custom delay managers
func applyAuthenticationDelayWithManager(ctx context.Context, limiter any, remoteAddr net.Addr, protocol string, dm *DelayManager) error {
	delayHelper, ok := limiter.(AuthDelayHelper)
	if !ok || delayHelper == nil {
		return nil
	}

	delay := delayHelper.GetAuthenticationDelay(remoteAddr)
	if delay <= 0 {
		return nil
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// Try to acquire a delay slot (non-blocking)
	if !dm.tryAcquire(ip) {
		// Queue full for this IP - fast-reject to prevent goroutine exhaustion
		metrics.AuthDelayRejections.WithLabelValues(protocol, ip).Inc()
		logger.Info("Auth delay: Queue full, rejecting connection", "protocol", protocol, "ip", ip, "delay", delay)
		return ErrDelayQueueFull
	}
	defer dm.release(ip)

	// Track queue depth
	metrics.AuthDelayQueueDepth.WithLabelValues(protocol, ip).Inc()
	defer metrics.AuthDelayQueueDepth.WithLabelValues(protocol, ip).Dec()

	logger.Debug("Auth delay: Applying delay", "protocol", protocol, "delay", delay, "ip", ip)

	// Use context-aware delay to allow cancellation
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Delay completed normally
		metrics.AuthDelayCompleted.WithLabelValues(protocol, ip).Inc()
		logger.Debug("Auth delay: Delay completed", "protocol", protocol, "ip", ip)
		return nil
	case <-ctx.Done():
		// Context cancelled (connection closed, server shutdown, etc.)
		metrics.AuthDelayCancelled.WithLabelValues(protocol, ip).Inc()
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
