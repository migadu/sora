package server

import (
	"context"
	"fmt"
	"github.com/migadu/sora/logger"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionLimiter manages connection limits for protocol servers
type ConnectionLimiter struct {
	maxConnections   int
	maxPerIP         int
	currentTotal     atomic.Int64
	perIPConnections sync.Map // map[string]*atomic.Int64 - lock-free for better concurrency
	cleanupInterval  time.Duration
	protocol         string
	trustedNets      []*net.IPNet // Trusted networks that bypass per-IP limits
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(protocol string, maxConnections, maxPerIP int) *ConnectionLimiter {
	return &ConnectionLimiter{
		maxConnections:  maxConnections,
		maxPerIP:        maxPerIP,
		cleanupInterval: 5 * time.Minute, // Clean up stale IP entries
		protocol:        protocol,
		trustedNets:     []*net.IPNet{},
	}
}

// NewConnectionLimiterWithTrustedNets creates a new connection limiter with trusted networks
func NewConnectionLimiterWithTrustedNets(protocol string, maxConnections, maxPerIP int, trustedProxies []string) *ConnectionLimiter {
	trustedNets, err := ParseTrustedNetworks(trustedProxies)
	if err != nil {
		logger.Debug("Connection limiter: WARNING - failed to parse trusted networks", "protocol", protocol, "error", err)
		trustedNets = []*net.IPNet{}
	}

	return &ConnectionLimiter{
		maxConnections:  maxConnections,
		maxPerIP:        maxPerIP,
		cleanupInterval: 5 * time.Minute, // Clean up stale IP entries
		protocol:        protocol,
		trustedNets:     trustedNets,
	}
}

// IsTrustedConnection checks if connection is from trusted network (public method)
func (cl *ConnectionLimiter) IsTrustedConnection(remoteAddr net.Addr) bool {
	return cl.isTrustedConnection(remoteAddr)
}

// isTrustedConnection checks if connection is from trusted network (internal method)
func (cl *ConnectionLimiter) isTrustedConnection(remoteAddr net.Addr) bool {
	if len(cl.trustedNets) == 0 {
		return false
	}

	var ip net.IP
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	default:
		// For unknown types, must use String() which may trigger DNS lookup
		// This should be rare in practice (TCP/UDP are most common)
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	for _, network := range cl.trustedNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// CanAccept checks if a new connection can be accepted from the given remote address
func (cl *ConnectionLimiter) CanAccept(remoteAddr net.Addr) error {
	if cl.maxConnections <= 0 && cl.maxPerIP <= 0 {
		return nil // No limits configured
	}

	// Check total connection limit
	if cl.maxConnections > 0 {
		current := cl.currentTotal.Load()
		if current >= int64(cl.maxConnections) {
			logger.Info("Connection limiter: Maximum total connections reached", "protocol", cl.protocol, "current", current, "max", cl.maxConnections, "remote_addr", GetAddrString(remoteAddr))
			return fmt.Errorf("maximum connections reached (%d/%d)", current, cl.maxConnections)
		}
	}

	// Check per-IP connection limit (skip if maxPerIP is 0, allowing unlimited per-IP for proxy scenarios)
	// Also skip per-IP limits for trusted networks (proxies)
	if cl.maxPerIP > 0 && !cl.isTrustedConnection(remoteAddr) {
		var ip string
		switch a := remoteAddr.(type) {
		case *net.TCPAddr:
			ip = a.IP.String()
		default:
			// Fallback for non-TCP addresses
			host, _, err := net.SplitHostPort(remoteAddr.String())
			if err != nil {
				ip = remoteAddr.String()
			} else {
				ip = host
			}
		}

		if value, exists := cl.perIPConnections.Load(ip); exists {
			ipCounter := value.(*atomic.Int64)
			current := ipCounter.Load()
			if current >= int64(cl.maxPerIP) {
				return fmt.Errorf("maximum connections per IP reached for %s (%d/%d)", ip, current, cl.maxPerIP)
			}
		}
	}

	return nil
}

// AcceptWithRealIP registers a new connection with support for PROXY protocol real client IP
// remoteAddr is the direct connection address (proxy IP if proxied)
// realClientIP is the actual client IP from PROXY protocol (empty string if not proxied)
func (cl *ConnectionLimiter) AcceptWithRealIP(remoteAddr net.Addr, realClientIP string) (func(), error) {
	err := cl.CanAcceptWithRealIP(remoteAddr, realClientIP)
	if err != nil {
		return nil, err
	}

	// Determine which IP to use for per-IP tracking
	var trackingIP string
	isTrusted := cl.isTrustedConnection(remoteAddr)

	if realClientIP != "" && !isTrusted {
		// Use real client IP for per-IP limiting when not from trusted network
		trackingIP = realClientIP
	} else {
		switch a := remoteAddr.(type) {
		case *net.TCPAddr:
			trackingIP = a.IP.String()
		default:
			// Fallback for non-TCP addresses
			host, _, err := net.SplitHostPort(remoteAddr.String())
			if err != nil {
				trackingIP = remoteAddr.String()
			} else {
				trackingIP = host
			}
		}
	}

	// Increment total counter
	total := cl.currentTotal.Add(1)

	var perIP int64 = 0
	var ipCounter *atomic.Int64

	// Only track per-IP if limits are enabled (maxPerIP > 0) and not from trusted network
	if cl.maxPerIP > 0 && !isTrusted {
		// Increment per-IP counter using lock-free LoadOrStore
		value, _ := cl.perIPConnections.LoadOrStore(trackingIP, &atomic.Int64{})
		ipCounter = value.(*atomic.Int64)
		perIP = ipCounter.Add(1)

		if realClientIP != "" {
			logger.Debug("Connection limiter: Connection accepted", "protocol", cl.protocol, "remote", GetAddrString(remoteAddr), "real_client", realClientIP, "total", total, "max_total", cl.maxConnections, "per_ip", perIP, "max_per_ip", cl.maxPerIP)
		} else {
			logger.Debug("Connection limiter: Connection accepted", "protocol", cl.protocol, "ip", trackingIP, "total", total, "max_total", cl.maxConnections, "per_ip", perIP, "max_per_ip", cl.maxPerIP)
		}
	} else if isTrusted {
		proxyIPStr := GetAddrString(remoteAddr)
		if realClientIP != "" {
			logger.Debug("Connection limiter: Connection accepted from trusted proxy", "protocol", cl.protocol, "proxy", proxyIPStr, "real_client", realClientIP, "total", total, "max_total", cl.maxConnections)
		} else {
			logger.Debug("Connection limiter: Connection accepted from trusted network", "protocol", cl.protocol, "ip", proxyIPStr, "total", total, "max_total", cl.maxConnections)
		}
	} else {
		logger.Debug("Connection limiter: Connection accepted - unlimited", "protocol", cl.protocol, "ip", trackingIP, "total", total, "max_total", cl.maxConnections)
	}

	// Return cleanup function
	return func() {
		cl.currentTotal.Add(-1)

		if cl.maxPerIP > 0 && !isTrusted && ipCounter != nil {
			remaining := ipCounter.Add(-1)

			// Clean up IP entry if no connections remain (lazy cleanup)
			if remaining <= 0 {
				// Use sync.Map's CompareAndDelete for lock-free cleanup
				if ipCounter.Load() <= 0 {
					cl.perIPConnections.CompareAndDelete(trackingIP, ipCounter)
				}
			}

			if realClientIP != "" {
				logger.Debug("Connection limiter: Connection released", "protocol", cl.protocol, "remote", GetAddrString(remoteAddr), "real_client", realClientIP, "total", cl.currentTotal.Load(), "per_ip", remaining)
			} else {
				logger.Debug("Connection limiter: Connection released", "protocol", cl.protocol, "ip", trackingIP, "total", cl.currentTotal.Load(), "per_ip", remaining)
			}
		} else {
			if realClientIP != "" {
				logger.Debug("Connection limiter: Connection released - unlimited", "protocol", cl.protocol, "remote", GetAddrString(remoteAddr), "real_client", realClientIP, "total", cl.currentTotal.Load())
			} else {
				logger.Debug("Connection limiter: Connection released - unlimited", "protocol", cl.protocol, "ip", trackingIP, "total", cl.currentTotal.Load())
			}
		}
	}, nil
}

// CanAcceptWithRealIP checks if a new connection can be accepted with PROXY protocol support
func (cl *ConnectionLimiter) CanAcceptWithRealIP(remoteAddr net.Addr, realClientIP string) error {
	if cl.maxConnections <= 0 && cl.maxPerIP <= 0 {
		return nil // No limits configured
	}

	// Check total connection limit
	if cl.maxConnections > 0 {
		current := cl.currentTotal.Load()
		if current >= int64(cl.maxConnections) {
			if realClientIP != "" {
				logger.Info("Connection limiter: Maximum total connections reached", "protocol", cl.protocol, "current", current, "max", cl.maxConnections, "proxy_addr", GetAddrString(remoteAddr), "real_client", realClientIP)
			} else {
				logger.Info("Connection limiter: Maximum total connections reached", "protocol", cl.protocol, "current", current, "max", cl.maxConnections, "remote_addr", GetAddrString(remoteAddr))
			}
			return fmt.Errorf("maximum connections reached (%d/%d)", current, cl.maxConnections)
		}
	}

	// Check per-IP connection limit (skip if maxPerIP is 0, allowing unlimited per-IP for proxy scenarios)
	// Also skip per-IP limits for trusted networks (proxies)
	if cl.maxPerIP > 0 && !cl.isTrustedConnection(remoteAddr) {
		// Determine which IP to check for per-IP limits
		var checkIP string
		if realClientIP != "" {
			// Use real client IP for per-IP limiting when available
			checkIP = realClientIP
		} else {
			// Extract IP from remote address without triggering reverse DNS lookup
			var extractedIP net.IP
			switch addr := remoteAddr.(type) {
			case *net.TCPAddr:
				extractedIP = addr.IP
			case *net.UDPAddr:
				extractedIP = addr.IP
			default:
				// For unknown types, we must call String() but this may be slow
				// if it triggers reverse DNS lookup
				host, _, err := net.SplitHostPort(remoteAddr.String())
				if err == nil {
					extractedIP = net.ParseIP(host)
				}
			}

			if extractedIP != nil {
				checkIP = extractedIP.String()
			} else {
				// Fallback - this may be slow if it triggers DNS
				checkIP = remoteAddr.String()
			}
		}

		if value, exists := cl.perIPConnections.Load(checkIP); exists {
			ipCounter := value.(*atomic.Int64)
			current := ipCounter.Load()
			if current >= int64(cl.maxPerIP) {
				return fmt.Errorf("maximum connections per IP reached for %s (%d/%d)", checkIP, current, cl.maxPerIP)
			}
		}
	}

	return nil
}

// GetStats returns current connection statistics
func (cl *ConnectionLimiter) GetStats() ConnectionStats {
	stats := ConnectionStats{
		Protocol:         cl.protocol,
		TotalConnections: cl.currentTotal.Load(),
		MaxConnections:   int64(cl.maxConnections),
		MaxPerIP:         int64(cl.maxPerIP),
		IPConnections:    make(map[string]int64),
	}

	cl.perIPConnections.Range(func(key, value interface{}) bool {
		ip := key.(string)
		counter := value.(*atomic.Int64)
		stats.IPConnections[ip] = counter.Load()
		return true
	})

	return stats
}

// StartCleanup starts a background goroutine to clean up stale IP entries
func (cl *ConnectionLimiter) StartCleanup(ctx context.Context) {
	if cl.cleanupInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(cl.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cl.cleanup()
			}
		}
	}()
}

// cleanup removes IP entries with zero connections
func (cl *ConnectionLimiter) cleanup() {
	cleaned := 0
	cl.perIPConnections.Range(func(key, value interface{}) bool {
		ip := key.(string)
		counter := value.(*atomic.Int64)
		if counter.Load() <= 0 {
			cl.perIPConnections.Delete(ip)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		logger.Debug("Connection limiter: Cleaned up stale IP entries", "protocol", cl.protocol, "count", cleaned)
	}
}

// ConnectionStats represents connection statistics
type ConnectionStats struct {
	Protocol         string
	TotalConnections int64
	MaxConnections   int64
	MaxPerIP         int64
	IPConnections    map[string]int64
}
