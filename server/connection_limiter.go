package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// ErrMaxConnectionsPerIP is a refusal over max_connections_per_ip: one client has too
// many connections, as opposed to the server being full (max_connections).
var ErrMaxConnectionsPerIP = errors.New("maximum connections per IP reached")

// IsProxiedClientRefusal reports whether err, a ConnectionLimiter refusal, refused the
// client a PROXY header named over that client's own max_connections_per_ip. Such a
// refusal is answered with a protocol reply after the TLS handshake instead of a silent
// close: the PROXY peer is a proxy or load balancer (the header is only read from a
// trusted peer), and a sora proxy that sees the socket close before its TLS handshake
// counts a backend failure, quarantining the backend for every user over one client.
// Every other refusal stays a silent close, so a flooder connecting directly is told
// nothing.
func IsProxiedClientRefusal(err error, proxyInfo *ProxyProtocolInfo) bool {
	return proxyInfo != nil && proxyInfo.SrcIP != "" && errors.Is(err, ErrMaxConnectionsPerIP)
}

// ConnectionLimiter manages connection limits for protocol servers
type ConnectionLimiter struct {
	maxConnections   int
	maxPerIP         int
	currentTotal     atomic.Int64
	perIPConnections sync.Map // map[string]*atomic.Int64 - lock-free for better concurrency (local only)
	cleanupInterval  time.Duration
	protocol         string
	trustedNets      []*net.IPNet    // Trusted networks that bypass per-IP limits
	ipTracker        *IPLimitTracker // Cluster-wide per-IP tracking (nil if cluster disabled)
	instanceID       string          // Unique instance identifier for cluster mode
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
	trustedNets, err := helpers.ParseTrustedNetworks(trustedProxies)
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
		ipTracker:       nil, // No cluster tracking
		instanceID:      "",
	}
}

// NewConnectionLimiterWithCluster creates a new connection limiter with cluster-wide per-IP tracking
func NewConnectionLimiterWithCluster(protocol string, instanceID string, clusterMgr *cluster.Manager, maxConnections, maxPerIP int, trustedProxies []string) *ConnectionLimiter {
	trustedNets, err := helpers.ParseTrustedNetworks(trustedProxies)
	if err != nil {
		logger.Debug("Connection limiter: WARNING - failed to parse trusted networks", "protocol", protocol, "error", err)
		trustedNets = []*net.IPNet{}
	}

	var ipTracker *IPLimitTracker
	if clusterMgr != nil && maxPerIP > 0 {
		// Create IP tracker with cluster support
		ipTracker = NewIPLimitTracker(protocol, instanceID, clusterMgr, defaultMaxIPEventQueueSize)
		logger.Info("Connection limiter: Cluster-wide per-IP limiting enabled", "protocol", protocol, "max_per_ip", maxPerIP)
	}

	return &ConnectionLimiter{
		maxConnections:  maxConnections,
		maxPerIP:        maxPerIP,
		cleanupInterval: 5 * time.Minute, // Clean up stale IP entries
		protocol:        protocol,
		trustedNets:     trustedNets,
		ipTracker:       ipTracker,
		instanceID:      instanceID,
	}
}

// IsTrustedConnection checks if connection is from trusted network (public method)
func (cl *ConnectionLimiter) IsTrustedConnection(remoteAddr net.Addr) bool {
	return cl.isTrustedConnection(remoteAddr)
}

// isTrustedConnection checks if connection is from trusted network (internal method)
func (cl *ConnectionLimiter) isTrustedConnection(remoteAddr net.Addr) bool {
	return cl.isTrustedIP(addrIP(remoteAddr))
}

// isTrustedIP reports whether ip is in trusted_networks.
func (cl *ConnectionLimiter) isTrustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range cl.trustedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// perIPAddr returns the address max_connections_per_ip counts for a connection
// and whether trusted_networks exempt it. The counted address is the client a
// PROXY header names (realClientIP) when there is one, else the socket peer, and
// the exemption is checked against that address, not against the peer: a trusted
// load balancer or proxy passes the limit on to the clients it names, and is only
// exempt itself when it names none (no header, PROXY LOCAL/UNKNOWN). The PROXY
// reader refuses headers from untrusted peers, so realClientIP is never an address
// an untrusted client chose.
func (cl *ConnectionLimiter) perIPAddr(remoteAddr net.Addr, realClientIP string) (string, bool) {
	if realClientIP == "" {
		if ip := addrIP(remoteAddr); ip != nil {
			return ip.String(), cl.isTrustedIP(ip)
		}
		return GetIPString(remoteAddr), false
	}
	// Canonical form, so one client spelled two ways is one key.
	if ip := net.ParseIP(realClientIP); ip != nil {
		return ip.String(), cl.isTrustedIP(ip)
	}
	return realClientIP, false
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
				logger.Info("Connection limiter: Maximum connections per IP reached", "protocol", cl.protocol, "ip", ip, "current", current, "max", cl.maxPerIP)
				return fmt.Errorf("%w for %s (%d/%d)", ErrMaxConnectionsPerIP, ip, current, cl.maxPerIP)
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

	trackingIP, exempt := cl.perIPAddr(remoteAddr, realClientIP)

	// Increment total counter, then re-check the limit. CanAcceptWithRealIP above is
	// only an advisory pre-check; without this post-increment guard two concurrent
	// accepts at (max-1) could both pass it and overshoot maxConnections.
	total := cl.currentTotal.Add(1)
	if cl.maxConnections > 0 && total > int64(cl.maxConnections) {
		cl.currentTotal.Add(-1)
		return nil, fmt.Errorf("maximum connections reached (%d/%d)", cl.maxConnections, cl.maxConnections)
	}

	// Log every 1000th accept to track connection rate
	if total%1000 == 0 {
		logger.Info("Connection limiter: Connections accepted", "protocol", cl.protocol, "current_total", total, "max", cl.maxConnections)
	}

	var perIP int64 = 0
	var ipCounter *atomic.Int64

	// Only track per-IP if limits are enabled (maxPerIP > 0) and the counted address is not trusted
	if cl.maxPerIP > 0 && !exempt {
		// Use cluster-wide tracking if available, otherwise use local tracking
		if cl.ipTracker != nil {
			// Cluster mode: increment cluster-wide counter
			cl.ipTracker.IncrementIP(trackingIP)
			perIP = int64(cl.ipTracker.GetIPCount(trackingIP))
		} else {
			// Local mode: increment local counter using lock-free LoadOrStore
			value, _ := cl.perIPConnections.LoadOrStore(trackingIP, &atomic.Int64{})
			ipCounter = value.(*atomic.Int64)
			perIP = ipCounter.Add(1)
		}

		// Post-increment per-IP guard, mirroring the total-counter guard above: close the
		// check/increment TOCTOU so concurrent accepts from one IP can't overshoot maxPerIP.
		if perIP > int64(cl.maxPerIP) {
			if cl.ipTracker != nil {
				cl.ipTracker.DecrementIP(trackingIP)
			} else if ipCounter != nil {
				ipCounter.Add(-1)
			}
			cl.currentTotal.Add(-1)
			return nil, fmt.Errorf("%w for %s (%d/%d)", ErrMaxConnectionsPerIP, trackingIP, cl.maxPerIP, cl.maxPerIP)
		}

		if realClientIP != "" {
			logger.Debug("Connection limiter: Connection accepted", "protocol", cl.protocol, "remote", GetAddrString(remoteAddr), "real_client", realClientIP, "total", total, "max_total", cl.maxConnections, "per_ip", perIP, "max_per_ip", cl.maxPerIP)
		} else {
			logger.Debug("Connection limiter: Connection accepted", "protocol", cl.protocol, "ip", trackingIP, "total", total, "max_total", cl.maxConnections, "per_ip", perIP, "max_per_ip", cl.maxPerIP)
		}
	} else if exempt {
		if realClientIP != "" {
			logger.Debug("Connection limiter: Connection accepted for client in trusted network", "protocol", cl.protocol, "remote", GetAddrString(remoteAddr), "real_client", realClientIP, "total", total, "max_total", cl.maxConnections)
		} else {
			logger.Debug("Connection limiter: Connection accepted from trusted network", "protocol", cl.protocol, "ip", GetAddrString(remoteAddr), "total", total, "max_total", cl.maxConnections)
		}
	} else {
		logger.Debug("Connection limiter: Connection accepted - unlimited", "protocol", cl.protocol, "ip", trackingIP, "total", total, "max_total", cl.maxConnections)
	}

	// Return cleanup function with sync.Once to prevent double-decrement
	// This can happen if both session.close() and panic recovery try to call releaseConn()
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			newTotal := cl.currentTotal.Add(-1)

			// Log every 1000th release to track if releases are happening
			if newTotal%1000 == 0 {
				logger.Info("Connection limiter: Connections released", "protocol", cl.protocol, "current_total", newTotal, "max", cl.maxConnections)
			}

			if cl.maxPerIP > 0 && !exempt {
				var remaining int64

				// Use cluster-wide tracking if available, otherwise use local tracking
				if cl.ipTracker != nil {
					// Cluster mode: decrement cluster-wide counter
					cl.ipTracker.DecrementIP(trackingIP)
					remaining = int64(cl.ipTracker.GetIPCount(trackingIP))
				} else if ipCounter != nil {
					// Local mode: decrement local counter
					remaining = ipCounter.Add(-1)

					// Clean up IP entry if no connections remain (lazy cleanup)
					if remaining <= 0 {
						// Double-check after a brief moment to avoid race with new connections
						// If a new connection arrives between Add(-1) and this check, we'll see count > 0
						if ipCounter.Load() <= 0 {
							// Final check: only delete if we can confirm the counter is still at the same address
							// and still has zero value. This prevents deleting an entry that was just incremented
							// by a racing new connection.
							if loaded, ok := cl.perIPConnections.Load(trackingIP); ok {
								if loadedCounter, ok := loaded.(*atomic.Int64); ok && loadedCounter == ipCounter && loadedCounter.Load() <= 0 {
									cl.perIPConnections.CompareAndDelete(trackingIP, ipCounter)
								}
							}
						}
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
		})
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
			return fmt.Errorf("maximum connections reached (%d/%d)", current, cl.maxConnections)
		}
	}

	// Check per-IP connection limit (skip if maxPerIP is 0, allowing unlimited per-IP for proxy scenarios)
	if cl.maxPerIP <= 0 {
		return nil
	}
	checkIP, exempt := cl.perIPAddr(remoteAddr, realClientIP)
	if !exempt {
		// Use cluster-wide count if tracker is available, otherwise use local count
		var current int64
		if cl.ipTracker != nil {
			// Cluster mode: check cluster-wide count
			current = int64(cl.ipTracker.GetIPCount(checkIP))
		} else {
			// Local mode: check local count
			if value, exists := cl.perIPConnections.Load(checkIP); exists {
				ipCounter := value.(*atomic.Int64)
				current = ipCounter.Load()
			}
		}

		if current >= int64(cl.maxPerIP) {
			return fmt.Errorf("%w for %s (%d/%d)", ErrMaxConnectionsPerIP, checkIP, current, cl.maxPerIP)
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

	// Get per-IP counts from cluster tracker if available, otherwise from local map
	if cl.ipTracker != nil {
		// Cluster mode: get cluster-wide IP counts from tracker
		cl.ipTracker.mu.RLock()
		for ip, info := range cl.ipTracker.connections {
			if info.TotalCount > 0 {
				stats.IPConnections[ip] = int64(info.TotalCount)
			}
		}
		cl.ipTracker.mu.RUnlock()
	} else {
		// Local mode: get local IP counts from map
		cl.perIPConnections.Range(func(key, value interface{}) bool {
			ip := key.(string)
			counter := value.(*atomic.Int64)
			stats.IPConnections[ip] = counter.Load()
			return true
		})
	}

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
