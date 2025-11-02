package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
)

// StringAddr implements net.Addr interface for string addresses
type StringAddr struct {
	Addr string
}

func (s *StringAddr) String() string {
	return s.Addr
}

func (s *StringAddr) Network() string {
	return "tcp"
}

// AuthRateLimiterConfig is an alias for config.AuthRateLimiterConfig for compatibility
type AuthRateLimiterConfig = config.AuthRateLimiterConfig

// DefaultAuthRateLimiterConfig returns sensible defaults for authentication rate limiting
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return config.DefaultAuthRateLimiterConfig()
}

// AuthAttempt represents a single authentication attempt
type AuthAttempt struct {
	Timestamp time.Time
	Success   bool
	IP        string
	Username  string
}

// AuthDatabase interface for rate limiting database operations
type AuthDatabase interface {
	RecordAuthAttemptWithRetry(ctx context.Context, ipAddress, username, protocol string, success bool) error
	GetFailedAttemptsCountSeparateWindowsWithRetry(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error)
	CleanupOldAuthAttemptsWithRetry(ctx context.Context, maxAge time.Duration) (int64, error)
	GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]any, error)
}

// AuthLimiter interface that both AuthRateLimiter and EnhancedAuthRateLimiter implement
type AuthLimiter interface {
	CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error
	RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool)
	// New methods with proxy awareness
	CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string) error
	RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string, success bool)
	GetStats(ctx context.Context, windowDuration time.Duration) map[string]any
	Stop()
}

// AuthRateLimiter provides fast IP blocking and progressive delays
type AuthRateLimiter struct {
	config   AuthRateLimiterConfig
	db       AuthDatabase
	protocol string

	// Trusted networks for exemption
	trustedNetworks []string

	// Fast IP blocking cache
	blockedIPs map[string]*BlockedIPInfo
	blockMu    sync.RWMutex

	// Progressive delay tracking
	ipFailureCounts map[string]*IPFailureInfo
	delayMu         sync.RWMutex

	// Database sync for persistence
	pendingRecords []AuthAttempt
	pendingMu      sync.Mutex
	dbSyncInterval time.Duration

	// Circuit breaker for database protection
	dbHealthy        bool
	lastDBError      time.Time
	dbErrorThreshold time.Duration

	// Cluster integration (optional)
	clusterLimiter *ClusterRateLimiter

	stopCleanup chan struct{}
	stopSync    chan struct{}
}

// BlockedIPInfo tracks IPs that are temporarily blocked
type BlockedIPInfo struct {
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
	Protocol     string
}

// IPFailureInfo tracks failure counts and delays for progressive delays
type IPFailureInfo struct {
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
	LastDelay    time.Duration
}

// NewAuthRateLimiter creates a new authentication rate limiter.
func NewAuthRateLimiter(protocol string, config AuthRateLimiterConfig, rdb AuthDatabase) *AuthRateLimiter {
	return NewAuthRateLimiterWithTrustedNetworks(protocol, config, rdb, nil)
}

// NewAuthRateLimiterWithTrustedNetworks creates a new authentication rate limiter with trusted networks exemption.
func NewAuthRateLimiterWithTrustedNetworks(protocol string, config AuthRateLimiterConfig, rdb AuthDatabase, trustedNetworks []string) *AuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &AuthRateLimiter{
		config:           config,
		db:               rdb,
		protocol:         protocol,
		trustedNetworks:  trustedNetworks,
		blockedIPs:       make(map[string]*BlockedIPInfo),
		ipFailureCounts:  make(map[string]*IPFailureInfo),
		pendingRecords:   make([]AuthAttempt, 0, config.MaxPendingBatch),
		dbSyncInterval:   config.DBSyncInterval,
		dbHealthy:        true,
		dbErrorThreshold: config.DBErrorThreshold,
		stopCleanup:      make(chan struct{}),
		stopSync:         make(chan struct{}),
	}

	// Start background routines
	go limiter.cleanupRoutine(config.CacheCleanupInterval)
	go limiter.syncRoutine()

	logger.Debug("Auth limiter: Initialized", "protocol", protocol, "fast_block_threshold", config.FastBlockThreshold, "fast_block_duration", config.FastBlockDuration, "delay_start_threshold", config.DelayStartThreshold, "max_delay", config.MaxDelay)

	return limiter
}

// SetClusterLimiter sets the cluster rate limiter for cluster-wide synchronization
func (a *AuthRateLimiter) SetClusterLimiter(clusterLimiter *ClusterRateLimiter) {
	if a == nil {
		return
	}
	a.clusterLimiter = clusterLimiter
}

// CanAttemptAuth checks if authentication can be attempted with fast blocking
func (a *AuthRateLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
	if a == nil {
		return nil
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// FAST PATH: Check if IP is currently blocked in cache
	a.blockMu.RLock()
	if blocked, exists := a.blockedIPs[ip]; exists {
		if time.Now().Before(blocked.BlockedUntil) {
			a.blockMu.RUnlock()
			return fmt.Errorf("IP %s is temporarily blocked until %v (failed %d times)",
				ip, blocked.BlockedUntil.Format("15:04:05"), blocked.FailureCount)
		}
		// Block has expired, remove it
		delete(a.blockedIPs, ip)
	}
	a.blockMu.RUnlock()

	// Regular rate limiting check (database if healthy, otherwise deny)
	if a.shouldCheckDatabase() {
		ipCount, usernameCount, err := a.db.GetFailedAttemptsCountSeparateWindowsWithRetry(
			ctx, ip, username, a.config.IPWindowDuration, a.config.UsernameWindowDuration)

		if err != nil {
			a.markDBUnhealthy()
			logger.Debug("Auth limiter: CRITICAL - database check failed, denying auth for security", "protocol", a.protocol, "error", err)
			// Fail closed - deny authentication when database is unavailable
			// This prevents attackers from bypassing rate limiting by causing DB errors
			return fmt.Errorf("authentication rate limiting unavailable, access temporarily denied for security")
		}

		if a.config.MaxAttemptsPerIP > 0 && ipCount >= a.config.MaxAttemptsPerIP {
			return fmt.Errorf("too many failed authentication attempts from IP %s (%d/%d in %v)",
				ip, ipCount, a.config.MaxAttemptsPerIP, a.config.IPWindowDuration)
		}

		if a.config.MaxAttemptsPerUsername > 0 && username != "" && usernameCount >= a.config.MaxAttemptsPerUsername {
			return fmt.Errorf("too many failed authentication attempts for user %s (%d/%d in %v)",
				username, usernameCount, a.config.MaxAttemptsPerUsername, a.config.UsernameWindowDuration)
		}
	}

	return nil
}

// CanAttemptAuthWithProxy checks if authentication can be attempted with proper proxy IP detection
func (a *AuthRateLimiter) CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string) error {
	if a == nil {
		return nil
	}

	// Extract real client IP and proxy IP
	clientIP, proxyIP := GetConnectionIPs(conn, proxyInfo)

	// Check if the real client IP is from a trusted network
	if a.isFromTrustedNetwork(clientIP) {
		if proxyIP != "" {
			logger.Debug("Auth limiter: Skipping rate limiting for trusted client", "protocol", a.protocol, "client", clientIP, "proxy", proxyIP)
		} else {
			logger.Debug("Auth limiter: Skipping rate limiting for trusted client", "protocol", a.protocol, "client", clientIP)
		}
		return nil
	}

	// Use the real client IP for rate limiting
	clientAddr := &StringAddr{Addr: clientIP}
	return a.CanAttemptAuth(ctx, clientAddr, username)
}

// RecordAuthAttemptWithProxy records an authentication attempt with proper proxy IP detection
func (a *AuthRateLimiter) RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string, success bool) {
	if a == nil {
		return
	}

	// Extract real client IP and proxy IP
	clientIP, proxyIP := GetConnectionIPs(conn, proxyInfo)

	// Check if the real client IP is from a trusted network
	if a.isFromTrustedNetwork(clientIP) {
		if proxyIP != "" {
			logger.Debug("Auth limiter: Skipping rate limiting recording for trusted client", "protocol", a.protocol, "client", clientIP, "proxy", proxyIP)
		} else {
			logger.Debug("Auth limiter: Skipping rate limiting recording for trusted client", "protocol", a.protocol, "client", clientIP)
		}
		return
	}

	// Use the real client IP for rate limiting
	clientAddr := &StringAddr{Addr: clientIP}
	a.RecordAuthAttempt(ctx, clientAddr, username, success)
}

// isFromTrustedNetwork checks if an IP address is in the trusted networks
func (a *AuthRateLimiter) isFromTrustedNetwork(ipStr string) bool {
	if len(a.trustedNetworks) == 0 {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check against trusted networks
	for _, cidr := range a.trustedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// RecordAuthAttempt records an authentication attempt with fast blocking and delays
func (a *AuthRateLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
	if a == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	now := time.Now()
	attempt := AuthAttempt{Timestamp: now, Success: success, IP: ip, Username: username}
	a.queueForDBSync(attempt)

	if !success {
		a.updateFailureTracking(ip, now)
		logger.Debug("Auth limiter: Failed authentication attempt", "protocol", a.protocol, "ip", ip, "user", username)
	} else {
		a.clearFailureTracking(ip)
		logger.Debug("Auth limiter: Successful authentication", "protocol", a.protocol, "ip", ip, "user", username)
	}
}

// GetAuthenticationDelay returns delay duration for progressive delays
func (a *AuthRateLimiter) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	if a == nil {
		return 0
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	a.delayMu.RLock()
	defer a.delayMu.RUnlock()

	if info, exists := a.ipFailureCounts[ip]; exists && info.FailureCount >= a.config.DelayStartThreshold {
		return info.LastDelay
	}

	return 0
}

func (a *AuthRateLimiter) updateFailureTracking(ip string, failureTime time.Time) {
	a.delayMu.Lock()
	defer a.delayMu.Unlock()

	info, exists := a.ipFailureCounts[ip]
	if !exists {
		info = &IPFailureInfo{FirstFailure: failureTime, LastDelay: 0}
		a.ipFailureCounts[ip] = info
	}

	info.FailureCount++
	info.LastFailure = failureTime

	if info.FailureCount >= a.config.DelayStartThreshold {
		if info.LastDelay == 0 {
			info.LastDelay = a.config.InitialDelay
		} else {
			info.LastDelay = time.Duration(float64(info.LastDelay) * a.config.DelayMultiplier)
			if info.LastDelay > a.config.MaxDelay {
				info.LastDelay = a.config.MaxDelay
			}
		}
	}

	if info.FailureCount >= a.config.FastBlockThreshold {
		blockedUntil := failureTime.Add(a.config.FastBlockDuration)
		a.blockMu.Lock()
		a.blockedIPs[ip] = &BlockedIPInfo{
			BlockedUntil: blockedUntil,
			FailureCount: info.FailureCount,
			FirstFailure: info.FirstFailure,
			LastFailure:  failureTime,
			Protocol:     a.protocol,
		}
		a.blockMu.Unlock()
		logger.Debug("Auth limiter: FAST BLOCKED IP", "protocol", a.protocol, "ip", ip, "failures", info.FailureCount, "blocked_until", blockedUntil.Format("15:04:05"))

		// Broadcast to cluster
		if a.clusterLimiter != nil {
			a.clusterLimiter.BroadcastBlockIP(ip, blockedUntil, info.FailureCount, a.protocol, info.FirstFailure)
		}
	} else if info.FailureCount >= a.config.DelayStartThreshold {
		logger.Debug("Auth limiter: Progressive delay for IP", "protocol", a.protocol, "ip", ip, "delay", info.LastDelay, "failures", info.FailureCount)

		// Broadcast failure count to cluster for progressive delays
		if a.clusterLimiter != nil {
			a.clusterLimiter.BroadcastFailureCount(ip, info.FailureCount, info.LastDelay, info.FirstFailure)
		}
	}
}

func (a *AuthRateLimiter) clearFailureTracking(ip string) {
	a.delayMu.Lock()
	delete(a.ipFailureCounts, ip)
	a.delayMu.Unlock()
	a.blockMu.Lock()
	delete(a.blockedIPs, ip)
	a.blockMu.Unlock()
	logger.Debug("Auth limiter: Cleared failure tracking after successful login", "protocol", a.protocol, "ip", ip)
}

func (a *AuthRateLimiter) queueForDBSync(attempt AuthAttempt) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	a.pendingRecords = append(a.pendingRecords, attempt)
	if len(a.pendingRecords) >= a.config.MaxPendingBatch {
		go a.syncPendingRecords()
	}
}

func (a *AuthRateLimiter) shouldCheckDatabase() bool {
	if !a.dbHealthy {
		if time.Since(a.lastDBError) < a.config.DBErrorThreshold {
			return false
		}
		a.dbHealthy = true
	}
	return true
}

func (a *AuthRateLimiter) markDBUnhealthy() {
	a.dbHealthy = false
	a.lastDBError = time.Now()
}

func (a *AuthRateLimiter) syncRoutine() {
	ticker := time.NewTicker(a.dbSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.syncPendingRecords()
		case <-a.stopSync:
			a.syncPendingRecords()
			return
		}
	}
}

func (a *AuthRateLimiter) syncPendingRecords() {
	a.pendingMu.Lock()
	if len(a.pendingRecords) == 0 {
		a.pendingMu.Unlock()
		return
	}
	records := make([]AuthAttempt, len(a.pendingRecords))
	copy(records, a.pendingRecords)
	a.pendingRecords = a.pendingRecords[:0]
	a.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i, record := range records {
		if err := a.db.RecordAuthAttemptWithRetry(ctx, record.IP, record.Username, a.protocol, record.Success); err != nil {
			logger.Debug("Auth limiter: Warning - failed to sync auth attempt", "protocol", a.protocol, "error", err)
			a.markDBUnhealthy()
			// Re-queue failed records
			a.pendingMu.Lock()
			a.pendingRecords = append(records[i:], a.pendingRecords...)
			a.pendingMu.Unlock()
			return
		}
	}
	logger.Debug("Auth limiter: Synced auth attempts to database", "protocol", a.protocol, "count", len(records))
}

func (a *AuthRateLimiter) cleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cleanupExpiredEntries()
		case <-a.stopCleanup:
			return
		}
	}
}

func (a *AuthRateLimiter) cleanupExpiredEntries() {
	now := time.Now()
	a.blockMu.Lock()
	expiredBlocks := 0
	for ip, blocked := range a.blockedIPs {
		if now.After(blocked.BlockedUntil) {
			delete(a.blockedIPs, ip)
			expiredBlocks++
		}
	}
	a.blockMu.Unlock()

	a.delayMu.Lock()
	expiredFailures := 0
	cutoff := now.Add(-a.config.IPWindowDuration)
	for ip, info := range a.ipFailureCounts {
		if info.LastFailure.Before(cutoff) {
			delete(a.ipFailureCounts, ip)
			expiredFailures++
		}
	}
	a.delayMu.Unlock()

	if expiredBlocks > 0 || expiredFailures > 0 {
		logger.Debug("Auth limiter: Cleaned up expired blocks and old failure records", "protocol", a.protocol, "expired_blocks", expiredBlocks, "expired_failures", expiredFailures)
	}
}

func (a *AuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]any {
	if a == nil {
		return map[string]any{"enabled": false}
	}
	a.blockMu.RLock()
	blockedCount := len(a.blockedIPs)
	a.blockMu.RUnlock()
	a.delayMu.RLock()
	trackedIPs := len(a.ipFailureCounts)
	a.delayMu.RUnlock()
	a.pendingMu.Lock()
	pendingCount := len(a.pendingRecords)
	a.pendingMu.Unlock()

	stats := map[string]any{
		"enabled":      true,
		"blocked_ips":  blockedCount,
		"tracked_ips":  trackedIPs,
		"pending_sync": pendingCount,
		"db_healthy":   a.dbHealthy,
		"config": map[string]any{
			"max_attempts_per_ip":       a.config.MaxAttemptsPerIP,
			"max_attempts_per_username": a.config.MaxAttemptsPerUsername,
			"ip_window_duration":        a.config.IPWindowDuration.String(),
			"username_window_duration":  a.config.UsernameWindowDuration.String(),
		},
	}

	if a.shouldCheckDatabase() {
		dbStats, err := a.db.GetAuthAttemptsStats(ctx, windowDuration)
		if err != nil {
			stats["db_stats_error"] = err.Error()
			a.markDBUnhealthy()
		} else {
			stats["database"] = dbStats
		}
	}
	return stats
}

func (a *AuthRateLimiter) Stop() {
	if a == nil {
		return
	}
	close(a.stopCleanup)
	close(a.stopSync)
}
