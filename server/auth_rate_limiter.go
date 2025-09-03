package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
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

// AuthRateLimiterConfig holds authentication rate limiting configuration
type AuthRateLimiterConfig struct {
	Enabled                bool          `toml:"enabled"`                   // Enable/disable rate limiting
	MaxAttemptsPerIP       int           `toml:"max_attempts_per_ip"`       // Max failed attempts per IP before DB-based block
	MaxAttemptsPerUsername int           `toml:"max_attempts_per_username"` // Max failed attempts per username before DB-based block
	IPWindowDuration       time.Duration `toml:"ip_window_duration"`        // Time window for IP-based limiting
	UsernameWindowDuration time.Duration `toml:"username_window_duration"`  // Time window for username-based limiting
	CleanupInterval        time.Duration `toml:"cleanup_interval"`          // How often to clean up old DB entries

	// Enhanced Features (for EnhancedAuthRateLimiter)
	FastBlockThreshold   int           `toml:"fast_block_threshold"`   // Failed attempts before in-memory fast block
	FastBlockDuration    time.Duration `toml:"fast_block_duration"`    // How long to fast block an IP in-memory
	DelayStartThreshold  int           `toml:"delay_start_threshold"`  // Failed attempts before progressive delays start
	InitialDelay         time.Duration `toml:"initial_delay"`          // First delay duration
	MaxDelay             time.Duration `toml:"max_delay"`              // Maximum delay duration
	DelayMultiplier      float64       `toml:"delay_multiplier"`       // Delay increase factor
	CacheCleanupInterval time.Duration `toml:"cache_cleanup_interval"` // How often to clean in-memory cache
	DBSyncInterval       time.Duration `toml:"db_sync_interval"`       // How often to sync attempt batches to database
	MaxPendingBatch      int           `toml:"max_pending_batch"`      // Max records before a forced batch sync
	DBErrorThreshold     time.Duration `toml:"db_error_threshold"`     // Wait time before retrying DB after an error
}

// DefaultAuthRateLimiterConfig returns sensible defaults
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		MaxAttemptsPerIP:       10,               // 10 failed attempts per IP
		MaxAttemptsPerUsername: 5,                // 5 failed attempts per username
		IPWindowDuration:       15 * time.Minute, // 15 minute window for IP
		UsernameWindowDuration: 30 * time.Minute, // 30 minute window for username
		CleanupInterval:        5 * time.Minute,  // Clean up every 5 minutes
		Enabled:                false,            // Disabled by default

		// Enhanced Defaults
		FastBlockThreshold:   10,               // Block IP after 10 failures
		FastBlockDuration:    5 * time.Minute,  // Block for 5 minutes
		DelayStartThreshold:  2,                // Start delays after 2 failures
		InitialDelay:         2 * time.Second,  // 2 second initial delay
		MaxDelay:             30 * time.Second, // Max 30 second delay
		DelayMultiplier:      2.0,              // Double delay each time
		CacheCleanupInterval: 1 * time.Minute,  // Clean cache every minute
		DBSyncInterval:       30 * time.Second, // Sync to DB every 30 seconds
		MaxPendingBatch:      100,              // Batch up to 100 records
		DBErrorThreshold:     1 * time.Minute,  // Wait 1 minute after DB error
	}
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
	RecordAuthAttempt(ctx context.Context, ipAddress, username, protocol string, success bool) error
	GetFailedAttemptsCountSeparateWindows(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error)
	CleanupOldAuthAttempts(ctx context.Context, maxAge time.Duration) (int64, error)
	GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error)
}

// AuthLimiter interface that both AuthRateLimiter and EnhancedAuthRateLimiter implement
type AuthLimiter interface {
	CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error
	RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool)
	GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{}
	Stop()
}

// AuthRateLimiter provides fast IP blocking and progressive delays
type AuthRateLimiter struct {
	config   AuthRateLimiterConfig
	db       AuthDatabase
	protocol string

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
func NewAuthRateLimiter(protocol string, config AuthRateLimiterConfig, database AuthDatabase) *AuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &AuthRateLimiter{
		config:           config,
		db:               database,
		protocol:         protocol,
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

	log.Printf("[%s-AUTH-LIMITER] Initialized: fast_block=%d/%v, delay_after=%d, max_delay=%v",
		protocol, config.FastBlockThreshold, config.FastBlockDuration,
		config.DelayStartThreshold, config.MaxDelay)

	return limiter
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

	// Regular rate limiting check (database if healthy, otherwise allow)
	if a.shouldCheckDatabase() {
		ipCount, usernameCount, err := a.db.GetFailedAttemptsCountSeparateWindows(
			ctx, ip, username, a.config.IPWindowDuration, a.config.UsernameWindowDuration)

		if err != nil {
			a.markDBUnhealthy()
			log.Printf("[%s-AUTH-LIMITER] Warning: database check failed, using cache-only: %v", a.protocol, err)
		} else {
			if a.config.MaxAttemptsPerIP > 0 && ipCount >= a.config.MaxAttemptsPerIP {
				return fmt.Errorf("too many failed authentication attempts from IP %s (%d/%d in %v)",
					ip, ipCount, a.config.MaxAttemptsPerIP, a.config.IPWindowDuration)
			}

			if a.config.MaxAttemptsPerUsername > 0 && username != "" && usernameCount >= a.config.MaxAttemptsPerUsername {
				return fmt.Errorf("too many failed authentication attempts for user %s (%d/%d in %v)",
					username, usernameCount, a.config.MaxAttemptsPerUsername, a.config.UsernameWindowDuration)
			}
		}
	}

	return nil
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
		log.Printf("[%s-AUTH-LIMITER] Failed authentication attempt from %s for user '%s'", a.protocol, ip, username)
	} else {
		a.clearFailureTracking(ip)
		log.Printf("[%s-AUTH-LIMITER] Successful authentication from %s for user '%s'", a.protocol, ip, username)
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
		a.blockMu.Lock()
		a.blockedIPs[ip] = &BlockedIPInfo{
			BlockedUntil: failureTime.Add(a.config.FastBlockDuration),
			FailureCount: info.FailureCount,
			FirstFailure: info.FirstFailure,
			LastFailure:  failureTime,
			Protocol:     a.protocol,
		}
		a.blockMu.Unlock()
		log.Printf("[%s-AUTH-LIMITER] FAST BLOCKED IP %s after %d failures (blocked until %v)",
			a.protocol, ip, info.FailureCount, failureTime.Add(a.config.FastBlockDuration).Format("15:04:05"))
	} else if info.FailureCount >= a.config.DelayStartThreshold {
		log.Printf("[%s-AUTH-LIMITER] Progressive delay for IP %s: %v (failure %d)",
			a.protocol, ip, info.LastDelay, info.FailureCount)
	}
}

func (a *AuthRateLimiter) clearFailureTracking(ip string) {
	a.delayMu.Lock()
	delete(a.ipFailureCounts, ip)
	a.delayMu.Unlock()
	a.blockMu.Lock()
	delete(a.blockedIPs, ip)
	a.blockMu.Unlock()
	log.Printf("[%s-AUTH-LIMITER] Cleared failure tracking for IP %s after successful login", a.protocol, ip)
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
		if err := a.db.RecordAuthAttempt(ctx, record.IP, record.Username, a.protocol, record.Success); err != nil {
			log.Printf("[%s-AUTH-LIMITER] Warning: failed to sync auth attempt: %v", a.protocol, err)
			a.markDBUnhealthy()
			// Re-queue failed records
			a.pendingMu.Lock()
			a.pendingRecords = append(records[i:], a.pendingRecords...)
			a.pendingMu.Unlock()
			return
		}
	}
	log.Printf("[%s-AUTH-LIMITER] Synced %d auth attempts to database", a.protocol, len(records))
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
		log.Printf("[%s-AUTH-LIMITER] Cleaned up %d expired blocks and %d old failure records",
			a.protocol, expiredBlocks, expiredFailures)
	}
}

func (a *AuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{} {
	if a == nil {
		return map[string]interface{}{"enabled": false}
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

	stats := map[string]interface{}{
		"enabled":      true,
		"blocked_ips":  blockedCount,
		"tracked_ips":  trackedIPs,
		"pending_sync": pendingCount,
		"db_healthy":   a.dbHealthy,
		"config": map[string]interface{}{
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
