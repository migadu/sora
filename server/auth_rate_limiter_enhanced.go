package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// EnhancedAuthRateLimiter provides fast IP blocking and progressive delays
type EnhancedAuthRateLimiter struct {
	config           AuthRateLimiterConfig
	enhancedConfig   EnhancedAuthRateLimiterConfig
	db               AuthDatabase
	protocol         string
	
	// Fast IP blocking cache
	blockedIPs       map[string]*BlockedIPInfo
	blockMu          sync.RWMutex
	
	// Progressive delay tracking
	ipFailureCounts  map[string]*IPFailureInfo
	delayMu          sync.RWMutex
	
	// Database sync for persistence
	pendingRecords   []AuthAttempt
	pendingMu        sync.Mutex
	dbSyncInterval   time.Duration
	
	// Circuit breaker for database protection
	dbHealthy        bool
	lastDBError      time.Time
	dbErrorThreshold time.Duration
	
	stopCleanup      chan struct{}
	stopSync         chan struct{}
}

// BlockedIPInfo tracks IPs that are temporarily blocked
type BlockedIPInfo struct {
	BlockedUntil    time.Time
	FailureCount    int
	FirstFailure    time.Time
	LastFailure     time.Time
	Protocol        string
}

// IPFailureInfo tracks failure counts and delays for progressive delays
type IPFailureInfo struct {
	FailureCount    int
	FirstFailure    time.Time
	LastFailure     time.Time
	LastDelay       time.Duration
}

// EnhancedAuthRateLimiterConfig extends the basic config with enhanced features
type EnhancedAuthRateLimiterConfig struct {
	AuthRateLimiterConfig
	
	// Fast blocking settings
	FastBlockThreshold    int           `toml:"fast_block_threshold"`    // Failed attempts before fast block
	FastBlockDuration     time.Duration `toml:"fast_block_duration"`     // How long to fast block IP
	
	// Progressive delay settings  
	DelayStartThreshold   int           `toml:"delay_start_threshold"`   // Failed attempts before delays start
	InitialDelay          time.Duration `toml:"initial_delay"`           // First delay duration
	MaxDelay              time.Duration `toml:"max_delay"`               // Maximum delay duration
	DelayMultiplier       float64       `toml:"delay_multiplier"`        // Delay increase factor
	
	// Cache and sync settings
	CacheCleanupInterval  time.Duration `toml:"cache_cleanup_interval"`  // How often to clean cache
	DBSyncInterval        time.Duration `toml:"db_sync_interval"`        // How often to sync to database
	MaxPendingBatch       int           `toml:"max_pending_batch"`       // Max records before forced sync
	DBErrorThreshold      time.Duration `toml:"db_error_threshold"`      // Wait time before retrying DB
}

// DefaultEnhancedAuthRateLimiterConfig returns sensible defaults
func DefaultEnhancedAuthRateLimiterConfig() EnhancedAuthRateLimiterConfig {
	return EnhancedAuthRateLimiterConfig{
		AuthRateLimiterConfig: DefaultAuthRateLimiterConfig(),
		FastBlockThreshold:    10,               // Block IP after 10 failures (same as max_attempts_per_ip)
		FastBlockDuration:     5 * time.Minute,  // Block for 5 minutes
		DelayStartThreshold:   2,                // Start delays after 2 failures
		InitialDelay:          2 * time.Second,  // 2 second initial delay
		MaxDelay:              30 * time.Second, // Max 30 second delay
		DelayMultiplier:       2.0,              // Double delay each time
		CacheCleanupInterval:  1 * time.Minute,  // Clean cache every minute
		DBSyncInterval:        30 * time.Second, // Sync to DB every 30 seconds
		MaxPendingBatch:       100,              // Batch up to 100 records
		DBErrorThreshold:      1 * time.Minute,  // Wait 1 minute after DB error
	}
}

// NewEnhancedAuthRateLimiter creates a new enhanced authentication rate limiter
func NewEnhancedAuthRateLimiter(protocol string, config EnhancedAuthRateLimiterConfig, database AuthDatabase) *EnhancedAuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &EnhancedAuthRateLimiter{
		config:           config.AuthRateLimiterConfig,
		enhancedConfig:   config,
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

	log.Printf("[%s-AUTH-LIMITER] Enhanced limiter initialized: fast_block=%d/%v, delay_after=%d, max_delay=%v", 
		protocol, config.FastBlockThreshold, config.FastBlockDuration,
		config.DelayStartThreshold, config.MaxDelay)

	return limiter
}

// CanAttemptAuth checks if authentication can be attempted with fast blocking
func (a *EnhancedAuthRateLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
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
			// Continue with cache-only decision (fail-open)
		} else {
			// Database check succeeded, use database counts
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
func (a *EnhancedAuthRateLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
	if a == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	now := time.Now()
	attempt := AuthAttempt{
		Timestamp: now,
		Success:   success,
		IP:        ip,
		Username:  username,
	}

	// Always queue for database sync
	a.queueForDBSync(attempt)

	if !success {
		// Update failure tracking and check for fast blocking
		a.updateFailureTracking(ip, now)
		
		log.Printf("[%s-AUTH-LIMITER] Failed authentication attempt from %s for user '%s'", 
			a.protocol, ip, username)
	} else {
		// Successful login - clear the IP from failure tracking
		a.clearFailureTracking(ip)
		log.Printf("[%s-AUTH-LIMITER] Successful authentication from %s for user '%s'", 
			a.protocol, ip, username)
	}
}

// GetAuthenticationDelay returns delay duration for progressive delays
func (a *EnhancedAuthRateLimiter) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	if a == nil {
		return 0
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	a.delayMu.RLock()
	defer a.delayMu.RUnlock()

	if info, exists := a.ipFailureCounts[ip]; exists {
		// Apply delay if we have enough failures
		config := a.getEnhancedConfig()
		if info.FailureCount >= config.DelayStartThreshold {
			return info.LastDelay
		}
	}

	return 0
}

// updateFailureTracking updates failure counts and manages fast blocking
func (a *EnhancedAuthRateLimiter) updateFailureTracking(ip string, failureTime time.Time) {
	config := a.getEnhancedConfig()
	
	a.delayMu.Lock()
	defer a.delayMu.Unlock()

	// Update or create failure info
	info, exists := a.ipFailureCounts[ip]
	if !exists {
		info = &IPFailureInfo{
			FirstFailure: failureTime,
			LastDelay:    0,
		}
		a.ipFailureCounts[ip] = info
	}
	
	info.FailureCount++
	info.LastFailure = failureTime
	
	// Calculate progressive delay
	if info.FailureCount >= config.DelayStartThreshold {
		if info.LastDelay == 0 {
			info.LastDelay = config.InitialDelay
		} else {
			info.LastDelay = time.Duration(float64(info.LastDelay) * config.DelayMultiplier)
			if info.LastDelay > config.MaxDelay {
				info.LastDelay = config.MaxDelay
			}
		}
	}

	// Check if IP should be fast blocked
	if info.FailureCount >= config.FastBlockThreshold {
		a.blockMu.Lock()
		a.blockedIPs[ip] = &BlockedIPInfo{
			BlockedUntil: failureTime.Add(config.FastBlockDuration),
			FailureCount: info.FailureCount,
			FirstFailure: info.FirstFailure,
			LastFailure:  failureTime,
			Protocol:     a.protocol,
		}
		a.blockMu.Unlock()
		
		log.Printf("[%s-AUTH-LIMITER] FAST BLOCKED IP %s after %d failures (blocked until %v)", 
			a.protocol, ip, info.FailureCount, failureTime.Add(config.FastBlockDuration).Format("15:04:05"))
	} else if info.FailureCount >= config.DelayStartThreshold {
		log.Printf("[%s-AUTH-LIMITER] Progressive delay for IP %s: %v (failure %d)", 
			a.protocol, ip, info.LastDelay, info.FailureCount)
	}
}

// clearFailureTracking clears failure tracking for IP after successful login
func (a *EnhancedAuthRateLimiter) clearFailureTracking(ip string) {
	a.delayMu.Lock()
	delete(a.ipFailureCounts, ip)
	a.delayMu.Unlock()

	a.blockMu.Lock()  
	delete(a.blockedIPs, ip)
	a.blockMu.Unlock()

	log.Printf("[%s-AUTH-LIMITER] Cleared failure tracking for IP %s after successful login", a.protocol, ip)
}

// enhancedConfig stores the full config for this limiter
type configHolder struct {
	enhanced EnhancedAuthRateLimiterConfig
}

// Store config in the limiter
// getEnhancedConfig returns the enhanced config
func (a *EnhancedAuthRateLimiter) getEnhancedConfig() EnhancedAuthRateLimiterConfig {
	return a.enhancedConfig
}

// NewEnhancedAuthRateLimiterFromBasic creates enhanced limiter from basic config
func NewEnhancedAuthRateLimiterFromBasic(protocol string, basicConfig AuthRateLimiterConfig, database AuthDatabase) *EnhancedAuthRateLimiter {
	// Convert basic config to enhanced config with defaults
	enhancedConfig := EnhancedAuthRateLimiterConfig{
		AuthRateLimiterConfig: basicConfig,
		FastBlockThreshold:    10,               // Block after 10 failures (same as max_attempts_per_ip)
		FastBlockDuration:     5 * time.Minute,  // Block for 5 minutes
		DelayStartThreshold:   2,                // Start delays after 2 failures
		InitialDelay:          2 * time.Second,  // 2 second initial delay
		MaxDelay:              30 * time.Second, // Max 30 second delay
		DelayMultiplier:       2.0,              // Double delay each time
		CacheCleanupInterval:  1 * time.Minute,  // Clean cache every minute
		DBSyncInterval:        30 * time.Second, // Sync every 30 seconds
		MaxPendingBatch:       100,              // Batch up to 100 records
		DBErrorThreshold:      1 * time.Minute,  // Wait 1 minute after DB error
	}
	
	return NewEnhancedAuthRateLimiter(protocol, enhancedConfig, database)
}

// queueForDBSync queues attempt for batched database sync
func (a *EnhancedAuthRateLimiter) queueForDBSync(attempt AuthAttempt) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	
	a.pendingRecords = append(a.pendingRecords, attempt)
	
	// If batch is full, trigger immediate sync
	config := a.getEnhancedConfig()
	if len(a.pendingRecords) >= config.MaxPendingBatch {
		go a.syncPendingRecords()
	}
}

// shouldCheckDatabase returns true if database should be consulted
func (a *EnhancedAuthRateLimiter) shouldCheckDatabase() bool {
	if !a.dbHealthy {
		config := a.getEnhancedConfig()
		if time.Since(a.lastDBError) < config.DBErrorThreshold {
			return false
		}
		a.dbHealthy = true
	}
	return true
}

// markDBUnhealthy marks database as unhealthy after an error
func (a *EnhancedAuthRateLimiter) markDBUnhealthy() {
	a.dbHealthy = false
	a.lastDBError = time.Now()
}

// syncRoutine periodically syncs pending records to database
func (a *EnhancedAuthRateLimiter) syncRoutine() {
	ticker := time.NewTicker(a.dbSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.syncPendingRecords()
		case <-a.stopSync:
			a.syncPendingRecords() // Final sync
			return
		}
	}
}

// syncPendingRecords syncs all pending records to database
func (a *EnhancedAuthRateLimiter) syncPendingRecords() {
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
	
	successCount := 0
	for _, record := range records {
		err := a.db.RecordAuthAttempt(ctx, record.IP, record.Username, a.protocol, record.Success)
		if err != nil {
			log.Printf("[%s-AUTH-LIMITER] Warning: failed to sync auth attempt: %v", a.protocol, err)
			a.markDBUnhealthy()
			break
		}
		successCount++
	}
	
	if successCount > 0 {
		log.Printf("[%s-AUTH-LIMITER] Synced %d/%d auth attempts to database", a.protocol, successCount, len(records))
	}
}

// cleanupRoutine periodically cleans up expired cache entries
func (a *EnhancedAuthRateLimiter) cleanupRoutine(interval time.Duration) {
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

// cleanupExpiredEntries removes expired cache entries
func (a *EnhancedAuthRateLimiter) cleanupExpiredEntries() {
	now := time.Now()
	
	// Clean up expired blocks
	a.blockMu.Lock()
	expiredBlocks := 0
	for ip, blocked := range a.blockedIPs {
		if now.After(blocked.BlockedUntil) {
			delete(a.blockedIPs, ip)
			expiredBlocks++
		}
	}
	a.blockMu.Unlock()
	
	// Clean up old failure info (older than IP window)
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

// GetStats returns current enhanced rate limiting statistics
func (a *EnhancedAuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{} {
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
		"enabled":       true,
		"type":          "enhanced",
		"blocked_ips":   blockedCount,
		"tracked_ips":   trackedIPs,
		"pending_sync":  pendingCount,
		"db_healthy":    a.dbHealthy,
		"config": map[string]interface{}{
			"max_attempts_per_ip":       a.config.MaxAttemptsPerIP,
			"max_attempts_per_username": a.config.MaxAttemptsPerUsername,
			"ip_window_duration":        a.config.IPWindowDuration.String(),
			"username_window_duration":  a.config.UsernameWindowDuration.String(),
		},
	}

	// Try to get database stats if healthy
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

// Stop shuts down the enhanced rate limiter
func (a *EnhancedAuthRateLimiter) Stop() {
	if a == nil {
		return
	}
	
	close(a.stopCleanup)
	close(a.stopSync)
}

// Ensure EnhancedAuthRateLimiter implements the same interface as AuthRateLimiter
// These methods provide compatibility with existing code

// CanAttemptAuth is already implemented above
// RecordAuthAttempt is already implemented above  
// GetStats is already implemented above
// GetAuthenticationDelay is already implemented above (for AuthDelayHelper interface)