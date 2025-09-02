package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// HybridAuthRateLimiter combines in-memory caching with database persistence
// to provide shared rate limiting with database protection
type HybridAuthRateLimiter struct {
	config           AuthRateLimiterConfig
	db               AuthDatabase
	protocol         string
	
	// In-memory cache for recent attempts (reduces DB load)
	recentAttempts   map[string]*RecentAttemptCache
	cacheMu          sync.RWMutex
	cacheExpiry      time.Duration
	
	// Database sync settings
	dbSyncInterval   time.Duration
	pendingRecords   []AuthAttempt
	pendingMu        sync.Mutex
	
	// Circuit breaker for database protection
	dbHealthy        bool
	lastDBError      time.Time
	dbErrorThreshold time.Duration
	
	stopCleanup      chan struct{}
	stopSync         chan struct{}
}

// RecentAttemptCache holds recent authentication attempts in memory
type RecentAttemptCache struct {
	Attempts    []AuthAttempt
	LastUpdated time.Time
	FailCount   int
}

// HybridAuthRateLimiterConfig extends the basic config with cache settings
type HybridAuthRateLimiterConfig struct {
	AuthRateLimiterConfig
	
	// Cache settings
	CacheExpiry      time.Duration `toml:"cache_expiry"`       // How long to keep attempts in memory
	DBSyncInterval   time.Duration `toml:"db_sync_interval"`   // How often to sync to database
	MaxPendingBatch  int           `toml:"max_pending_batch"`  // Max records to batch before forced sync
	DBErrorThreshold time.Duration `toml:"db_error_threshold"` // Time to wait before retrying DB after error
}

// DefaultHybridAuthRateLimiterConfig returns sensible defaults for hybrid limiter
func DefaultHybridAuthRateLimiterConfig() HybridAuthRateLimiterConfig {
	return HybridAuthRateLimiterConfig{
		AuthRateLimiterConfig: DefaultAuthRateLimiterConfig(),
		CacheExpiry:           5 * time.Minute,  // Keep recent attempts in memory for 5 minutes
		DBSyncInterval:        30 * time.Second, // Sync to database every 30 seconds
		MaxPendingBatch:       100,              // Force sync after 100 pending records
		DBErrorThreshold:      1 * time.Minute,  // Wait 1 minute before retrying DB after error
	}
}

// NewHybridAuthRateLimiter creates a new hybrid authentication rate limiter
func NewHybridAuthRateLimiter(protocol string, config HybridAuthRateLimiterConfig, database AuthDatabase) *HybridAuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &HybridAuthRateLimiter{
		config:           config.AuthRateLimiterConfig,
		db:               database,
		protocol:         protocol,
		recentAttempts:   make(map[string]*RecentAttemptCache),
		cacheExpiry:      config.CacheExpiry,
		dbSyncInterval:   config.DBSyncInterval,
		pendingRecords:   make([]AuthAttempt, 0, config.MaxPendingBatch),
		dbHealthy:        true,
		dbErrorThreshold: config.DBErrorThreshold,
		stopCleanup:      make(chan struct{}),
		stopSync:         make(chan struct{}),
	}

	// Start background routines
	go limiter.cleanupRoutine()
	go limiter.syncRoutine()

	log.Printf("[%s-AUTH-LIMITER] Initialized hybrid limiter: max_per_ip=%d/%v, max_per_user=%d/%v, cache_expiry=%v", 
		protocol, config.MaxAttemptsPerIP, config.IPWindowDuration,
		config.MaxAttemptsPerUsername, config.UsernameWindowDuration, config.CacheExpiry)

	return limiter
}

// CanAttemptAuth checks if authentication can be attempted using cache-first approach
func (a *HybridAuthRateLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
	if a == nil {
		return nil
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// First check in-memory cache for recent attempts
	ipCount, usernameCount := a.getRecentFailureCounts(ip, username)
	
	// If cache shows we're already over limits, deny immediately (fast path)
	if a.config.MaxAttemptsPerIP > 0 && ipCount >= a.config.MaxAttemptsPerIP {
		return fmt.Errorf("too many failed authentication attempts from IP %s (%d/%d in recent cache)", 
			ip, ipCount, a.config.MaxAttemptsPerIP)
	}
	
	if a.config.MaxAttemptsPerUsername > 0 && username != "" && usernameCount >= a.config.MaxAttemptsPerUsername {
		return fmt.Errorf("too many failed authentication attempts for user %s (%d/%d in recent cache)", 
			username, usernameCount, a.config.MaxAttemptsPerUsername)
	}

	// If cache doesn't show violations, check database (but only if DB is healthy)
	if a.shouldCheckDatabase() {
		dbIPCount, dbUsernameCount, err := a.db.GetFailedAttemptsCountSeparateWindows(
			ctx, ip, username, a.config.IPWindowDuration, a.config.UsernameWindowDuration)
		
		if err != nil {
			a.markDBUnhealthy()
			log.Printf("[%s-AUTH-LIMITER] Warning: database check failed, using cache-only: %v", a.protocol, err)
			// Continue with cache-only decision (fail-open)
		} else {
			// Database check succeeded, use more accurate database counts
			if a.config.MaxAttemptsPerIP > 0 && dbIPCount >= a.config.MaxAttemptsPerIP {
				return fmt.Errorf("too many failed authentication attempts from IP %s (%d/%d in %v)", 
					ip, dbIPCount, a.config.MaxAttemptsPerIP, a.config.IPWindowDuration)
			}
			
			if a.config.MaxAttemptsPerUsername > 0 && username != "" && dbUsernameCount >= a.config.MaxAttemptsPerUsername {
				return fmt.Errorf("too many failed authentication attempts for user %s (%d/%d in %v)", 
					username, dbUsernameCount, a.config.MaxAttemptsPerUsername, a.config.UsernameWindowDuration)
			}
		}
	}

	return nil
}

// RecordAuthAttempt records an authentication attempt in cache and queues for DB sync
func (a *HybridAuthRateLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
	if a == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	attempt := AuthAttempt{
		Timestamp: time.Now(),
		Success:   success,
		IP:        ip,
		Username:  username,
	}

	// Always record in memory cache for fast lookups
	a.recordInCache(attempt)

	// Queue for database sync (batched for performance)
	a.queueForDBSync(attempt)

	if !success {
		log.Printf("[%s-AUTH-LIMITER] Failed authentication attempt from %s for user '%s'", 
			a.protocol, ip, username)
	}
}

// getRecentFailureCounts gets failure counts from in-memory cache
func (a *HybridAuthRateLimiter) getRecentFailureCounts(ip, username string) (ipCount, usernameCount int) {
	a.cacheMu.RLock()
	defer a.cacheMu.RUnlock()
	
	now := time.Now()
	ipCutoff := now.Add(-a.config.IPWindowDuration)
	usernameCutoff := now.Add(-a.config.UsernameWindowDuration)
	
	// Count IP failures
	if cache, exists := a.recentAttempts[ip]; exists && cache.LastUpdated.After(ipCutoff) {
		for _, attempt := range cache.Attempts {
			if !attempt.Success && attempt.Timestamp.After(ipCutoff) {
				ipCount++
			}
		}
	}
	
	// Count username failures
	if username != "" {
		if cache, exists := a.recentAttempts[username]; exists && cache.LastUpdated.After(usernameCutoff) {
			for _, attempt := range cache.Attempts {
				if !attempt.Success && attempt.Timestamp.After(usernameCutoff) {
					usernameCount++
				}
			}
		}
	}
	
	return ipCount, usernameCount
}

// recordInCache adds attempt to in-memory cache
func (a *HybridAuthRateLimiter) recordInCache(attempt AuthAttempt) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	
	now := time.Now()
	
	// Record by IP
	if cache, exists := a.recentAttempts[attempt.IP]; exists {
		cache.Attempts = append(cache.Attempts, attempt)
		cache.LastUpdated = now
		if !attempt.Success {
			cache.FailCount++
		}
	} else {
		failCount := 0
		if !attempt.Success {
			failCount = 1
		}
		a.recentAttempts[attempt.IP] = &RecentAttemptCache{
			Attempts:    []AuthAttempt{attempt},
			LastUpdated: now,
			FailCount:   failCount,
		}
	}
	
	// Record by username if provided
	if attempt.Username != "" {
		if cache, exists := a.recentAttempts[attempt.Username]; exists {
			cache.Attempts = append(cache.Attempts, attempt)
			cache.LastUpdated = now
			if !attempt.Success {
				cache.FailCount++
			}
		} else {
			failCount := 0
			if !attempt.Success {
				failCount = 1
			}
			a.recentAttempts[attempt.Username] = &RecentAttemptCache{
				Attempts:    []AuthAttempt{attempt},
				LastUpdated: now,
				FailCount:   failCount,
			}
		}
	}
}

// queueForDBSync queues attempt for batched database sync
func (a *HybridAuthRateLimiter) queueForDBSync(attempt AuthAttempt) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	
	a.pendingRecords = append(a.pendingRecords, attempt)
	
	// If batch is full, trigger immediate sync
	if len(a.pendingRecords) >= 100 { // Configurable max batch size
		go a.syncPendingRecords()
	}
}

// shouldCheckDatabase returns true if database should be consulted
func (a *HybridAuthRateLimiter) shouldCheckDatabase() bool {
	if !a.dbHealthy {
		// Check if enough time has passed to retry database
		if time.Since(a.lastDBError) < a.dbErrorThreshold {
			return false
		}
		// Reset health status for retry
		a.dbHealthy = true
	}
	return true
}

// markDBUnhealthy marks database as unhealthy after an error
func (a *HybridAuthRateLimiter) markDBUnhealthy() {
	a.dbHealthy = false
	a.lastDBError = time.Now()
}

// syncRoutine periodically syncs pending records to database
func (a *HybridAuthRateLimiter) syncRoutine() {
	ticker := time.NewTicker(a.dbSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.syncPendingRecords()
		case <-a.stopSync:
			// Final sync before shutdown
			a.syncPendingRecords()
			return
		}
	}
}

// syncPendingRecords syncs all pending records to database
func (a *HybridAuthRateLimiter) syncPendingRecords() {
	a.pendingMu.Lock()
	if len(a.pendingRecords) == 0 {
		a.pendingMu.Unlock()
		return
	}
	
	records := make([]AuthAttempt, len(a.pendingRecords))
	copy(records, a.pendingRecords)
	a.pendingRecords = a.pendingRecords[:0] // Clear pending records
	a.pendingMu.Unlock()
	
	// Sync to database with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	successCount := 0
	for _, record := range records {
		err := a.db.RecordAuthAttempt(ctx, record.IP, record.Username, a.protocol, record.Success)
		if err != nil {
			log.Printf("[%s-AUTH-LIMITER] Warning: failed to sync auth attempt to database: %v", a.protocol, err)
			a.markDBUnhealthy()
			break // Stop trying on first error to avoid cascading failures
		}
		successCount++
	}
	
	if successCount > 0 {
		log.Printf("[%s-AUTH-LIMITER] Synced %d/%d auth attempts to database", a.protocol, successCount, len(records))
	}
}

// cleanupRoutine periodically cleans up old cache entries
func (a *HybridAuthRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(a.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.cleanupCache()
		case <-a.stopCleanup:
			return
		}
	}
}

// cleanupCache removes expired entries from in-memory cache
func (a *HybridAuthRateLimiter) cleanupCache() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	
	now := time.Now()
	expiry := now.Add(-a.cacheExpiry)
	cleaned := 0
	
	for key, cache := range a.recentAttempts {
		if cache.LastUpdated.Before(expiry) {
			delete(a.recentAttempts, key)
			cleaned++
		}
	}
	
	if cleaned > 0 {
		log.Printf("[%s-AUTH-LIMITER] Cleaned up %d expired cache entries", a.protocol, cleaned)
	}
}

// GetStats returns current rate limiting statistics including cache stats
func (a *HybridAuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{} {
	if a == nil {
		return map[string]interface{}{"enabled": false}
	}

	a.cacheMu.RLock()
	cacheSize := len(a.recentAttempts)
	a.cacheMu.RUnlock()
	
	a.pendingMu.Lock()
	pendingCount := len(a.pendingRecords)
	a.pendingMu.Unlock()

	stats := map[string]interface{}{
		"enabled":       true,
		"storage":       "hybrid",
		"cache_size":    cacheSize,
		"pending_sync":  pendingCount,
		"db_healthy":    a.dbHealthy,
		"config": map[string]interface{}{
			"max_attempts_per_ip":       a.config.MaxAttemptsPerIP,
			"max_attempts_per_username": a.config.MaxAttemptsPerUsername,
			"ip_window_duration":        a.config.IPWindowDuration.String(),
			"username_window_duration":  a.config.UsernameWindowDuration.String(),
			"cache_expiry":              a.cacheExpiry.String(),
		},
	}

	// Try to get database stats if DB is healthy
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

// Stop shuts down the hybrid rate limiter
func (a *HybridAuthRateLimiter) Stop() {
	if a == nil {
		return
	}
	
	close(a.stopCleanup)
	close(a.stopSync)
	
	// Final sync of any pending records
	a.syncPendingRecords()
}