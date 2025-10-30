package authcache

import (
	"context"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// AuthResult represents the result of an authentication attempt
type AuthResult int

const (
	AuthSuccess AuthResult = iota
	AuthUserNotFound
	AuthInvalidPassword
)

// cacheEntry represents a cached authentication result
type cacheEntry struct {
	accountID      int64
	hashedPassword string
	result         AuthResult
	expiresAt      time.Time
}

// AuthCache provides in-memory caching for authentication results
type AuthCache struct {
	mu              sync.RWMutex
	entries         map[string]*cacheEntry
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxSize         int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}

	// Metrics
	hits   uint64
	misses uint64
}

// New creates a new authentication cache instance
func New(positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration) *AuthCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	cache := &AuthCache{
		entries:         make(map[string]*cacheEntry),
		positiveTTL:     positiveTTL,
		negativeTTL:     negativeTTL,
		maxSize:         maxSize,
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
		cleanupStopped:  make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	logger.Info("AuthCache: Initialized", "positive_ttl", positiveTTL,
		"negative_ttl", negativeTTL, "max_size", maxSize, "cleanup_interval", cleanupInterval)

	return cache
}

// Authenticate attempts to authenticate using cached data
// Returns (accountID, nil) on success, or (0, error) if not in cache or cache miss
// If credentials are in cache, it verifies the password against the cached hash
func (c *AuthCache) Authenticate(address, password string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[address]
	if !exists {
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return 0, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return 0, false
	}

	c.hits++
	metrics.AuthCacheHitsTotal.Inc()

	// If it's a negative cache entry (user not found or previous auth failed)
	if entry.result != AuthSuccess {
		return 0, false
	}

	// Verify password against cached hash
	if err := db.VerifyPassword(entry.hashedPassword, password); err != nil {
		// Password verification failed - this is a cache hit but auth failure
		// Don't update cache here, let it expire naturally
		return 0, false
	}

	// Password verified successfully
	return entry.accountID, true
}

// SetSuccess caches a successful authentication result
func (c *AuthCache) SetSuccess(address string, accountID int64, hashedPassword string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[address] = &cacheEntry{
		accountID:      accountID,
		hashedPassword: hashedPassword,
		result:         AuthSuccess,
		expiresAt:      time.Now().Add(c.positiveTTL),
	}

	metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
}

// SetFailure caches a failed authentication result (user not found or invalid password)
// result parameter: 0 = success (ignored), 1 = user not found, 2 = invalid password
func (c *AuthCache) SetFailure(address string, result int) {
	authResult := AuthResult(result)
	if authResult == AuthSuccess {
		return // Don't cache success as failure
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[address] = &cacheEntry{
		result:    authResult,
		expiresAt: time.Now().Add(c.negativeTTL),
	}

	metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
}

// Invalidate removes a specific entry from the cache (e.g., after password change)
func (c *AuthCache) Invalidate(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, address)
	metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
}

// evictOldest removes the oldest entry from the cache
// Caller must hold the write lock
func (c *AuthCache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.entries {
		if first || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// cleanupLoop periodically removes expired entries
func (c *AuthCache) cleanupLoop() {
	defer close(c.cleanupStopped)

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (c *AuthCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			removed++
		}
	}

	if removed > 0 {
		logger.Info("AuthCache: Cleanup removed expired entries", "removed", removed, "remaining", len(c.entries))
		metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
	}

	// Update hit rate metric
	c.updateHitRateMetric()
}

// updateHitRateMetric updates the Prometheus hit rate gauge
// Caller must hold at least the read lock
func (c *AuthCache) updateHitRateMetric() {
	total := c.hits + c.misses
	if total > 0 {
		hitRate := float64(c.hits) / float64(total) * 100
		metrics.AuthCacheHitRate.Set(hitRate)
	}
}

// Stop stops the cleanup goroutine
func (c *AuthCache) Stop(ctx context.Context) error {
	close(c.stopCleanup)

	// Wait for cleanup to stop with timeout
	select {
	case <-c.cleanupStopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetStats returns cache statistics
func (c *AuthCache) GetStats() (hits, misses uint64, size int, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	var rate float64
	if total > 0 {
		rate = float64(c.hits) / float64(total) * 100
	}

	return c.hits, c.misses, len(c.entries), rate
}

// Clear removes all entries from the cache
func (c *AuthCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
	c.hits = 0
	c.misses = 0

	logger.Info("AuthCache: Cache cleared")
}
