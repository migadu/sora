package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// cacheEntry represents a cached prelookup result
type cacheEntry struct {
	info         *UserRoutingInfo
	authResult   AuthResult
	expiresAt    time.Time
	isNegative   bool   // True for negative cache entries (user not found, etc.)
	passwordHash string // Password hash from prelookup (for detecting password changes)
}

// prelookupCache provides in-memory caching for HTTP prelookup results
type prelookupCache struct {
	mu              sync.RWMutex
	entries         map[string]*cacheEntry
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxSize         int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}
	protocol        string // Protocol name for logging/metrics (imap, pop3, managesieve, lmtp, userapi)

	// Metrics
	hits   uint64
	misses uint64

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64
}

// newPrelookupCache creates a new cache instance
func newPrelookupCache(protocol string, positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration) *prelookupCache {
	if maxSize <= 0 {
		maxSize = 10000
	}

	cache := &prelookupCache{
		entries:         make(map[string]*cacheEntry),
		positiveTTL:     positiveTTL,
		negativeTTL:     negativeTTL,
		maxSize:         maxSize,
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
		cleanupStopped:  make(chan struct{}),
		protocol:        protocol,
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	logger.Info("Prelookup cache initialized", "protocol", protocol, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize, "cleanup_interval", cleanupInterval)

	return cache
}

// Get retrieves a cached entry
func (c *prelookupCache) Get(key string) (*UserRoutingInfo, AuthResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		atomic.AddUint64(&c.misses, 1)
		return nil, 0, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		atomic.AddUint64(&c.misses, 1)
		return nil, 0, false
	}

	atomic.AddUint64(&c.hits, 1)
	return entry.info, entry.authResult, true
}

// GetPasswordHash retrieves just the password hash from cache for a given email
// Returns the hash and whether it was found
func (c *prelookupCache) GetPasswordHash(email string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[email]
	if !exists {
		return "", false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.passwordHash, true
}

// GetWithPasswordHash atomically retrieves both the password hash and full entry
// This prevents the race condition where an entry is evicted between GetPasswordHash and Get calls
// Returns: (passwordHash, info, authResult, found)
func (c *prelookupCache) GetWithPasswordHash(email string) (string, *UserRoutingInfo, AuthResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[email]
	if !exists {
		atomic.AddUint64(&c.misses, 1)
		return "", nil, 0, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		atomic.AddUint64(&c.misses, 1)
		return "", nil, 0, false
	}

	atomic.AddUint64(&c.hits, 1)
	return entry.passwordHash, entry.info, entry.authResult, true
}

// Set stores a result in the cache
func (c *prelookupCache) Set(key string, info *UserRoutingInfo, authResult AuthResult) {
	c.SetWithHash(key, info, authResult, "")
}

// SetWithHash stores a result in the cache with password hash for invalidation on change
func (c *prelookupCache) SetWithHash(key string, info *UserRoutingInfo, authResult AuthResult, passwordHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	// Determine TTL based on result type
	var ttl time.Duration
	isNegative := (authResult == AuthUserNotFound || authResult == AuthFailed)
	if isNegative {
		ttl = c.negativeTTL
	} else {
		ttl = c.positiveTTL
	}

	c.entries[key] = &cacheEntry{
		info:         info,
		authResult:   authResult,
		expiresAt:    time.Now().Add(ttl),
		isNegative:   isNegative,
		passwordHash: passwordHash,
	}
}

// Delete removes a cache entry by key
func (c *prelookupCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// evictOldest removes the oldest entry from the cache
// Caller must hold the write lock
func (c *prelookupCache) evictOldest() {
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
func (c *prelookupCache) cleanupLoop() {
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
func (c *prelookupCache) cleanup() {
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
		logger.Debug("Prelookup cache cleanup", "removed", removed, "remaining", len(c.entries))
	}

	// Calculate positive vs negative entry counts
	positiveEntries := 0
	negativeEntries := 0
	for _, entry := range c.entries {
		if entry.isNegative {
			negativeEntries++
		} else {
			positiveEntries++
		}
	}

	// Update Prometheus metrics every cleanup cycle
	totalEntries := len(c.entries)
	metrics.PrelookupCacheEntries.Set(float64(totalEntries))
	metrics.PrelookupCachePositiveEntries.Set(float64(positiveEntries))
	metrics.PrelookupCacheNegativeEntries.Set(float64(negativeEntries))

	// Log memory usage stats every 10 cleanup cycles (~50 minutes with 5min cleanup interval)
	c.cleanupCounter++
	if c.cleanupCounter%10 == 0 {
		hits := atomic.LoadUint64(&c.hits)
		misses := atomic.LoadUint64(&c.misses)
		var hitRate float64
		if hits+misses > 0 {
			hitRate = float64(hits) / float64(hits+misses) * 100
		}

		logger.Info("Prelookup cache stats",
			"protocol", c.protocol,
			"total_entries", totalEntries,
			"positive_entries", positiveEntries,
			"negative_entries", negativeEntries,
			"max_size", c.maxSize,
			"hit_rate_pct", roundToTwoDecimals(hitRate),
			"removed_this_cycle", removed)
	}
}

// Stop stops the cleanup goroutine
func (c *prelookupCache) Stop(ctx context.Context) error {
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
func (c *prelookupCache) GetStats() (hits, misses uint64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return atomic.LoadUint64(&c.hits), atomic.LoadUint64(&c.misses), len(c.entries)
}

// roundToTwoDecimals rounds a float to 2 decimal places
func roundToTwoDecimals(val float64) float64 {
	return float64(int(val*100+0.5)) / 100
}
