package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"golang.org/x/sync/singleflight"
)

// HashPassword creates a SHA-256 hash of the password for cache comparison.
// This is used to detect password changes without storing plaintext passwords in the cache.
func HashPassword(password string) string {
	if password == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// AuthResult represents the authentication result
type AuthResult int

const (
	AuthSuccess AuthResult = iota
	AuthFailed
	AuthUserNotFound
	AuthUnavailable
)

func (a AuthResult) String() string {
	switch a {
	case AuthSuccess:
		return "success"
	case AuthFailed:
		return "failed"
	case AuthUserNotFound:
		return "user_not_found"
	case AuthUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// CacheEntry represents a cached authentication and routing result
type CacheEntry struct {
	// Authentication data
	AccountID    int64
	PasswordHash string // For detecting password changes

	// Routing data
	ServerAddress          string // Backend server address (from prelookup or affinity)
	RemoteTLS              bool
	RemoteTLSUseStartTLS   bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	RemoteUseIDCommand     bool
	RemoteUseXCLIENT       bool

	// Metadata
	AuthResult    AuthResult
	FromPrelookup bool // True if this came from prelookup API
	CreatedAt     time.Time
	ExpiresAt     time.Time
	IsNegative    bool // True for failed/not found results
}

// IsOld checks if the cache entry is older than the given duration
// This is used to determine if we should revalidate instead of trusting the cache
func (e *CacheEntry) IsOld(maxAge time.Duration) bool {
	return time.Since(e.CreatedAt) > maxAge
}

// AuthCache provides unified caching for authentication and routing across all protocols
type AuthCache struct {
	mu              sync.RWMutex
	entries         map[string]*CacheEntry // key: "server:username"
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxPositiveSize int // Max entries for successful auth
	maxNegativeSize int // Max entries for failed auth (limits attack impact)
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}
	stopOnce        sync.Once          // Ensures Stop() can be called multiple times safely
	sfGroup         singleflight.Group // Prevents thundering herd on cache miss

	// Metrics
	hits   uint64
	misses uint64

	// Cleanup counter for periodic logging
	cleanupCounter uint64
}

// New creates a new AuthCache instance
func New(positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration) *AuthCache {
	if maxSize <= 0 {
		maxSize = 50000
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	// Allocate 80% to positive cache, 20% to negative cache
	// This limits attack impact while allowing legitimate users ample space
	maxPositiveSize := int(float64(maxSize) * 0.8)
	maxNegativeSize := int(float64(maxSize) * 0.2)

	cache := &AuthCache{
		entries:         make(map[string]*CacheEntry),
		positiveTTL:     positiveTTL,
		negativeTTL:     negativeTTL,
		maxPositiveSize: maxPositiveSize,
		maxNegativeSize: maxNegativeSize,
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
		cleanupStopped:  make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	logger.Info("Auth cache initialized",
		"positive_ttl", positiveTTL,
		"negative_ttl", negativeTTL,
		"max_positive", maxPositiveSize,
		"max_negative", maxNegativeSize,
		"cleanup_interval", cleanupInterval)

	return cache
}

// makeKey creates a cache key from server name and username
// Using server name (instead of protocol) prevents cache collisions when:
// - Running proxy and backend on the same server
// - Running multiple proxies for the same protocol with different prelookup services
func makeKey(serverName, username string) string {
	return fmt.Sprintf("%s:%s", serverName, username)
}

// Get retrieves a cached entry
// serverName should be the unique server name (e.g., "imap-proxy-1", "imap-backend")
// Returns the entry and whether it was found (and not expired)
func (c *AuthCache) Get(serverName, username string) (*CacheEntry, bool) {
	key := makeKey(serverName, username)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		atomic.AddUint64(&c.misses, 1)
		metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddUint64(&c.misses, 1)
		metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		return nil, false
	}

	atomic.AddUint64(&c.hits, 1)
	metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()
	return entry, true
}

// GetPasswordHash retrieves just the password hash for a user
// This is used to detect password changes without fetching the full entry
func (c *AuthCache) GetPasswordHash(serverName, username string) (string, bool) {
	key := makeKey(serverName, username)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.PasswordHash, true
}

// Set stores an entry in the cache
func (c *AuthCache) Set(serverName, username string, entry *CacheEntry) {
	key := makeKey(serverName, username)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Determine TTL based on result type
	entry.IsNegative = (entry.AuthResult == AuthFailed || entry.AuthResult == AuthUserNotFound)
	var ttl time.Duration
	if entry.IsNegative {
		ttl = c.negativeTTL
	} else {
		ttl = c.positiveTTL
	}

	entry.CreatedAt = time.Now()
	entry.ExpiresAt = time.Now().Add(ttl)

	// Check if this is an update to an existing entry
	existingEntry, isUpdate := c.entries[key]

	// Enforce separate size limits for positive and negative entries
	// Only count and evict if this is a NEW entry (not an update)
	if !isUpdate {
		positiveCount, negativeCount := c.countEntriesByType()

		if entry.IsNegative {
			// Adding a new negative entry
			if negativeCount >= c.maxNegativeSize {
				// Evict oldest negative entry to make room
				c.evictOldestByType(true)
			}
		} else {
			// Adding a new positive entry
			if positiveCount >= c.maxPositiveSize {
				// Evict oldest positive entry to make room
				c.evictOldestByType(false)
			}
		}
	} else {
		// If updating an entry and changing its type (positive <-> negative), need to check limits
		if existingEntry.IsNegative != entry.IsNegative {
			positiveCount, negativeCount := c.countEntriesByType()

			if entry.IsNegative {
				// Changing from positive to negative
				// We're freeing a positive slot and need a negative slot
				if negativeCount >= c.maxNegativeSize {
					c.evictOldestByType(true)
				}
			} else {
				// Changing from negative to positive
				// We're freeing a negative slot and need a positive slot
				if positiveCount >= c.maxPositiveSize {
					c.evictOldestByType(false)
				}
			}
		}
		// If same type, no eviction needed - just update in place
	}

	c.entries[key] = entry
	metrics.CacheOperationsTotal.WithLabelValues("set", "success").Inc()
}

// countEntriesByType counts positive and negative entries (caller must hold lock)
func (c *AuthCache) countEntriesByType() (positive, negative int) {
	for _, entry := range c.entries {
		if entry.IsNegative {
			negative++
		} else {
			positive++
		}
	}
	return
}

// evictOldestByType evicts the oldest entry of the specified type (caller must hold lock)
func (c *AuthCache) evictOldestByType(isNegative bool) {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if entry.IsNegative != isNegative {
			continue
		}

		if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		metrics.CacheOperationsTotal.WithLabelValues("evict", "size_limit").Inc()
	}
}

// Refresh extends the TTL of an existing cache entry
// This is called when the same password is used again to keep frequently-used entries fresh
func (c *AuthCache) Refresh(serverName, username string) bool {
	key := makeKey(serverName, username)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return false
	}

	// Extend TTL based on entry type
	var ttl time.Duration
	if entry.IsNegative {
		ttl = c.negativeTTL
	} else {
		ttl = c.positiveTTL
	}

	entry.ExpiresAt = time.Now().Add(ttl)
	metrics.CacheOperationsTotal.WithLabelValues("refresh", "success").Inc()
	return true
}

// Invalidate removes an entry from the cache
// This is useful when you detect a password change
func (c *AuthCache) Invalidate(serverName, username string) {
	key := makeKey(serverName, username)

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
	metrics.CacheOperationsTotal.WithLabelValues("invalidate", "success").Inc()
}

// CheckPasswordChange checks if the password has changed and invalidates if needed
// Returns true if the password changed and cache was invalidated
// If either password hash is empty, returns false without invalidating (cannot detect change)
func (c *AuthCache) CheckPasswordChange(serverName, username, newPasswordHash string) bool {
	// If new password hash is empty, we can't detect change - don't invalidate
	if newPasswordHash == "" {
		return false
	}

	key := makeKey(serverName, username)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return false
	}

	// If cached password hash is empty, we can't detect change - don't invalidate
	if entry.PasswordHash == "" {
		return false
	}

	// Check if password changed
	if entry.PasswordHash != newPasswordHash {
		delete(c.entries, key)
		metrics.CacheOperationsTotal.WithLabelValues("password_change", "invalidated").Inc()
		logger.Debug("Cache invalidated due to password change", "server", serverName, "username", username)
		return true
	}

	return false
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

// cleanup removes expired entries and updates metrics
func (c *AuthCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			removed++
		}
	}

	if removed > 0 {
		logger.Debug("Auth cache cleanup", "removed", removed, "remaining", len(c.entries))
	}

	// Calculate statistics
	positiveEntries := 0
	negativeEntries := 0
	prelookupEntries := 0

	for _, entry := range c.entries {
		if entry.IsNegative {
			negativeEntries++
		} else {
			positiveEntries++
		}
		if entry.FromPrelookup {
			prelookupEntries++
		}
	}

	totalEntries := len(c.entries)

	// Update metrics
	metrics.CacheSize.WithLabelValues("auth").Set(float64(totalEntries))
	metrics.CacheHitRatio.WithLabelValues("auth").Set(c.calculateHitRatio())

	// Log stats periodically (every 10 cleanup cycles)
	c.cleanupCounter++
	if c.cleanupCounter%10 == 0 {
		hits := atomic.LoadUint64(&c.hits)
		misses := atomic.LoadUint64(&c.misses)
		hitRate := c.calculateHitRatio() * 100

		maxSize := c.maxPositiveSize + c.maxNegativeSize
		logger.Info("Auth cache stats",
			"total_entries", totalEntries,
			"positive_entries", positiveEntries,
			"negative_entries", negativeEntries,
			"prelookup_entries", prelookupEntries,
			"max_size", maxSize,
			"max_positive", c.maxPositiveSize,
			"max_negative", c.maxNegativeSize,
			"hits", hits,
			"misses", misses,
			"hit_rate_pct", roundToTwoDecimals(hitRate),
			"removed_this_cycle", removed)
	}
}

// calculateHitRatio calculates the cache hit ratio
func (c *AuthCache) calculateHitRatio() float64 {
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

// Stop stops the cleanup goroutine
// It is safe to call Stop multiple times
func (c *AuthCache) Stop(ctx context.Context) error {
	c.stopOnce.Do(func() {
		close(c.stopCleanup)
	})

	// Wait for cleanup to stop with timeout
	select {
	case <-c.cleanupStopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetStats returns cache statistics
func (c *AuthCache) GetStats() (hits, misses uint64, size int, hitRatio float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	h := atomic.LoadUint64(&c.hits)
	m := atomic.LoadUint64(&c.misses)
	return h, m, len(c.entries), c.calculateHitRatio()
}

// Clear removes all entries from the cache
// This is mainly useful for testing
func (c *AuthCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)
}

// roundToTwoDecimals rounds a float to 2 decimal places
func roundToTwoDecimals(val float64) float64 {
	return float64(int(val*100+0.5)) / 100
}
