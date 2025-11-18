package authcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
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

// CacheEntry represents a cached authentication and routing result
type CacheEntry struct {
	// Authentication data
	AccountID      int64
	HashedPassword string // Stored password hash from database (for backend auth)
	PasswordHash   string // SHA-256 hash of plaintext password for comparison

	// Routing data (for proxy)
	ServerAddress          string
	RemoteTLS              bool
	RemoteTLSUseStartTLS   bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	RemoteUseIDCommand     bool
	RemoteUseXCLIENT       bool

	// Metadata
	Result        AuthResult
	FromPrelookup bool // True if this came from prelookup API
	CreatedAt     time.Time
	ExpiresAt     time.Time
	IsNegative    bool
}

// AuthCache provides in-memory caching for authentication results
type AuthCache struct {
	mu              sync.RWMutex
	entries         map[string]*CacheEntry
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxSize         int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}

	// Revalidation windows for password change detection
	negativeRevalidationWindow time.Duration
	positiveRevalidationWindow time.Duration

	// Metrics
	hits   uint64
	misses uint64

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64
}

// New creates a new authentication cache instance
func New(positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration, negativeRevalidationWindow, positiveRevalidationWindow time.Duration) *AuthCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}
	if negativeRevalidationWindow <= 0 {
		negativeRevalidationWindow = 5 * time.Second
	}
	if positiveRevalidationWindow <= 0 {
		positiveRevalidationWindow = 30 * time.Second
	}

	cache := &AuthCache{
		entries:                    make(map[string]*CacheEntry),
		positiveTTL:                positiveTTL,
		negativeTTL:                negativeTTL,
		maxSize:                    maxSize,
		cleanupInterval:            cleanupInterval,
		negativeRevalidationWindow: negativeRevalidationWindow,
		positiveRevalidationWindow: positiveRevalidationWindow,
		stopCleanup:                make(chan struct{}),
		cleanupStopped:             make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	logger.Info("AuthCache: Initialized", "positive_ttl", positiveTTL,
		"negative_ttl", negativeTTL, "max_size", maxSize, "cleanup_interval", cleanupInterval,
		"negative_revalidation_window", negativeRevalidationWindow, "positive_revalidation_window", positiveRevalidationWindow)

	return cache
}

// HashPassword creates a SHA-256 hash of the password for cache comparison.
// This is used to detect password changes without storing plaintext passwords in the cache.
func HashPassword(password string) string {
	if password == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// IsOld checks if a cache entry is older than the given duration
func (e *CacheEntry) IsOld(duration time.Duration) bool {
	return time.Since(e.CreatedAt) > duration
}

// Authenticate attempts to authenticate using cached data
// Returns:
//   - (accountID, true, nil) on cache hit with successful authentication
//   - (0, false, nil) if not in cache or needs revalidation (caller should check database)
//   - (0, false, error) on cached authentication failure (caller should NOT check database)
//
// Uses password-aware revalidation to detect password changes while preventing rapid brute force attempts
func (c *AuthCache) Authenticate(address, password string) (accountID int64, found bool, err error) {
	c.mu.RLock()
	entry, exists := c.entries[address]
	if !exists {
		c.mu.RUnlock()
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return 0, false, nil
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.mu.RUnlock()
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return 0, false, nil
	}

	c.hits++
	metrics.AuthCacheHitsTotal.Inc()

	// Hash the provided password for comparison
	passwordHash := HashPassword(password)

	// Check if password matches cached hash
	// Note: entry.PasswordHash should never be empty for valid entries, but we check defensively
	passwordMatches := (entry.PasswordHash != "" && entry.PasswordHash == passwordHash)

	// Handle negative cache entries (failed authentication)
	if entry.Result != AuthSuccess {
		c.mu.RUnlock()
		if passwordMatches {
			// Same wrong password - return cached failure WITHOUT going to database
			logger.Info("Authentication failed (cached)", "address", address, "cache", "hit", "age", time.Since(entry.CreatedAt))
			// Return error to signal cached failure (don't query database)
			return 0, false, consts.ErrAuthenticationFailed
		} else {
			// Different password - allow revalidation if entry is old enough
			if entry.IsOld(c.negativeRevalidationWindow) {
				// Entry is old enough - allow revalidation
				logger.Debug("Auth cache: negative entry revalidation allowed (different password)", "address", address, "age", time.Since(entry.CreatedAt))
				return 0, false, nil
			} else {
				// Entry is too fresh - likely brute force attempt, block revalidation
				logger.Info("Authentication failed (cached, different password blocked)", "address", address, "cache", "hit", "age", time.Since(entry.CreatedAt))
				return 0, false, consts.ErrAuthenticationFailed
			}
		}
	}

	// Positive cache entry - successful authentication previously cached
	if passwordMatches {
		// Same password - verify against bcrypt hash and return success
		if err := db.VerifyPassword(entry.HashedPassword, password); err != nil {
			// Bcrypt verification failed even though password hash matched
			// This shouldn't happen, but handle it by invalidating the cache
			c.mu.RUnlock()
			c.Invalidate(address)
			return 0, false, nil
		}
		c.mu.RUnlock()
		return entry.AccountID, true, nil
	} else {
		// Different password on positive entry - allow revalidation if old enough
		c.mu.RUnlock()
		if entry.IsOld(c.positiveRevalidationWindow) {
			// Entry is old enough - allow revalidation
			return 0, false, nil
		} else {
			// Entry is too fresh - likely wrong password attempt
			logger.Info("Authentication failed (cached positive entry, wrong password)", "address", address, "cache", "hit")
			return 0, false, consts.ErrAuthenticationFailed
		}
	}
}

// SetSuccess caches a successful authentication result
func (c *AuthCache) SetSuccess(address string, accountID int64, hashedPassword string, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	now := time.Now()
	c.entries[address] = &CacheEntry{
		AccountID:      accountID,
		HashedPassword: hashedPassword,
		PasswordHash:   HashPassword(password),
		Result:         AuthSuccess,
		CreatedAt:      now,
		ExpiresAt:      now.Add(c.positiveTTL),
	}

	metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
}

// SetFailure caches a failed authentication result (user not found or invalid password)
// result parameter: 0 = success (ignored), 1 = user not found, 2 = invalid password
// password parameter is optional - used for password-aware negative caching
func (c *AuthCache) SetFailure(address string, result int, password string) {
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

	now := time.Now()
	c.entries[address] = &CacheEntry{
		PasswordHash: HashPassword(password),
		Result:       authResult,
		CreatedAt:    now,
		ExpiresAt:    now.Add(c.negativeTTL),
		IsNegative:   true,
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
		if first || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
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
		if now.After(entry.ExpiresAt) {
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

	// Calculate positive vs negative entry counts
	successEntries := 0
	userNotFoundEntries := 0
	invalidPasswordEntries := 0
	for _, entry := range c.entries {
		switch entry.Result {
		case AuthSuccess:
			successEntries++
		case AuthUserNotFound:
			userNotFoundEntries++
		case AuthInvalidPassword:
			invalidPasswordEntries++
		}
	}

	// Log memory usage stats every 10 cleanup cycles (~50 minutes with 5min cleanup interval)
	c.cleanupCounter++
	if c.cleanupCounter%10 == 0 {
		total := c.hits + c.misses
		var hitRate float64
		if total > 0 {
			hitRate = float64(c.hits) / float64(total) * 100
		}

		logger.Info("AuthCache stats",
			"total_entries", len(c.entries),
			"success_entries", successEntries,
			"user_not_found", userNotFoundEntries,
			"invalid_password", invalidPasswordEntries,
			"max_size", c.maxSize,
			"hit_rate_pct", roundToTwoDecimals(hitRate),
			"removed_this_cycle", removed)
	}
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

	c.entries = make(map[string]*CacheEntry)
	c.hits = 0
	c.misses = 0

	logger.Info("AuthCache: Cache cleared")
}

// roundToTwoDecimals rounds a float to 2 decimal places
func roundToTwoDecimals(val float64) float64 {
	return float64(int(val*100+0.5)) / 100
}

// --- Methods for Proxy Usage ---

// Get retrieves a cached entry
// serverName should be the unique server name (e.g., "imap-proxy-1", "imap-backend")
// Returns the entry and whether it was found (and not expired)
func (c *AuthCache) Get(serverName, username string) (*CacheEntry, bool) {
	key := makeKey(serverName, username)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.misses++
		metrics.AuthCacheMissesTotal.Inc()
		return nil, false
	}

	c.hits++
	metrics.AuthCacheHitsTotal.Inc()
	return entry, true
}

// Set stores an entry in the cache
func (c *AuthCache) Set(serverName, username string, entry *CacheEntry) {
	key := makeKey(serverName, username)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	// Determine TTL based on result type if not already set
	if entry.ExpiresAt.IsZero() {
		var ttl time.Duration
		if entry.IsNegative {
			ttl = c.negativeTTL
		} else {
			ttl = c.positiveTTL
		}
		entry.CreatedAt = time.Now()
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	c.entries[key] = entry
	metrics.AuthCacheEntriesTotal.Set(float64(len(c.entries)))
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
	return true
}

// makeKey creates a cache key from server name and username
func makeKey(serverName, username string) string {
	// If serverName is empty, just use username (backward compatibility for backend)
	if serverName == "" {
		return username
	}
	return fmt.Sprintf("%s:%s", serverName, username)
}
