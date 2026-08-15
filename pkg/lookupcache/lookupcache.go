package lookupcache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"golang.org/x/sync/singleflight"
)

// AuthResult represents the result of an authentication attempt
type AuthResult int

const (
	AuthSuccess AuthResult = iota
	AuthFailed
	AuthUserNotFound
	AuthInvalidPassword
	AuthUnavailable
)

// CacheEntry represents a cached authentication and routing result
type CacheEntry struct {
	// Authentication data
	AccountID      int64
	HashedPassword string // Stored password hash from database (for backend auth)
	// PasswordDigest identifies the password this entry was created with, so a
	// later login can tell "same password" from "different password" without a
	// database round trip. Keyed and salted - see PasswordDigest.
	PasswordDigest PasswordDigest
	ActualEmail    string // Resolved email address (different from cache key if token-based auth)

	// Routing data (for proxy)
	ServerAddress          string
	RemoteTLS              bool
	RemoteTLSUseStartTLS   bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	RemoteUseIDCommand     bool
	RemoteUseXCLIENT       bool

	// Metadata
	Result           AuthResult
	FromRemoteLookup bool // True if this came from remotelookup API
	CreatedAt        time.Time
	ExpiresAt        time.Time
	IsNegative       bool
}

// LookupCache provides in-memory caching for authentication results
type LookupCache struct {
	mu              sync.RWMutex
	entries         map[string]*CacheEntry
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxSize         int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}
	stopped         bool // Track if Stop() has been called

	// Revalidation window for password change detection
	positiveRevalidationWindow time.Duration

	// Singleflight prevents thundering herd on cache miss
	sfGroup singleflight.Group

	// Metrics
	hits   uint64
	misses uint64

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64
}

// New creates a new authentication cache instance
func New(positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration, positiveRevalidationWindow time.Duration) *LookupCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}
	if positiveRevalidationWindow <= 0 {
		positiveRevalidationWindow = 30 * time.Second
	}

	cache := &LookupCache{
		entries:                    make(map[string]*CacheEntry),
		positiveTTL:                positiveTTL,
		negativeTTL:                negativeTTL,
		maxSize:                    maxSize,
		cleanupInterval:            cleanupInterval,
		positiveRevalidationWindow: positiveRevalidationWindow,
		stopCleanup:                make(chan struct{}),
		cleanupStopped:             make(chan struct{}),
	}

	// Start background cleanup goroutine
	go cache.cleanupLoop()

	// Note: Logging is handled by the caller (server) for better context
	return cache
}

// verifyPassword is a seam so tests can drive the verification step; production
// always uses db.VerifyPassword (bcrypt/SSHA512).
var verifyPassword = db.VerifyPassword

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
func (c *LookupCache) Authenticate(address, password string) (accountID int64, found bool, err error) {
	// Copy the entry and release the lock before doing any expensive work, the same
	// way Get/GetOrFetch do. Password verification below is bcrypt (~180ms at cost
	// 12); holding the read lock across it makes every cache write wait it out, and
	// Go's RWMutex parks new readers behind a waiting writer - convoying the whole
	// auth path on exactly the reconnect storm this cache exists to absorb.
	c.mu.RLock()
	cached, exists := c.entries[address]
	var entry CacheEntry
	if exists {
		entry = *cached
	}
	c.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&c.misses, 1)
		metrics.LookupCacheMissesTotal.Inc()
		return 0, false, nil
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddUint64(&c.misses, 1)
		metrics.LookupCacheMissesTotal.Inc()
		return 0, false, nil
	}

	atomic.AddUint64(&c.hits, 1)
	metrics.LookupCacheHitsTotal.Inc()

	// Handle negative cache entries (failed authentication)
	if entry.Result != AuthSuccess {
		// ALWAYS allow revalidation for negative entries, regardless of password match
		// This is critical because:
		// 1. User might not have existed when first cached, but could be created later
		// 2. User's password might have been wrong, but could be changed to match what they tried
		// 3. We rely on the negative TTL (typically 1 minute) to expire stale failures
		// 4. Brute force protection is handled by protocol-level rate limiting
		//
		// Because the outcome is unconditional, negative entries carry no password
		// digest at all (see SetFailure).
		logger.Debug("Auth cache: negative entry revalidation allowed", "address", address, "age", time.Since(entry.CreatedAt))
		return 0, false, nil
	}

	// Positive cache entry - successful authentication previously cached.
	// The age check comes first because an old entry revalidates whatever the
	// password is, so there is no point deriving a digest for it.
	if entry.IsOld(c.positiveRevalidationWindow) {
		// Entry is old - revalidate with database to detect password changes
		logger.Debug("Auth cache: positive entry revalidation needed (entry too old)", "address", address, "age", time.Since(entry.CreatedAt))
		return 0, false, nil
	}

	if !entry.PasswordDigest.Matches(password) {
		// Different password on positive entry - ALWAYS allow revalidation
		// User might have changed their password, or they're trying a wrong password.
		// Either way, we need to check with the database to verify.
		// Brute force protection is handled by protocol-level rate limiting, not by the cache.
		logger.Debug("Auth cache: positive entry revalidation allowed (different password)", "address", address, "age", time.Since(entry.CreatedAt))
		return 0, false, nil
	}

	// Entry is fresh and the password is the one it was created with - verify
	// against the cached bcrypt hash and return success
	if err := verifyPassword(entry.HashedPassword, password); err != nil {
		// Bcrypt verification failed even though the password digest matched
		// This shouldn't happen, but handle it by invalidating the cache
		c.Invalidate(address)
		return 0, false, nil
	}
	return entry.AccountID, true, nil
}

// SetSuccess caches a successful authentication result
func (c *LookupCache) SetSuccess(address string, accountID int64, hashedPassword string, password string) {
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
		PasswordDigest: NewPasswordDigest(password),
		Result:         AuthSuccess,
		CreatedAt:      now,
		ExpiresAt:      now.Add(c.positiveTTL),
	}

	metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))
}

// SetFailure caches a failed authentication result (user not found or invalid password)
// result parameter: 0 = success (ignored), 1 = user not found, 2 = invalid password
//
// No password digest is recorded: Authenticate revalidates every negative entry
// against the database regardless of which password is presented, so retaining
// anything derived from a failed guess (frequently a real password with a typo)
// would buy nothing and only widen what a memory disclosure yields.
func (c *LookupCache) SetFailure(address string, result int) {
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
		Result:     authResult,
		CreatedAt:  now,
		ExpiresAt:  now.Add(c.negativeTTL),
		IsNegative: true,
	}

	metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))
}

// Invalidate removes a specific entry from the cache (e.g., after password change).
// Safe to call on a nil receiver (no-op when the cache is disabled).
func (c *LookupCache) Invalidate(address string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, address)
	metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))
}

// InvalidateUser removes the entry for a serverName/username pair, using the
// same key derivation as Get/Set. Prefer this over Invalidate with a
// hand-built key so key formats can never drift apart.
// Safe to call on a nil receiver (no-op when the cache is disabled).
func (c *LookupCache) InvalidateUser(serverName, username string) {
	if c == nil {
		return
	}
	c.Invalidate(makeKey(serverName, username))
}

// evictOldest removes the oldest entry from the cache
// Caller must hold the write lock
func (c *LookupCache) evictOldest() {
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
func (c *LookupCache) cleanupLoop() {
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
func (c *LookupCache) cleanup() {
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
		logger.Info("LookupCache: Cleanup removed expired entries", "removed", removed, "remaining", len(c.entries))
		metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))
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
	counter := atomic.AddUint64(&c.cleanupCounter, 1)
	if counter%10 == 0 {
		hits := atomic.LoadUint64(&c.hits)
		misses := atomic.LoadUint64(&c.misses)
		total := hits + misses
		var hitRate float64
		if total > 0 {
			hitRate = float64(hits) / float64(total) * 100
		}

		logger.Info("LookupCache stats",
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
// No lock required - uses atomic operations
func (c *LookupCache) updateHitRateMetric() {
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	total := hits + misses
	if total > 0 {
		hitRate := float64(hits) / float64(total) * 100
		metrics.LookupCacheHitRate.Set(hitRate)
	}
}

// Stop stops the cleanup goroutine
func (c *LookupCache) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil // Already stopped
	}
	c.stopped = true
	c.mu.Unlock()

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
func (c *LookupCache) GetStats() (hits, misses uint64, size int, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits = atomic.LoadUint64(&c.hits)
	misses = atomic.LoadUint64(&c.misses)
	total := hits + misses
	var rate float64
	if total > 0 {
		rate = float64(hits) / float64(total) * 100
	}

	return hits, misses, len(c.entries), rate
}

// Clear removes all entries from the cache
func (c *LookupCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)

	logger.Info("LookupCache: Cache cleared")
}

// roundToTwoDecimals rounds a float to 2 decimal places
func roundToTwoDecimals(val float64) float64 {
	return float64(int(val*100+0.5)) / 100
}

// --- Methods for Proxy Usage ---

// Get retrieves a cached entry
// serverName should be the unique server name (e.g., "imap-proxy-1", "imap-backend")
// Returns the entry and whether it was found (and not expired).
// Safe to call on a nil receiver (always a miss when the cache is disabled).
func (c *LookupCache) Get(serverName, username string) (*CacheEntry, bool) {
	if c == nil {
		return nil, false
	}
	key := makeKey(serverName, username)

	c.mu.RLock()
	entry, exists := c.entries[key]
	var entryCopy CacheEntry
	if exists {
		entryCopy = *entry
	}
	c.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&c.misses, 1)
		metrics.LookupCacheMissesTotal.Inc()
		return nil, false
	}

	// Check if expired
	if time.Now().After(entryCopy.ExpiresAt) {
		atomic.AddUint64(&c.misses, 1)
		metrics.LookupCacheMissesTotal.Inc()
		return nil, false
	}

	atomic.AddUint64(&c.hits, 1)
	metrics.LookupCacheHitsTotal.Inc()
	return &entryCopy, true
}

// Set stores an entry in the cache.
// Safe to call on a nil receiver (no-op when the cache is disabled).
func (c *LookupCache) Set(serverName, username string, entry *CacheEntry) {
	if c == nil {
		return
	}
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
	metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))
}

// Refresh extends the TTL of an existing cache entry
// DO NOT USE. Use natural TTL expiration instead.
func (c *LookupCache) Refresh(serverName, username string) bool {
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

// GetOrFetch retrieves a cached entry, or if not found/expired, executes the fetchFn
// using singleflight to prevent thundering herd on cache misses.
//
// The fetchFn should return a *CacheEntry that will be cached automatically.
// Multiple concurrent requests for the same key will share the same fetchFn execution.
//
// This method is useful for both backends and proxies to prevent multiple simultaneous
// database/API queries when cache is cold or expired.
//
// Returns:
//   - entry: The cached or freshly fetched entry
//   - fromCache: true if retrieved from cache, false if fetched
//   - err: Any error from fetchFn
func (c *LookupCache) GetOrFetch(serverName, username string, fetchFn func() (*CacheEntry, error)) (*CacheEntry, bool, error) {
	key := makeKey(serverName, username)

	// Try cache first
	c.mu.RLock()
	entry, exists := c.entries[key]
	var entryCopy CacheEntry
	if exists {
		entryCopy = *entry
	}
	c.mu.RUnlock()

	if exists && !time.Now().After(entryCopy.ExpiresAt) {
		// Cache hit
		atomic.AddUint64(&c.hits, 1)
		metrics.LookupCacheHitsTotal.Inc()
		return &entryCopy, true, nil
	}

	// Cache miss or expired - use singleflight to prevent thundering herd
	atomic.AddUint64(&c.misses, 1)
	metrics.LookupCacheMissesTotal.Inc()

	// Use singleflight to ensure only one fetch per key
	result, err, shared := c.sfGroup.Do(key, func() (interface{}, error) {
		// Execute the fetch function
		fetchedEntry, fetchErr := fetchFn()
		if fetchErr != nil {
			return nil, fetchErr
		}

		// Cache the result
		c.mu.Lock()
		defer c.mu.Unlock()

		// Enforce max size with simple eviction (oldest entries first)
		if len(c.entries) >= c.maxSize {
			c.evictOldest()
		}

		// Store in cache
		c.entries[key] = fetchedEntry
		metrics.LookupCacheEntriesTotal.Set(float64(len(c.entries)))

		return fetchedEntry, nil
	})

	if err != nil {
		return nil, false, err
	}

	entry = result.(*CacheEntry)
	entryCopy = *entry

	// Log if this was a shared fetch (thundering herd prevented)
	if shared {
		logger.Debug("LookupCache: prevented thundering herd", "key", key)
		metrics.LookupCacheSharedFetchesTotal.Inc()
	}

	return &entryCopy, false, nil
}
