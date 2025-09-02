package lmtp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/server/sieveengine"
)

// SieveScriptCacheEntry represents a cached parsed Sieve script
type SieveScriptCacheEntry struct {
	executor   sieveengine.Executor
	lastAccess time.Time
	createdAt  time.Time // When this entry was cached
	scriptID   int64     // Script ID from database
	updatedAt  time.Time // Last update time from database
}

// SieveScriptCache implements an LRU cache for parsed Sieve scripts with TTL
type SieveScriptCache struct {
	mu          sync.RWMutex
	cache       map[string]*SieveScriptCacheEntry
	maxEntries  int
	ttl         time.Duration // Time to live for cache entries
	accessOrder []string      // Track access order for LRU eviction
}

// NewSieveScriptCache creates a new Sieve script cache with the specified maximum entries and TTL
func NewSieveScriptCache(maxEntries int, ttl time.Duration) *SieveScriptCache {
	return &SieveScriptCache{
		cache:       make(map[string]*SieveScriptCacheEntry),
		maxEntries:  maxEntries,
		ttl:         ttl,
		accessOrder: make([]string, 0, maxEntries),
	}
}

// hashScript creates a hash of the script content for use as a cache key
func hashScript(script string) string {
	h := sha256.New()
	h.Write([]byte(script))
	return hex.EncodeToString(h.Sum(nil))
}

// Get retrieves a parsed Sieve script from the cache
func (c *SieveScriptCache) Get(scriptContent string) (sieveengine.Executor, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := hashScript(scriptContent)
	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	// Check if entry has expired based on TTL
	if time.Since(entry.createdAt) > c.ttl {
		// Remove expired entry
		delete(c.cache, key)
		c.removeFromAccessOrder(key)
		return nil, false
	}

	// Update last access time and move to end of access order
	entry.lastAccess = time.Now()
	c.updateAccessOrder(key)

	return entry.executor, true
}

// Put stores a parsed Sieve script in the cache
func (c *SieveScriptCache) Put(scriptContent string, executor sieveengine.Executor) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := hashScript(scriptContent)
	now := time.Now()

	// Check if already exists
	if _, exists := c.cache[key]; exists {
		c.updateAccessOrder(key)
		return
	}

	// Evict oldest entry if at capacity
	if len(c.cache) >= c.maxEntries && c.maxEntries > 0 {
		c.evictOldest()
	}

	// Add new entry
	c.cache[key] = &SieveScriptCacheEntry{
		executor:   executor,
		lastAccess: now,
		createdAt:  now,
	}
	c.accessOrder = append(c.accessOrder, key)
}

// PutWithMetadata stores a parsed Sieve script in the cache with metadata
func (c *SieveScriptCache) PutWithMetadata(scriptContent string, executor sieveengine.Executor, scriptID int64, updatedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := hashScript(scriptContent)
	now := time.Now()

	// Check if already exists
	if entry, exists := c.cache[key]; exists {
		// Update metadata if newer
		if updatedAt.After(entry.updatedAt) {
			entry.scriptID = scriptID
			entry.updatedAt = updatedAt
			entry.createdAt = now
		}
		c.updateAccessOrder(key)
		return
	}

	// Evict oldest entry if at capacity
	if len(c.cache) >= c.maxEntries && c.maxEntries > 0 {
		c.evictOldest()
	}

	// Add new entry
	c.cache[key] = &SieveScriptCacheEntry{
		executor:   executor,
		lastAccess: now,
		createdAt:  now,
		scriptID:   scriptID,
		updatedAt:  updatedAt,
	}
	c.accessOrder = append(c.accessOrder, key)
}

// updateAccessOrder moves the key to the end of the access order list
func (c *SieveScriptCache) updateAccessOrder(key string) {
	// Find and remove the key from its current position
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
	// Add to the end
	c.accessOrder = append(c.accessOrder, key)
}

// removeFromAccessOrder removes a key from the access order list
func (c *SieveScriptCache) removeFromAccessOrder(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
}

// evictOldest removes the least recently used entry from the cache
func (c *SieveScriptCache) evictOldest() {
	if len(c.accessOrder) == 0 {
		return
	}

	oldestKey := c.accessOrder[0]
	delete(c.cache, oldestKey)
	c.accessOrder = c.accessOrder[1:]
}

// Clear removes all entries from the cache
func (c *SieveScriptCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*SieveScriptCacheEntry)
	c.accessOrder = make([]string, 0, c.maxEntries)
}

// Size returns the current number of cached entries
func (c *SieveScriptCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// GetOrCreate attempts to get a cached executor, or creates and caches it if not found
func (c *SieveScriptCache) GetOrCreate(scriptContent string, userID int64, oracle sieveengine.VacationOracle) (sieveengine.Executor, error) {
	// Try to get from cache first
	if executor, found := c.Get(scriptContent); found {
		return executor, nil
	}

	// Create new executor
	executor, err := sieveengine.NewSieveExecutorWithOracle(scriptContent, userID, oracle)
	if err != nil {
		return nil, fmt.Errorf("failed to create sieve executor: %w", err)
	}

	// Cache it
	c.Put(scriptContent, executor)

	return executor, nil
}

// GetOrCreateWithMetadata attempts to get a cached executor with validation, or creates and caches it if not found
func (c *SieveScriptCache) GetOrCreateWithMetadata(scriptContent string, scriptID int64, updatedAt time.Time, userID int64, oracle sieveengine.VacationOracle) (sieveengine.Executor, error) {
	c.mu.Lock()

	key := hashScript(scriptContent)
	entry, exists := c.cache[key]

	// Check if we have a valid cached entry
	if exists {
		// Check TTL
		if time.Since(entry.createdAt) <= c.ttl {
			// Check if this is the same script version
			if entry.scriptID == scriptID && !updatedAt.After(entry.updatedAt) {
				// Valid cache hit
				entry.lastAccess = time.Now()
				c.updateAccessOrder(key)
				c.mu.Unlock()
				return entry.executor, nil
			}
		}
		// Invalid or outdated entry, remove it
		delete(c.cache, key)
		c.removeFromAccessOrder(key)
	}

	c.mu.Unlock()

	// Create new executor
	executor, err := sieveengine.NewSieveExecutorWithOracle(scriptContent, userID, oracle)
	if err != nil {
		return nil, fmt.Errorf("failed to create sieve executor: %w", err)
	}

	// Cache it with metadata
	c.PutWithMetadata(scriptContent, executor, scriptID, updatedAt)

	return executor, nil
}

// CleanExpired removes all expired entries from the cache
func (c *SieveScriptCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var keysToRemove []string

	for key, entry := range c.cache {
		if now.Sub(entry.createdAt) > c.ttl {
			keysToRemove = append(keysToRemove, key)
		}
	}

	for _, key := range keysToRemove {
		delete(c.cache, key)
		c.removeFromAccessOrder(key)
	}
}
