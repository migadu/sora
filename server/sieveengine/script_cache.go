package sieveengine

import (
	"strings"
	"sync"
	"time"
)

// ScriptCache keeps compiled Sieve scripts around so a script is parsed once per version
// instead of once per delivered message.
//
// CompileScript is a pure function of the script text and the enabled extension set, so
// entries are keyed on exactly those two things: a hit can only ever return the
// compilation of the text the caller asked to compile. Keying on the database's
// (script id, updated_at) instead would make every hit depend on every writer
// remembering to bump updated_at, and the failure mode there is silent - a compiled copy
// of a script the user has already replaced keeps filing their mail. Both callers have
// already read the script row by the time they get here, so addressing by content costs
// nothing extra. The price is that entries pin the script text (bounded: maxEntries
// times the ManageSieve/User API script size cap).
//
// It is safe for concurrent use.
type ScriptCache struct {
	mu         sync.Mutex
	entries    map[scriptCacheKey]*scriptCacheEntry
	order      []scriptCacheKey // least recently used first
	maxEntries int
	ttl        time.Duration
	hits       uint64
	misses     uint64
}

type scriptCacheKey struct {
	script     string
	extensions string
}

type scriptCacheEntry struct {
	compiled *CompiledScript
	cachedAt time.Time
}

const (
	defaultScriptCacheEntries = 100
	defaultScriptCacheTTL     = 5 * time.Minute
)

// sharedScriptCache backs every delivery path in the process. One cache means a script
// compiled for an LMTP delivery is reused by an Admin API delivery of the next message
// for the same account, and - more importantly - that the two paths can never hold two
// different compilations of one script and file the same user's mail differently.
var sharedScriptCache = NewScriptCache(defaultScriptCacheEntries, defaultScriptCacheTTL)

// SharedScriptCache returns the process-wide compiled-script cache. Delivery paths must
// compile through it rather than keeping a cache of their own.
func SharedScriptCache() *ScriptCache { return sharedScriptCache }

// NewScriptCache creates a cache holding at most maxEntries compiled scripts, each
// recompiled after ttl at the latest.
func NewScriptCache(maxEntries int, ttl time.Duration) *ScriptCache {
	return &ScriptCache{
		entries:    make(map[scriptCacheKey]*scriptCacheEntry),
		order:      make([]scriptCacheKey, 0, maxEntries),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// GetOrCompile returns the compiled form of scriptContent, either from the cache or by
// compiling it. The result is not bound to any account: callers turn it into an executor
// for the account being delivered to with CompiledScript.NewExecutor.
func (c *ScriptCache) GetOrCompile(scriptContent string, enabledExtensions []string) (*CompiledScript, error) {
	key := scriptCacheKey{script: scriptContent, extensions: strings.Join(enabledExtensions, ",")}

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		if time.Since(entry.cachedAt) <= c.ttl {
			c.hits++
			c.touch(key)
			c.mu.Unlock()
			return entry.compiled, nil
		}
		c.remove(key)
	}
	c.misses++
	c.mu.Unlock()

	// Compiling outside the lock lets concurrent deliveries for different accounts
	// proceed; the worst case is that two of them compile the same script once each.
	compiled, err := CompileScript(scriptContent, enabledExtensions)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.remove(c.order[0])
	}
	c.entries[key] = &scriptCacheEntry{compiled: compiled, cachedAt: time.Now()}
	c.touch(key)

	return compiled, nil
}

// Stats reports how many GetOrCompile calls were served from the cache and how many had
// to compile. A hit and a miss are behaviourally identical by construction, so this is
// the only way to observe that a parse was skipped.
func (c *ScriptCache) Stats() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// touch moves key to the most-recently-used end of the order. Callers hold c.mu.
func (c *ScriptCache) touch(key scriptCacheKey) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, key)
}

// remove drops an entry and its order slot. Callers hold c.mu.
func (c *ScriptCache) remove(key scriptCacheKey) {
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
