package server

import (
	"sync"
)

// RateLimiterRegistry provides a global registry for auth rate limiters
// This allows the Admin API to query blocked IPs across all protocol servers
type RateLimiterRegistry struct {
	mu       sync.RWMutex
	limiters map[string]*AuthRateLimiter // key: "protocol:server_name"
}

var globalRateLimiterRegistry = &RateLimiterRegistry{
	limiters: make(map[string]*AuthRateLimiter),
}

// RegisterRateLimiter registers a rate limiter with the global registry
func RegisterRateLimiter(protocol, serverName string, limiter *AuthRateLimiter) {
	if limiter == nil {
		return
	}
	key := protocol + ":" + serverName
	globalRateLimiterRegistry.mu.Lock()
	globalRateLimiterRegistry.limiters[key] = limiter
	globalRateLimiterRegistry.mu.Unlock()
}

// UnregisterRateLimiter removes a rate limiter from the global registry
func UnregisterRateLimiter(protocol, serverName string) {
	key := protocol + ":" + serverName
	globalRateLimiterRegistry.mu.Lock()
	delete(globalRateLimiterRegistry.limiters, key)
	globalRateLimiterRegistry.mu.Unlock()
}

// GetAllBlockedEntries returns all blocked entries from all registered rate limiters
func GetAllBlockedEntries() []BlockedEntry {
	globalRateLimiterRegistry.mu.RLock()
	defer globalRateLimiterRegistry.mu.RUnlock()

	allEntries := make([]BlockedEntry, 0)
	for _, limiter := range globalRateLimiterRegistry.limiters {
		entries := limiter.GetBlockedEntries()
		allEntries = append(allEntries, entries...)
	}
	return deduplicateBlockedEntries(allEntries)
}

// GetBlockedEntriesByProtocol returns blocked entries for a specific protocol
func GetBlockedEntriesByProtocol(protocol string) []BlockedEntry {
	globalRateLimiterRegistry.mu.RLock()
	defer globalRateLimiterRegistry.mu.RUnlock()

	allEntries := make([]BlockedEntry, 0)
	for key, limiter := range globalRateLimiterRegistry.limiters {
		// Check if key starts with protocol prefix
		if len(key) > len(protocol) && key[:len(protocol)] == protocol && key[len(protocol)] == ':' {
			entries := limiter.GetBlockedEntries()
			allEntries = append(allEntries, entries...)
		}
	}
	return deduplicateBlockedEntries(allEntries)
}

type blockedIPKey struct {
	protocol string
	ip       string
}

func mergeBlockedIPEntry(existing, candidate BlockedEntry) BlockedEntry {
	if candidate.BlockedUntil.After(existing.BlockedUntil) {
		existing.BlockedUntil = candidate.BlockedUntil
	}
	if candidate.FailureCount > existing.FailureCount {
		existing.FailureCount = candidate.FailureCount
	}
	if !candidate.FirstFailure.IsZero() && (existing.FirstFailure.IsZero() || candidate.FirstFailure.Before(existing.FirstFailure)) {
		existing.FirstFailure = candidate.FirstFailure
	}
	if candidate.LastFailure.After(existing.LastFailure) {
		existing.LastFailure = candidate.LastFailure
	}
	return existing
}

// deduplicateBlockedEntries collapses shared Tier-2 IP blocks (Type == "ip")
// replicated across multiple listeners of the same protocol on one node while
// preserving distinct protocols and listener-local Tier-1 ("ip_username") entries.
func deduplicateBlockedEntries(entries []BlockedEntry) []BlockedEntry {
	if len(entries) == 0 {
		return make([]BlockedEntry, 0)
	}
	result := make([]BlockedEntry, 0, len(entries))
	ipIndex := make(map[blockedIPKey]int)
	for _, entry := range entries {
		if entry.Type != "ip" {
			result = append(result, entry)
			continue
		}
		key := blockedIPKey{protocol: entry.Protocol, ip: entry.IP}
		if idx, exists := ipIndex[key]; exists {
			result[idx] = mergeBlockedIPEntry(result[idx], entry)
			continue
		}
		ipIndex[key] = len(result)
		result = append(result, entry)
	}
	return result
}
