package server

import (
	"testing"
	"time"
)

// fakeLookupCache stands in for pkg/lookupcache.LookupCache, which this package
// cannot import because lookupcache imports it. It mirrors both entry points of
// the real cache, and derives keys exactly as lookupcache.makeKey does, so a
// tracker that invalidates by a key of its own making is caught here.
type fakeLookupCache struct {
	entries         map[string]struct{}
	invalidatedKeys []string
}

func newFakeLookupCache(keys ...string) *fakeLookupCache {
	c := &fakeLookupCache{entries: make(map[string]struct{}, len(keys))}
	for _, key := range keys {
		c.entries[key] = struct{}{}
	}
	return c
}

func (f *fakeLookupCache) Invalidate(key string) {
	f.invalidatedKeys = append(f.invalidatedKeys, key)
	delete(f.entries, key)
}

func (f *fakeLookupCache) InvalidateUser(serverName, username string) {
	f.Invalidate(lookupCacheKey(serverName, username))
}

func (f *fakeLookupCache) has(key string) bool {
	_, ok := f.entries[key]
	return ok
}

// lookupCacheKey is lookupcache.makeKey.
func lookupCacheKey(serverName, username string) string {
	if serverName == "" {
		return username
	}
	return serverName + ":" + username
}

// The proxies key their lookup cache by the name of the server the session is
// on, not by the protocol: an entry written by the IMAP proxy named
// "imap-proxy-1" lives under "imap-proxy-1:user@example.com".
const (
	kickCacheProtocol   = "IMAP"
	kickCacheServerName = "imap-proxy-1"
)

// TestKickInvalidatesCache verifies that a kick drops the entry the proxy
// cached for that user, so that the reconnect is looked up afresh.
func TestKickInvalidatesCache(t *testing.T) {
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)

	cachedKey := lookupCacheKey(kickCacheServerName, "user@example.com")
	cache := newFakeLookupCache(cachedKey)
	tracker.SetLookupCache(cache)

	tracker.handleKick(ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "user@example.com",
		Protocol:  kickCacheProtocol,
		NodeID:    "node-1",
		Timestamp: time.Now(),
	})

	if cache.has(cachedKey) {
		t.Errorf("kicked user keeps a cached lookup entry: %q survived, invalidated %q instead - "+
			"the kicked session reconnects on stale routing and auth", cachedKey, cache.invalidatedKeys)
	}
}

// TestKickWithoutCacheDoesNotPanic verifies that kick works without a cache
func TestKickWithoutCacheDoesNotPanic(t *testing.T) {
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)

	// Do NOT set lookup cache

	kickEvent := ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "user@example.com",
		Protocol:  kickCacheProtocol,
		NodeID:    "node-1",
		Timestamp: time.Now(),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Kick panicked without cache: %v", r)
		}
	}()

	tracker.handleKick(kickEvent)
}

// TestKickWithEmptyUsernameDoesNotInvalidate verifies that kick events
// without username don't attempt cache invalidation
func TestKickWithEmptyUsernameDoesNotInvalidate(t *testing.T) {
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)

	cache := newFakeLookupCache()
	tracker.SetLookupCache(cache)

	kickEvent := ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "", // Empty username
		Protocol:  kickCacheProtocol,
		NodeID:    "node-1",
		Timestamp: time.Now(),
	}

	tracker.handleKick(kickEvent)

	if len(cache.invalidatedKeys) != 0 {
		t.Errorf("Expected 0 cache invalidations, got %d", len(cache.invalidatedKeys))
	}
}

// TestMultipleKicksInvalidateMultipleCaches tests kicking multiple users
func TestMultipleKicksInvalidateMultipleCaches(t *testing.T) {
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)

	users := []struct {
		accountID int64
		username  string
	}{
		{12345, "user1@example.com"},
		{67890, "user2@example.com"},
		{11111, "user3@example.com"},
	}

	cache := newFakeLookupCache()
	for _, user := range users {
		cache.entries[lookupCacheKey(kickCacheServerName, user.username)] = struct{}{}
	}
	tracker.SetLookupCache(cache)

	for _, user := range users {
		tracker.handleKick(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: user.accountID,
			Username:  user.username,
			Protocol:  kickCacheProtocol,
			NodeID:    "node-1",
			Timestamp: time.Now(),
		})
	}

	for _, user := range users {
		if key := lookupCacheKey(kickCacheServerName, user.username); cache.has(key) {
			t.Errorf("kicked user keeps a cached lookup entry: %q survived", key)
		}
	}
}
