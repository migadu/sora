package server

import (
	"sync"
	"testing"
	"time"
)

// fakeLookupCache stands in for pkg/lookupcache.LookupCache, which this package
// cannot import because lookupcache imports it. It mirrors the entry points of
// the real cache, and derives keys exactly as lookupcache.makeKey does, so a
// tracker that invalidates by a key of its own making is caught here. Entries
// added with newFakeLookupCache belong to no account, so only a key reaches them.
type fakeLookupCache struct {
	mu                  sync.Mutex
	entries             map[string]int64 // key -> account the entry signs in
	invalidatedKeys     []string
	invalidatedAccounts []int64
}

func newFakeLookupCache(keys ...string) *fakeLookupCache {
	c := &fakeLookupCache{entries: make(map[string]int64, len(keys))}
	for _, key := range keys {
		c.entries[key] = 0
	}
	return c
}

func (f *fakeLookupCache) add(key string, accountID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key] = accountID
}

func (f *fakeLookupCache) Invalidate(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidatedKeys = append(f.invalidatedKeys, key)
	delete(f.entries, key)
}

func (f *fakeLookupCache) InvalidateUser(serverName, username string) {
	f.Invalidate(lookupCacheKey(serverName, username))
}

func (f *fakeLookupCache) InvalidateAccount(accountID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidatedAccounts = append(f.invalidatedAccounts, accountID)
	for key, account := range f.entries {
		if account == accountID {
			delete(f.entries, key)
		}
	}
}

func (f *fakeLookupCache) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// TestKickWithEmptyUsernameDropsTheAccountOnly verifies that a kick event
// without a username - the issuing node held no session, so it knew none - makes
// up no key, and still drops every entry of the account: whoever was kicked must
// not sign straight back in from the cache.
func TestKickWithEmptyUsernameDropsTheAccountOnly(t *testing.T) {
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)

	cachedKey := lookupCacheKey(kickCacheServerName, "user@example.com")
	cache := newFakeLookupCache()
	cache.add(cachedKey, 12345)
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
		t.Errorf("a kick without a username invalidated keys %q", cache.invalidatedKeys)
	}
	if cache.has(cachedKey) {
		t.Errorf("kicked account keeps its cached login %q", cachedKey)
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
		cache.add(lookupCacheKey(kickCacheServerName, user.username), 0)
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

// TestForgetLoginsLeavesSessions verifies that forgetting an account's logins
// drops its cached entries under every address, and ends no session.
func TestForgetLoginsLeavesSessions(t *testing.T) {
	const accountID int64 = 12345
	tracker := NewConnectionTracker(kickCacheProtocol, kickCacheServerName, "", "test-instance", nil, 0, 0, 100, false)
	defer tracker.Stop()

	changed := lookupCacheKey(kickCacheServerName, "user@example.com")
	alias := lookupCacheKey(kickCacheServerName, "alias@example.com")
	other := lookupCacheKey(kickCacheServerName, "other@example.com")
	cache := newFakeLookupCache(changed)
	cache.add(alias, accountID)
	cache.add(other, 67890)
	tracker.SetLookupCache(cache)

	session := tracker.RegisterSession(accountID)

	if err := tracker.ForgetLogins(accountID, "user@example.com"); err != nil {
		t.Fatalf("ForgetLogins: %v", err)
	}

	for _, key := range []string{changed, alias} {
		if cache.has(key) {
			t.Errorf("forgotten account keeps its cached login %q", key)
		}
	}
	if !cache.has(other) {
		t.Errorf("another account's cached login %q was dropped", other)
	}
	select {
	case <-session:
		t.Error("forgetting logins ended the account's session")
	default:
	}
}
