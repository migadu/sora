package server

import (
	"testing"
	"time"
)

// mockLookupCache implements LookupCacheInvalidator for testing
type mockLookupCache struct {
	invalidatedKeys []string
}

func (m *mockLookupCache) Invalidate(key string) {
	m.invalidatedKeys = append(m.invalidatedKeys, key)
}

// TestKickInvalidatesCache verifies that kick events invalidate the cache
func TestKickInvalidatesCache(t *testing.T) {
	// Create a connection tracker without cluster (local mode for testing)
	tracker := NewConnectionTracker("test-protocol", "", "", "test-instance", nil, 0, 0, 100, false)

	// Create a mock cache
	mockCache := &mockLookupCache{
		invalidatedKeys: []string{},
	}

	// Set the lookup cache
	tracker.SetLookupCache(mockCache)

	// Simulate a kick event
	kickEvent := ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "user@example.com",
		Protocol:  "IMAP",
		NodeID:    "node-1",
		Timestamp: time.Now(),
	}

	// Process the kick event
	tracker.handleKick(kickEvent)

	// Verify cache was invalidated
	if len(mockCache.invalidatedKeys) != 1 {
		t.Errorf("Expected 1 cache invalidation, got %d", len(mockCache.invalidatedKeys))
	}

	expectedKey := "test-protocol:user@example.com"
	if len(mockCache.invalidatedKeys) > 0 && mockCache.invalidatedKeys[0] != expectedKey {
		t.Errorf("Expected cache key %s, got %s", expectedKey, mockCache.invalidatedKeys[0])
	}

	t.Logf("✓ Kick event invalidated cache: %s", expectedKey)
}

// TestKickWithoutCacheDoesNotPanic verifies that kick works without a cache
func TestKickWithoutCacheDoesNotPanic(t *testing.T) {
	// Create a connection tracker without cache
	tracker := NewConnectionTracker("test-protocol", "", "", "test-instance", nil, 0, 0, 100, false)

	// Do NOT set lookup cache

	// Simulate a kick event
	kickEvent := ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "user@example.com",
		Protocol:  "IMAP",
		NodeID:    "node-1",
		Timestamp: time.Now(),
	}

	// Process the kick event - should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Kick panicked without cache: %v", r)
		}
	}()

	tracker.handleKick(kickEvent)
	t.Log("✓ Kick without cache did not panic")
}

// TestKickWithEmptyUsernameDoesNotInvalidate verifies that kick events
// without username don't attempt cache invalidation
func TestKickWithEmptyUsernameDoesNotInvalidate(t *testing.T) {
	tracker := NewConnectionTracker("test-protocol", "", "", "test-instance", nil, 0, 0, 100, false)

	mockCache := &mockLookupCache{
		invalidatedKeys: []string{},
	}
	tracker.SetLookupCache(mockCache)

	// Kick event with empty username
	kickEvent := ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 12345,
		Username:  "", // Empty username
		Protocol:  "IMAP",
		NodeID:    "node-1",
		Timestamp: time.Now(),
	}

	tracker.handleKick(kickEvent)

	// Verify cache was NOT invalidated
	if len(mockCache.invalidatedKeys) != 0 {
		t.Errorf("Expected 0 cache invalidations, got %d", len(mockCache.invalidatedKeys))
	}

	t.Log("✓ Kick with empty username did not invalidate cache")
}

// TestMultipleKicksInvalidateMultipleCaches tests kicking multiple users
func TestMultipleKicksInvalidateMultipleCaches(t *testing.T) {
	tracker := NewConnectionTracker("test-protocol", "", "", "test-instance", nil, 0, 0, 100, false)

	mockCache := &mockLookupCache{
		invalidatedKeys: []string{},
	}
	tracker.SetLookupCache(mockCache)

	// Kick multiple users
	users := []struct {
		accountID int64
		username  string
	}{
		{12345, "user1@example.com"},
		{67890, "user2@example.com"},
		{11111, "user3@example.com"},
	}

	for _, user := range users {
		kickEvent := ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: user.accountID,
			Username:  user.username,
			Protocol:  "IMAP",
			NodeID:    "node-1",
			Timestamp: time.Now(),
		}
		tracker.handleKick(kickEvent)
	}

	// Verify all caches were invalidated
	if len(mockCache.invalidatedKeys) != len(users) {
		t.Errorf("Expected %d cache invalidations, got %d", len(users), len(mockCache.invalidatedKeys))
	}

	// Verify correct keys
	for i, user := range users {
		expectedKey := "test-protocol:" + user.username
		if i < len(mockCache.invalidatedKeys) && mockCache.invalidatedKeys[i] != expectedKey {
			t.Errorf("Expected cache key %s, got %s", expectedKey, mockCache.invalidatedKeys[i])
		}
	}

	t.Logf("✓ Multiple kicks invalidated %d caches", len(mockCache.invalidatedKeys))
}
