package lookupcache

import (
	"context"
	"testing"
	"time"
)

// TestProxyMethods_GetSetRefresh tests the proxy-specific Get/Set/Refresh methods
func TestProxyMethods_GetSetRefresh(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 100, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	serverName := "imap-proxy-1"
	username := "user@example.com"

	// Test Get on empty cache
	entry, found := cache.Get(serverName, username)
	if found {
		t.Error("Expected cache miss on empty cache")
	}
	if entry != nil {
		t.Error("Expected nil entry on cache miss")
	}

	// Test Set
	testEntry := &CacheEntry{
		AccountID:              123,
		HashedPassword:         "hashed123",
		PasswordHash:           HashPassword("password123"),
		ServerAddress:          "backend1.example.com:993",
		RemoteTLS:              true,
		RemoteTLSUseStartTLS:   false,
		RemoteTLSVerify:        true,
		RemoteUseProxyProtocol: false,
		RemoteUseIDCommand:     true,
		RemoteUseXCLIENT:       false,
		Result:                 AuthSuccess,
		FromPrelookup:          true,
		CreatedAt:              time.Now(),
		ExpiresAt:              time.Now().Add(5 * time.Minute),
		IsNegative:             false,
	}

	cache.Set(serverName, username, testEntry)

	// Test Get after Set
	entry, found = cache.Get(serverName, username)
	if !found {
		t.Fatal("Expected cache hit after Set")
	}
	if entry == nil {
		t.Fatal("Expected non-nil entry")
	}

	// Verify all fields
	if entry.AccountID != 123 {
		t.Errorf("Expected AccountID 123, got %d", entry.AccountID)
	}
	if entry.ServerAddress != "backend1.example.com:993" {
		t.Errorf("Expected ServerAddress backend1.example.com:993, got %s", entry.ServerAddress)
	}
	if !entry.RemoteTLS {
		t.Error("Expected RemoteTLS to be true")
	}
	if !entry.RemoteUseIDCommand {
		t.Error("Expected RemoteUseIDCommand to be true")
	}
	if !entry.FromPrelookup {
		t.Error("Expected FromPrelookup to be true")
	}

	// Test different server name (should be different cache entry)
	entry2, found2 := cache.Get("imap-proxy-2", username)
	if found2 {
		t.Error("Expected cache miss for different server name")
	}
	if entry2 != nil {
		t.Error("Expected nil entry for different server")
	}

	// Test Refresh (extends TTL)
	time.Sleep(10 * time.Millisecond)
	refreshed := cache.Refresh(serverName, username)
	if !refreshed {
		t.Error("Expected Refresh to succeed")
	}

	// After refresh, entry should still be accessible
	entry, found = cache.Get(serverName, username)
	if !found {
		t.Error("Expected cache hit after Refresh")
	}

	// Test Refresh on non-existent entry
	refreshed = cache.Refresh(serverName, "nonexistent@example.com")
	if refreshed {
		t.Error("Expected Refresh to fail for non-existent entry")
	}

	// Test Get with empty server name (backend mode)
	backendEntry := &CacheEntry{
		AccountID:      456,
		HashedPassword: "hashed456",
		PasswordHash:   HashPassword("password456"),
		Result:         AuthSuccess,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
		IsNegative:     false,
	}
	cache.Set("", "backend-user@example.com", backendEntry)

	entry, found = cache.Get("", "backend-user@example.com")
	if !found {
		t.Error("Expected cache hit for backend mode (empty server name)")
	}
	if entry.AccountID != 456 {
		t.Errorf("Expected AccountID 456, got %d", entry.AccountID)
	}
}

// TestProxyMethods_ExpiredEntry tests that Get returns cache miss for expired entries
func TestProxyMethods_ExpiredEntry(t *testing.T) {
	cache := New(50*time.Millisecond, 50*time.Millisecond, 100, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	serverName := "proxy"
	username := "user@example.com"

	entry := &CacheEntry{
		AccountID:      789,
		HashedPassword: "hash789",
		PasswordHash:   HashPassword("pass789"),
		Result:         AuthSuccess,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(50 * time.Millisecond),
		IsNegative:     false,
	}

	cache.Set(serverName, username, entry)

	// Immediate get should work
	_, found := cache.Get(serverName, username)
	if !found {
		t.Error("Expected cache hit immediately after Set")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Get should return cache miss
	_, found = cache.Get(serverName, username)
	if found {
		t.Error("Expected cache miss for expired entry")
	}
}

// TestProxyMethods_NegativeCache tests negative caching in proxy methods
func TestProxyMethods_NegativeCache(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 100, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	serverName := "proxy"
	username := "notfound@example.com"

	// Cache a negative result (user not found)
	negativeEntry := &CacheEntry{
		AccountID:      0,
		HashedPassword: "",
		PasswordHash:   HashPassword("wrongpass"),
		Result:         AuthUserNotFound,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Minute),
		IsNegative:     true,
	}

	cache.Set(serverName, username, negativeEntry)

	// Retrieve negative entry
	entry, found := cache.Get(serverName, username)
	if !found {
		t.Error("Expected to find negative cache entry")
	}
	if entry.Result != AuthUserNotFound {
		t.Errorf("Expected Result AuthUserNotFound, got %v", entry.Result)
	}
	if !entry.IsNegative {
		t.Error("Expected IsNegative to be true")
	}
}

// TestClear tests the Clear method
func TestClear(t *testing.T) {
	cache := New(5*time.Minute, 1*time.Minute, 100, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	// Add several entries
	for i := 0; i < 10; i++ {
		entry := &CacheEntry{
			AccountID:      int64(i),
			HashedPassword: "hash",
			PasswordHash:   HashPassword("pass"),
			Result:         AuthSuccess,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(5 * time.Minute),
			IsNegative:     false,
		}
		cache.Set("server", "user"+string(rune(i))+"@example.com", entry)
	}

	// Verify entries exist
	hits, misses, size, _ := cache.GetStats()
	if size != 10 {
		t.Errorf("Expected cache size 10, got %d", size)
	}

	initialHits := hits
	initialMisses := misses

	// Clear the cache
	cache.Clear()

	// Verify cache is empty
	hits, misses, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected cache size 0 after Clear, got %d", size)
	}
	if hits != 0 {
		t.Errorf("Expected hits to be reset to 0, got %d", hits)
	}
	if misses != 0 {
		t.Errorf("Expected misses to be reset to 0, got %d", misses)
	}

	// Verify entries are gone
	_, found := cache.Get("server", "user0@example.com")
	if found {
		t.Error("Expected cache miss after Clear")
	}

	t.Logf("Clear successfully removed %d entries and reset stats (hits: %d->0, misses: %d->0)",
		10, initialHits, initialMisses)
}

// TestMakeKey tests the makeKey function edge cases
func TestMakeKey(t *testing.T) {
	tests := []struct {
		serverName string
		username   string
		expected   string
	}{
		{"imap-proxy-1", "user@example.com", "imap-proxy-1:user@example.com"},
		{"", "user@example.com", "user@example.com"}, // Backend mode
		{"proxy", "", "proxy:"},                      // Empty username (edge case)
		{"", "", ""},                                 // Both empty (edge case)
		{"server:with:colons", "user", "server:with:colons:user"},
	}

	for _, tt := range tests {
		result := makeKey(tt.serverName, tt.username)
		if result != tt.expected {
			t.Errorf("makeKey(%q, %q) = %q, expected %q",
				tt.serverName, tt.username, result, tt.expected)
		}
	}
}

// TestHashPassword tests HashPassword edge cases
func TestHashPassword(t *testing.T) {
	// Empty password
	hash1 := HashPassword("")
	if hash1 != "" {
		t.Error("Expected empty string for empty password")
	}

	// Same password should produce same hash
	hash2 := HashPassword("testpass123")
	hash3 := HashPassword("testpass123")
	if hash2 != hash3 {
		t.Error("Same password should produce same hash")
	}

	// Different passwords should produce different hashes
	hash4 := HashPassword("different")
	if hash2 == hash4 {
		t.Error("Different passwords should produce different hashes")
	}

	// Hash should be deterministic and 64 characters (SHA-256 hex)
	if len(hash2) != 64 {
		t.Errorf("Expected 64 character hash, got %d", len(hash2))
	}

	// Unicode/special characters
	hash5 := HashPassword("пароль中文🔐")
	if hash5 == "" {
		t.Error("Expected non-empty hash for unicode password")
	}
	if len(hash5) != 64 { // SHA-256 produces 64 hex characters
		t.Errorf("Expected 64 character hex string, got %d", len(hash5))
	}
}

// TestProxyMethods_MaxSizeEviction tests that Set respects max size
func TestProxyMethods_MaxSizeEviction(t *testing.T) {
	maxSize := 5
	cache := New(5*time.Minute, 1*time.Minute, maxSize, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	// Add entries up to max size
	for i := 0; i < maxSize; i++ {
		entry := &CacheEntry{
			AccountID:      int64(i),
			HashedPassword: "hash",
			PasswordHash:   HashPassword("pass"),
			Result:         AuthSuccess,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(5 * time.Minute),
			IsNegative:     false,
		}
		cache.Set("server", "user"+string(rune('0'+i))+"@example.com", entry)
		time.Sleep(1 * time.Millisecond) // Ensure different CreatedAt times
	}

	_, _, size, _ := cache.GetStats()
	if size != maxSize {
		t.Errorf("Expected cache size %d, got %d", maxSize, size)
	}

	// Add one more entry - should evict the oldest
	entry := &CacheEntry{
		AccountID:      999,
		HashedPassword: "hash999",
		PasswordHash:   HashPassword("pass999"),
		Result:         AuthSuccess,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
		IsNegative:     false,
	}
	cache.Set("server", "newest@example.com", entry)

	_, _, size, _ = cache.GetStats()
	if size != maxSize {
		t.Errorf("Expected cache size to remain at %d after eviction, got %d", maxSize, size)
	}

	// The oldest entry (user0) should be gone
	_, found := cache.Get("server", "user0@example.com")
	if found {
		t.Error("Expected oldest entry to be evicted")
	}

	// The newest entry should exist
	_, found = cache.Get("server", "newest@example.com")
	if !found {
		t.Error("Expected newest entry to exist")
	}
}

// TestRefresh_TTLExtension tests that Refresh extends the TTL correctly
func TestRefresh_TTLExtension(t *testing.T) {
	positiveTTL := 100 * time.Millisecond
	negativeTTL := 50 * time.Millisecond
	cache := New(positiveTTL, negativeTTL, 100, 1*time.Minute, 30*time.Second)
	defer cache.Stop(context.Background())

	serverName := "server"
	username := "user@example.com"

	// Add positive entry
	entry := &CacheEntry{
		AccountID:      123,
		HashedPassword: "hash",
		PasswordHash:   HashPassword("pass"),
		Result:         AuthSuccess,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(positiveTTL),
		IsNegative:     false,
	}
	cache.Set(serverName, username, entry)

	// Wait halfway through TTL
	time.Sleep(50 * time.Millisecond)

	// Refresh should extend TTL
	refreshed := cache.Refresh(serverName, username)
	if !refreshed {
		t.Error("Expected Refresh to succeed")
	}

	// Wait for original TTL to expire
	time.Sleep(70 * time.Millisecond) // Total: 120ms > 100ms original TTL

	// Entry should still be valid because Refresh extended it
	_, found := cache.Get(serverName, username)
	if !found {
		t.Error("Expected entry to still be valid after Refresh extended TTL")
	}

	// Test negative entry TTL extension
	negativeEntry := &CacheEntry{
		AccountID:      0,
		HashedPassword: "",
		PasswordHash:   HashPassword("wrong"),
		Result:         AuthFailed,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(negativeTTL),
		IsNegative:     true,
	}
	cache.Set(serverName, "negative@example.com", negativeEntry)

	time.Sleep(25 * time.Millisecond)
	refreshed = cache.Refresh(serverName, "negative@example.com")
	if !refreshed {
		t.Error("Expected Refresh to succeed for negative entry")
	}

	time.Sleep(40 * time.Millisecond) // Total: 65ms > 50ms original TTL
	_, found = cache.Get(serverName, "negative@example.com")
	if !found {
		t.Error("Expected negative entry to still be valid after Refresh")
	}
}
