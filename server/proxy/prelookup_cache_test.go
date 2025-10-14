package proxy

import (
	"context"
	"testing"
	"time"
)

func TestPrelookupCache(t *testing.T) {
	// Create cache with short TTLs for testing
	cache := newPrelookupCache(2*time.Second, 1*time.Second, 10, 500*time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cache.Stop(ctx)
	}()

	// Test positive cache
	t.Run("PositiveCache", func(t *testing.T) {
		info := &UserRoutingInfo{
			ServerAddress: "192.168.1.10:143",
			AccountID:     123,
		}

		// Set and get
		cache.Set("user1@example.com:pass123", info, AuthSuccess)
		gotInfo, authResult, found := cache.Get("user1@example.com:pass123")

		if !found {
			t.Fatal("Expected cache hit, got miss")
		}
		if authResult != AuthSuccess {
			t.Errorf("Expected AuthSuccess, got %v", authResult)
		}
		if gotInfo.ServerAddress != info.ServerAddress {
			t.Errorf("Expected server %s, got %s", info.ServerAddress, gotInfo.ServerAddress)
		}
	})

	// Test negative cache
	t.Run("NegativeCache", func(t *testing.T) {
		// Cache a failed auth
		cache.Set("baduser@example.com:wrongpass", nil, AuthFailed)
		_, authResult, found := cache.Get("baduser@example.com:wrongpass")

		if !found {
			t.Fatal("Expected cache hit for negative entry, got miss")
		}
		if authResult != AuthFailed {
			t.Errorf("Expected AuthFailed, got %v", authResult)
		}
	})

	// Test expiration
	t.Run("Expiration", func(t *testing.T) {
		info := &UserRoutingInfo{
			ServerAddress: "192.168.1.20:143",
			AccountID:     456,
		}

		// Set with positive TTL (2 seconds)
		cache.Set("tempuser@example.com:pass456", info, AuthSuccess)

		// Should exist immediately
		_, _, found := cache.Get("tempuser@example.com:pass456")
		if !found {
			t.Fatal("Expected cache hit immediately after set")
		}

		// Wait for expiration (2+ seconds)
		time.Sleep(2500 * time.Millisecond)

		// Should be expired
		_, _, found = cache.Get("tempuser@example.com:pass456")
		if found {
			t.Fatal("Expected cache miss after expiration")
		}
	})

	// Test negative cache expires faster
	t.Run("NegativeCacheExpiresFaster", func(t *testing.T) {
		// Set negative entry (1 second TTL)
		cache.Set("failuser@example.com:badpass", nil, AuthFailed)

		// Wait 1.5 seconds (past negative TTL, before positive TTL)
		time.Sleep(1500 * time.Millisecond)

		// Should be expired
		_, _, found := cache.Get("failuser@example.com:badpass")
		if found {
			t.Fatal("Expected negative cache entry to expire after 1.5 seconds")
		}
	})

	// Test max size eviction
	t.Run("MaxSizeEviction", func(t *testing.T) {
		smallCache := newPrelookupCache(10*time.Second, 10*time.Second, 3, 10*time.Second)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			smallCache.Stop(ctx)
		}()

		// Add 4 entries (exceeds max size of 3)
		for i := 1; i <= 4; i++ {
			info := &UserRoutingInfo{ServerAddress: "server", AccountID: int64(i)}
			smallCache.Set(string(rune('a'+i-1))+"@example.com:pass", info, AuthSuccess)
		}

		// Cache should have 3 entries (oldest evicted)
		_, _, size := smallCache.GetStats()
		if size != 3 {
			t.Errorf("Expected cache size 3, got %d", size)
		}
	})

	// Test stats
	t.Run("Stats", func(t *testing.T) {
		statsCache := newPrelookupCache(10*time.Second, 10*time.Second, 100, 10*time.Second)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			statsCache.Stop(ctx)
		}()

		info := &UserRoutingInfo{ServerAddress: "stats-server", AccountID: 999}
		statsCache.Set("stats@example.com:pass", info, AuthSuccess)

		// First get - miss then hit
		statsCache.Get("nonexistent@example.com:pass") // miss
		statsCache.Get("stats@example.com:pass")       // hit
		statsCache.Get("stats@example.com:pass")       // hit

		hits, misses, size := statsCache.GetStats()
		if hits != 2 {
			t.Errorf("Expected 2 hits, got %d", hits)
		}
		if misses != 1 {
			t.Errorf("Expected 1 miss, got %d", misses)
		}
		if size != 1 {
			t.Errorf("Expected size 1, got %d", size)
		}
	})
}
