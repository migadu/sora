package proxy

import (
	"context"
	"fmt"
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

	// Test password hash storage and retrieval
	t.Run("PasswordHashStorage", func(t *testing.T) {
		info := &UserRoutingInfo{
			ServerAddress: "192.168.1.30:143",
			AccountID:     789,
		}

		// Store with password hash
		passwordHash := "{SSHA512}somehash"
		cache.SetWithHash("user@example.com", info, AuthSuccess, passwordHash)

		// Retrieve password hash
		retrievedHash, found := cache.GetPasswordHash("user@example.com")
		if !found {
			t.Fatal("Expected to find password hash")
		}
		if retrievedHash != passwordHash {
			t.Errorf("Expected hash %s, got %s", passwordHash, retrievedHash)
		}

		// Retrieve full entry
		gotInfo, authResult, found := cache.Get("user@example.com")
		if !found {
			t.Fatal("Expected cache hit")
		}
		if authResult != AuthSuccess {
			t.Errorf("Expected AuthSuccess, got %v", authResult)
		}
		if gotInfo.ServerAddress != info.ServerAddress {
			t.Errorf("Expected server %s, got %s", info.ServerAddress, gotInfo.ServerAddress)
		}
	})

	// Test cache invalidation
	t.Run("CacheInvalidation", func(t *testing.T) {
		info := &UserRoutingInfo{
			ServerAddress: "192.168.1.40:143",
			AccountID:     890,
		}

		// Store with password hash
		cache.SetWithHash("testuser@example.com", info, AuthSuccess, "{SSHA512}oldhash")

		// Verify it's in cache
		_, found := cache.GetPasswordHash("testuser@example.com")
		if !found {
			t.Fatal("Expected to find cached entry")
		}

		// Delete/invalidate cache
		cache.Delete("testuser@example.com")

		// Verify it's gone
		_, found = cache.GetPasswordHash("testuser@example.com")
		if found {
			t.Fatal("Expected cache entry to be deleted")
		}
	})

	// Test cleanup removes expired entries and prevents memory growth
	t.Run("CleanupRemovesExpiredEntries", func(t *testing.T) {
		// Create cache with very short TTL and fast cleanup
		cleanupCache := newPrelookupCache(500*time.Millisecond, 500*time.Millisecond, 1000, 100*time.Millisecond)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cleanupCache.Stop(ctx)
		}()

		// Add 100 entries
		for i := 0; i < 100; i++ {
			info := &UserRoutingInfo{
				ServerAddress: "server",
				AccountID:     int64(i),
			}
			key := fmt.Sprintf("user%d@example.com", i)
			cleanupCache.SetWithHash(key, info, AuthSuccess, "{SSHA512}hash")
		}

		// Verify we have 100 entries
		_, _, size := cleanupCache.GetStats()
		if size != 100 {
			t.Errorf("Expected 100 entries, got %d", size)
		}
		t.Logf("Initial cache size: %d", size)

		// Wait for entries to expire (500ms TTL + 100ms buffer)
		time.Sleep(600 * time.Millisecond)

		// Wait for cleanup to run (cleanup interval is 100ms)
		// Give it 2 cleanup cycles to be safe
		time.Sleep(250 * time.Millisecond)

		// Verify entries were cleaned up
		_, _, sizeAfter := cleanupCache.GetStats()
		if sizeAfter != 0 {
			t.Errorf("Expected 0 entries after cleanup, got %d - MEMORY LEAK!", sizeAfter)
		}
		t.Logf("Cache size after cleanup: %d (cleaned up %d entries)", sizeAfter, size-sizeAfter)
	})

	// Test continuous cleanup doesn't let memory grow
	t.Run("ContinuousCleanupPreventsMemoryGrowth", func(t *testing.T) {
		// Create cache with short TTL and frequent cleanup
		growthCache := newPrelookupCache(200*time.Millisecond, 200*time.Millisecond, 10000, 50*time.Millisecond)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			growthCache.Stop(ctx)
		}()

		// Simulate continuous login attempts over 1 second
		// This simulates real-world scenario where users login continuously
		done := make(chan bool)
		go func() {
			for i := 0; i < 200; i++ {
				info := &UserRoutingInfo{
					ServerAddress: "server",
					AccountID:     int64(i),
				}
				key := "user" + string(rune(i%100)) + "@example.com"
				growthCache.SetWithHash(key, info, AuthSuccess, "{SSHA512}hash")
				time.Sleep(5 * time.Millisecond) // 5ms between logins
			}
			done <- true
		}()

		<-done

		// Wait for cleanup to run (TTL is 200ms, cleanup every 50ms)
		time.Sleep(300 * time.Millisecond)

		// Cache should be small (not all 200 entries!)
		// Most should have expired and been cleaned up
		_, _, finalSize := growthCache.GetStats()
		if finalSize > 50 {
			t.Errorf("Expected cache size < 50 after cleanup, got %d - MEMORY LEAK!", finalSize)
		}
		t.Logf("Final cache size: %d (expected < 50)", finalSize)
	})

	// Test memory growth monitoring - useful for debugging production issues
	t.Run("MemoryGrowthMonitoring", func(t *testing.T) {
		// Simulate production config: 5min TTL, 1min cleanup
		monitorCache := newPrelookupCache(5*time.Minute, 1*time.Minute, 10000, 1*time.Minute)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			monitorCache.Stop(ctx)
		}()

		// Track cache size over time
		var sizes []int

		// Add 1000 entries rapidly (simulating burst traffic)
		for i := 0; i < 1000; i++ {
			info := &UserRoutingInfo{
				ServerAddress: "server",
				AccountID:     int64(i),
			}
			key := fmt.Sprintf("user%d@example.com", i)
			monitorCache.SetWithHash(key, info, AuthSuccess, "{SSHA512}hash")
		}

		_, _, size := monitorCache.GetStats()
		sizes = append(sizes, size)
		t.Logf("After adding 1000 entries: %d", size)

		// Wait 30 seconds (should NOT expire with 5min TTL)
		time.Sleep(100 * time.Millisecond)
		_, _, size = monitorCache.GetStats()
		sizes = append(sizes, size)
		t.Logf("After 100ms (should still be ~1000): %d", size)

		// Size should still be ~1000 (not expired yet)
		if size < 990 {
			t.Errorf("Unexpected cleanup! Expected ~1000 entries, got %d - cleanup running too aggressively!", size)
		}

		// Verify no unbounded growth
		if size > 1000 {
			t.Errorf("Cache grew beyond expected! Expected 1000, got %d - MEMORY LEAK!", size)
		}
	})

	// Test that cleanup actually removes entries over multiple cycles
	t.Run("CleanupCyclesRemoveEntries", func(t *testing.T) {
		// Short TTL and very fast cleanup to see multiple cycles
		cycleCache := newPrelookupCache(200*time.Millisecond, 200*time.Millisecond, 1000, 50*time.Millisecond)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cycleCache.Stop(ctx)
		}()

		// Add 50 entries
		for i := 0; i < 50; i++ {
			info := &UserRoutingInfo{
				ServerAddress: "server",
				AccountID:     int64(i),
			}
			key := fmt.Sprintf("user%d@example.com", i)
			cycleCache.SetWithHash(key, info, AuthSuccess, "{SSHA512}hash")
		}

		// Initial size
		_, _, initialSize := cycleCache.GetStats()
		t.Logf("Initial size: %d", initialSize)

		// Wait for expiration
		time.Sleep(250 * time.Millisecond)

		// Wait for cleanup cycles (50ms interval, wait for 5 cycles)
		time.Sleep(300 * time.Millisecond)

		// Should be cleaned up
		_, _, finalSize := cycleCache.GetStats()
		t.Logf("Final size after cleanup cycles: %d", finalSize)

		if finalSize != 0 {
			t.Errorf("Expected 0 entries after cleanup cycles, got %d - CLEANUP NOT RUNNING!", finalSize)
		}
	})
}
