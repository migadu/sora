package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAuthCache_BasicOperations(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Test cache miss
	entry, found := cache.Get("imap-server", "user1@example.com")
	if found {
		t.Error("Expected cache miss for non-existent entry")
	}
	if entry != nil {
		t.Error("Expected nil entry on cache miss")
	}

	// Store an entry
	testEntry := &CacheEntry{
		AccountID:     123,
		PasswordHash:  "hash123",
		ServerAddress: "backend1.example.com:143",
		AuthResult:    AuthSuccess,
		FromPrelookup: true,
	}
	cache.Set("imap-server", "user1@example.com", testEntry)

	// Test cache hit
	entry, found = cache.Get("imap-server", "user1@example.com")
	if !found {
		t.Fatal("Expected cache hit for stored entry")
	}
	if entry.AccountID != 123 {
		t.Errorf("Expected AccountID 123, got %d", entry.AccountID)
	}
	if entry.PasswordHash != "hash123" {
		t.Errorf("Expected password hash 'hash123', got %s", entry.PasswordHash)
	}
	if entry.ServerAddress != "backend1.example.com:143" {
		t.Errorf("Expected server address 'backend1.example.com:143', got %s", entry.ServerAddress)
	}
	if entry.AuthResult != AuthSuccess {
		t.Errorf("Expected AuthSuccess, got %v", entry.AuthResult)
	}
	if !entry.FromPrelookup {
		t.Error("Expected FromPrelookup to be true")
	}
}

func TestAuthCache_ProtocolIsolation(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store same user in different protocols
	imapEntry := &CacheEntry{
		AccountID:     123,
		PasswordHash:  "hash123",
		ServerAddress: "imap-backend.example.com:143",
		AuthResult:    AuthSuccess,
	}
	cache.Set("imap-server", "user@example.com", imapEntry)

	pop3Entry := &CacheEntry{
		AccountID:     456,
		PasswordHash:  "hash456",
		ServerAddress: "pop3-backend.example.com:110",
		AuthResult:    AuthSuccess,
	}
	cache.Set("pop3", "user@example.com", pop3Entry)

	// Verify protocol isolation
	entry, found := cache.Get("imap-server", "user@example.com")
	if !found || entry.AccountID != 123 {
		t.Error("IMAP entry should have AccountID 123")
	}

	entry, found = cache.Get("pop3", "user@example.com")
	if !found || entry.AccountID != 456 {
		t.Error("POP3 entry should have AccountID 456")
	}

	// Verify different server addresses
	entry, found = cache.Get("imap-server", "user@example.com")
	if !found || entry.ServerAddress != "imap-backend.example.com:143" {
		t.Error("IMAP entry should have IMAP backend address")
	}

	entry, found = cache.Get("pop3", "user@example.com")
	if !found || entry.ServerAddress != "pop3-backend.example.com:110" {
		t.Error("POP3 entry should have POP3 backend address")
	}
}

func TestAuthCache_TTLExpiry(t *testing.T) {
	cache := New(200*time.Millisecond, 100*time.Millisecond, 100, 50*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store positive entry (long TTL)
	positiveEntry := &CacheEntry{
		AccountID:    123,
		PasswordHash: "hash123",
		AuthResult:   AuthSuccess,
	}
	cache.Set("imap-server", "success@example.com", positiveEntry)

	// Store negative entry (short TTL)
	negativeEntry := &CacheEntry{
		AccountID:    0,
		PasswordHash: "",
		AuthResult:   AuthUserNotFound,
	}
	cache.Set("imap-server", "notfound@example.com", negativeEntry)

	// Both should be present initially
	if _, found := cache.Get("imap-server", "success@example.com"); !found {
		t.Error("Positive entry should be present initially")
	}
	if _, found := cache.Get("imap-server", "notfound@example.com"); !found {
		t.Error("Negative entry should be present initially")
	}

	// Wait for negative TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Negative entry should be expired
	if _, found := cache.Get("imap-server", "notfound@example.com"); found {
		t.Error("Negative entry should have expired")
	}

	// Positive entry should still be present
	if _, found := cache.Get("imap-server", "success@example.com"); !found {
		t.Error("Positive entry should still be present")
	}

	// Wait for positive TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Both should be expired now
	if _, found := cache.Get("imap-server", "success@example.com"); found {
		t.Error("Positive entry should have expired")
	}
}

func TestAuthCache_PasswordChangeInvalidation(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store entry with password hash
	entry := &CacheEntry{
		AccountID:    123,
		PasswordHash: "old_hash",
		AuthResult:   AuthSuccess,
	}
	cache.Set("imap-server", "user@example.com", entry)

	// Verify entry is cached
	if _, found := cache.Get("imap-server", "user@example.com"); !found {
		t.Fatal("Entry should be cached")
	}

	// Check password change with same hash - should not invalidate
	changed := cache.CheckPasswordChange("imap-server", "user@example.com", "old_hash")
	if changed {
		t.Error("Same password hash should not trigger invalidation")
	}

	// Verify entry still exists
	if _, found := cache.Get("imap-server", "user@example.com"); !found {
		t.Error("Entry should still be cached after same password check")
	}

	// Check password change with different hash - should invalidate
	changed = cache.CheckPasswordChange("imap-server", "user@example.com", "new_hash")
	if !changed {
		t.Error("Different password hash should trigger invalidation")
	}

	// Verify entry was invalidated
	if _, found := cache.Get("imap-server", "user@example.com"); found {
		t.Error("Entry should be invalidated after password change")
	}
}

func TestAuthCache_Invalidate(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store entry
	entry := &CacheEntry{
		AccountID:  123,
		AuthResult: AuthSuccess,
	}
	cache.Set("imap-server", "user@example.com", entry)

	// Verify it's cached
	if _, found := cache.Get("imap-server", "user@example.com"); !found {
		t.Fatal("Entry should be cached")
	}

	// Invalidate it
	cache.Invalidate("imap-server", "user@example.com")

	// Verify it's gone
	if _, found := cache.Get("imap-server", "user@example.com"); found {
		t.Error("Entry should be invalidated")
	}
}

func TestAuthCache_MaxSizeEviction(t *testing.T) {
	// Create small cache with maxSize=5 (gives maxPositive=4, maxNegative=1 with 80/20 split)
	cache := New(5*time.Second, 2*time.Second, 5, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Add 4 positive entries (fills positive cache)
	cache.Set("imap-server", "user1@example.com", &CacheEntry{AccountID: 1, AuthResult: AuthSuccess})
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	cache.Set("imap-server", "user2@example.com", &CacheEntry{AccountID: 2, AuthResult: AuthSuccess})
	time.Sleep(10 * time.Millisecond)
	cache.Set("imap-server", "user3@example.com", &CacheEntry{AccountID: 3, AuthResult: AuthSuccess})
	time.Sleep(10 * time.Millisecond)
	cache.Set("imap-server", "user4@example.com", &CacheEntry{AccountID: 4, AuthResult: AuthSuccess})

	// All four should be present
	_, _, size, _ := cache.GetStats()
	if size != 4 {
		t.Errorf("Expected size 4, got %d", size)
	}

	// Add one more positive entry - should evict oldest positive (user1)
	cache.Set("imap-server", "user5@example.com", &CacheEntry{AccountID: 5, AuthResult: AuthSuccess})

	// Size should still be 4 (maxPositive limit enforced)
	_, _, size, _ = cache.GetStats()
	if size != 4 {
		t.Errorf("Expected size 4 after eviction, got %d", size)
	}

	// user1 should be evicted (oldest positive)
	if _, found := cache.Get("imap-server", "user1@example.com"); found {
		t.Error("Oldest positive entry (user1) should have been evicted")
	}

	// user2, user3, user4, user5 should still be present
	if _, found := cache.Get("imap-server", "user2@example.com"); !found {
		t.Error("user2 should still be cached")
	}
	if _, found := cache.Get("imap-server", "user3@example.com"); !found {
		t.Error("user3 should still be cached")
	}
	if _, found := cache.Get("imap-server", "user4@example.com"); !found {
		t.Error("user4 should still be cached")
	}
	if _, found := cache.Get("imap-server", "user5@example.com"); !found {
		t.Error("user5 should be cached")
	}

	// Now test negative cache limit (maxNegative=1)
	cache.Set("imap-server", "bad1@example.com", &CacheEntry{AccountID: 0, AuthResult: AuthFailed})
	time.Sleep(10 * time.Millisecond)

	// Size should be 5 (4 positive + 1 negative)
	_, _, size, _ = cache.GetStats()
	if size != 5 {
		t.Errorf("Expected size 5 (4 positive + 1 negative), got %d", size)
	}

	// Add another negative - should evict oldest negative (bad1)
	cache.Set("imap-server", "bad2@example.com", &CacheEntry{AccountID: 0, AuthResult: AuthFailed})

	// Size should still be 5 (4 positive + 1 negative)
	_, _, size, _ = cache.GetStats()
	if size != 5 {
		t.Errorf("Expected size 5 after negative eviction, got %d", size)
	}

	// bad1 should be evicted
	if _, found := cache.Get("imap-server", "bad1@example.com"); found {
		t.Error("Oldest negative entry (bad1) should have been evicted")
	}

	// bad2 should still be present
	if _, found := cache.Get("imap-server", "bad2@example.com"); !found {
		t.Error("bad2 should be cached")
	}

	t.Log("✓ Separate positive/negative cache limits enforced correctly")
}

func TestAuthCache_GetPasswordHash(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store entry with password hash
	entry := &CacheEntry{
		AccountID:    123,
		PasswordHash: "test_hash",
		AuthResult:   AuthSuccess,
	}
	cache.Set("imap-server", "user@example.com", entry)

	// Get password hash
	hash, found := cache.GetPasswordHash("imap-server", "user@example.com")
	if !found {
		t.Fatal("Expected to find password hash")
	}
	if hash != "test_hash" {
		t.Errorf("Expected hash 'test_hash', got %s", hash)
	}

	// Try non-existent user
	hash, found = cache.GetPasswordHash("imap-server", "nonexistent@example.com")
	if found {
		t.Error("Should not find hash for non-existent user")
	}
	if hash != "" {
		t.Error("Hash should be empty string for non-existent user")
	}
}

func TestAuthCache_NegativeCache(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Store auth failure
	failedEntry := &CacheEntry{
		AccountID:  0,
		AuthResult: AuthFailed,
	}
	cache.Set("imap-server", "failed@example.com", failedEntry)

	// Store user not found
	notFoundEntry := &CacheEntry{
		AccountID:  0,
		AuthResult: AuthUserNotFound,
	}
	cache.Set("imap-server", "notfound@example.com", notFoundEntry)

	// Store success
	successEntry := &CacheEntry{
		AccountID:  123,
		AuthResult: AuthSuccess,
	}
	cache.Set("imap-server", "success@example.com", successEntry)

	// Verify IsNegative flag is set correctly
	entry, found := cache.Get("imap-server", "failed@example.com")
	if !found || !entry.IsNegative {
		t.Error("Failed auth should be marked as negative")
	}

	entry, found = cache.Get("imap-server", "notfound@example.com")
	if !found || !entry.IsNegative {
		t.Error("User not found should be marked as negative")
	}

	entry, found = cache.Get("imap-server", "success@example.com")
	if !found || entry.IsNegative {
		t.Error("Success should not be marked as negative")
	}
}

func TestAuthCache_Stats(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Initial stats
	hits, misses, size, ratio := cache.GetStats()
	if hits != 0 || misses != 0 || size != 0 || ratio != 0 {
		t.Error("Initial stats should be zero")
	}

	// Add entry
	cache.Set("imap-server", "user@example.com", &CacheEntry{AccountID: 123, AuthResult: AuthSuccess})

	// Cause a hit
	cache.Get("imap-server", "user@example.com")

	// Cause a miss
	cache.Get("imap-server", "nonexistent@example.com")

	// Check stats
	hits, misses, size, ratio = cache.GetStats()
	if hits != 1 {
		t.Errorf("Expected 1 hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
	if ratio != 0.5 {
		t.Errorf("Expected hit ratio 0.5, got %f", ratio)
	}
}

func TestAuthCache_Clear(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Add some entries
	cache.Set("imap-server", "user1@example.com", &CacheEntry{AccountID: 1, AuthResult: AuthSuccess})
	cache.Set("imap-server", "user2@example.com", &CacheEntry{AccountID: 2, AuthResult: AuthSuccess})
	cache.Set("pop3", "user3@example.com", &CacheEntry{AccountID: 3, AuthResult: AuthSuccess})

	// Verify they exist
	_, _, size, _ := cache.GetStats()
	if size != 3 {
		t.Errorf("Expected size 3, got %d", size)
	}

	// Clear cache
	cache.Clear()

	// Verify everything is gone
	hits, misses, size, ratio := cache.GetStats()
	if hits != 0 || misses != 0 || size != 0 || ratio != 0 {
		t.Error("Cache should be completely empty after Clear()")
	}

	// Verify entries are actually gone
	if _, found := cache.Get("imap-server", "user1@example.com"); found {
		t.Error("user1 should not be found after Clear()")
	}
	if _, found := cache.Get("imap-server", "user2@example.com"); found {
		t.Error("user2 should not be found after Clear()")
	}
	if _, found := cache.Get("pop3", "user3@example.com"); found {
		t.Error("user3 should not be found after Clear()")
	}
}

func TestAuthCache_Cleanup(t *testing.T) {
	// Short cleanup interval for testing
	cache := New(100*time.Millisecond, 50*time.Millisecond, 100, 75*time.Millisecond)
	defer cache.Stop(context.Background())

	// Add entries that will expire
	cache.Set("imap-server", "expires@example.com", &CacheEntry{AccountID: 1, AuthResult: AuthUserNotFound})

	// Verify it exists
	if _, found := cache.Get("imap-server", "expires@example.com"); !found {
		t.Fatal("Entry should exist initially")
	}

	// Wait for cleanup to run (cleanup interval + buffer)
	time.Sleep(200 * time.Millisecond)

	// Entry should be cleaned up
	if _, found := cache.Get("imap-server", "expires@example.com"); found {
		t.Error("Entry should have been cleaned up")
	}
}

func TestAuthCache_UpdateExistingEntry(t *testing.T) {
	// Create small cache with maxSize=3 (maxPositive=2, maxNegative=0 with 80/20 split, rounded down)
	// Actually with integer math: 3*80/100=2, 3*20/100=0
	// Let's use maxSize=5: maxPositive=4, maxNegative=1
	cache := New(5*time.Second, 2*time.Second, 5, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	// Add 4 positive entries (fills positive cache)
	cache.Set("imap-server", "user1@example.com", &CacheEntry{AccountID: 1, AuthResult: AuthSuccess})
	cache.Set("imap-server", "user2@example.com", &CacheEntry{AccountID: 2, AuthResult: AuthSuccess})
	cache.Set("imap-server", "user3@example.com", &CacheEntry{AccountID: 3, AuthResult: AuthSuccess})
	cache.Set("imap-server", "user4@example.com", &CacheEntry{AccountID: 4, AuthResult: AuthSuccess})

	// All four should be present
	_, _, size, _ := cache.GetStats()
	if size != 4 {
		t.Fatalf("Expected size 4, got %d", size)
	}

	// Update user2 (should NOT cause eviction since it's an update, not a new entry)
	cache.Set("imap-server", "user2@example.com", &CacheEntry{AccountID: 22, AuthResult: AuthSuccess})

	// Size should still be 4 (no eviction on update)
	_, _, size, _ = cache.GetStats()
	if size != 4 {
		t.Errorf("Expected size 4 after update, got %d", size)
	}

	// All four users should still be present
	if _, found := cache.Get("imap-server", "user1@example.com"); !found {
		t.Error("user1 should still be cached")
	}
	if entry, found := cache.Get("imap-server", "user2@example.com"); !found {
		t.Error("user2 should still be cached")
	} else if entry.AccountID != 22 {
		t.Errorf("user2 should have updated AccountID 22, got %d", entry.AccountID)
	}
	if _, found := cache.Get("imap-server", "user3@example.com"); !found {
		t.Error("user3 should still be cached")
	}
	if _, found := cache.Get("imap-server", "user4@example.com"); !found {
		t.Error("user4 should still be cached")
	}

	// Now add a NEW entry - this should evict oldest
	cache.Set("imap-server", "user5@example.com", &CacheEntry{AccountID: 5, AuthResult: AuthSuccess})

	// Size should still be 4 (user1 evicted)
	_, _, size, _ = cache.GetStats()
	if size != 4 {
		t.Errorf("Expected size 4 after adding new entry, got %d", size)
	}

	// user1 should be evicted
	if _, found := cache.Get("imap-server", "user1@example.com"); found {
		t.Error("user1 should have been evicted")
	}

	// user2, user3, user4, user5 should be present
	if _, found := cache.Get("imap-server", "user2@example.com"); !found {
		t.Error("user2 should still be cached")
	}

	t.Log("✓ Update existing entry does not cause unnecessary evictions")
}

// TestAuthCache_ConcurrentSetGet tests concurrent reads and writes
func TestAuthCache_ConcurrentSetGet(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 1000, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	const numGoroutines = 100
	const numOperations = 1000

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	// Launch goroutines doing concurrent Set/Get operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				username := fmt.Sprintf("user%d@example.com", j%100)

				// Set entry
				cache.Set("imap-server", username, &CacheEntry{
					AccountID:  int64(id),
					AuthResult: AuthSuccess,
				})

				// Immediately try to get it
				if entry, found := cache.Get("imap-server", username); found {
					if entry.AccountID < 0 {
						errors <- fmt.Errorf("goroutine %d: got negative AccountID: %d", id, entry.AccountID)
						return
					}
				}

				// Refresh
				cache.Refresh("imap-server", username)

				// Invalidate occasionally
				if j%10 == 0 {
					cache.Invalidate("imap-server", username)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}

	t.Logf("✓ %d goroutines performed %d operations each without race conditions", numGoroutines, numOperations)
}

// TestAuthCache_ConcurrentEviction tests that concurrent operations don't cause issues during eviction
func TestAuthCache_ConcurrentEviction(t *testing.T) {
	// Small cache to force frequent evictions
	cache := New(100*time.Millisecond, 50*time.Millisecond, 50, 25*time.Millisecond)
	defer cache.Stop(context.Background())

	const numGoroutines = 50
	const numOperations = 200

	var wg sync.WaitGroup

	// Launch goroutines that constantly add entries (forcing evictions)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				username := fmt.Sprintf("user%d-%d@example.com", id, j)
				cache.Set("imap-server", username, &CacheEntry{
					AccountID:  int64(id*1000 + j),
					AuthResult: AuthSuccess,
				})

				// Small delay to let eviction happen
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is within size limits
	_, _, size, _ := cache.GetStats()
	maxSize := 40 + 10 // maxPositive=40 (80%), maxNegative=10 (20%)
	if size > maxSize {
		t.Errorf("Cache size %d exceeds max size %d after concurrent evictions", size, maxSize)
	}

	t.Logf("✓ Cache maintained size limits (%d/%d) during concurrent evictions", size, maxSize)
}

// TestAuthCache_ConcurrentTypeChanges tests concurrent operations that change entry types
func TestAuthCache_ConcurrentTypeChanges(t *testing.T) {
	cache := New(5*time.Second, 2*time.Second, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	const numGoroutines = 20
	const numOperations = 100

	var wg sync.WaitGroup

	// Goroutines that alternate between positive and negative entries
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			username := fmt.Sprintf("user%d@example.com", id)

			for j := 0; j < numOperations; j++ {
				if j%2 == 0 {
					// Set as positive
					cache.Set("imap-server", username, &CacheEntry{
						AccountID:  int64(id),
						AuthResult: AuthSuccess,
					})
				} else {
					// Set as negative
					cache.Set("imap-server", username, &CacheEntry{
						AuthResult: AuthFailed,
						IsNegative: true,
					})
				}

				// Verify we can read it back
				if _, found := cache.Get("imap-server", username); !found {
					t.Errorf("goroutine %d: entry disappeared during type change", id)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is still functional
	_, _, size, _ := cache.GetStats()
	if size == 0 {
		t.Error("Cache is empty after concurrent type changes")
	}

	t.Logf("✓ Cache handled %d concurrent type changes correctly", numGoroutines*numOperations)
}

// TestAuthCache_StressTestMemoryUsage tests that memory usage stays bounded under stress
func TestAuthCache_StressTestMemoryUsage(t *testing.T) {
	cache := New(1*time.Second, 500*time.Millisecond, 1000, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	const numIterations = 10000

	// Add many entries rapidly
	for i := 0; i < numIterations; i++ {
		username := fmt.Sprintf("user%d@example.com", i)
		cache.Set("imap-server", username, &CacheEntry{
			AccountID:     int64(i),
			ServerAddress: fmt.Sprintf("backend%d.example.com:143", i%10),
			AuthResult:    AuthSuccess,
		})
	}

	// Check that cache size is bounded
	_, _, size, _ := cache.GetStats()
	maxSize := 800 + 200 // maxPositive=800 (80%), maxNegative=200 (20%)
	if size > maxSize {
		t.Errorf("Cache size %d exceeds max size %d after stress test", size, maxSize)
	}

	// Verify oldest entries were evicted
	if _, found := cache.Get("imap-server", "user0@example.com"); found {
		t.Error("Oldest entry (user0) should have been evicted")
	}

	// Verify newest entries are present
	if _, found := cache.Get("imap-server", fmt.Sprintf("user%d@example.com", numIterations-1)); !found {
		t.Error("Newest entry should still be cached")
	}

	t.Logf("✓ Cache stayed within bounds (%d/%d) after adding %d entries", size, maxSize, numIterations)
}

// TestAuthCache_NoDeadlocks tests that concurrent operations don't cause deadlocks
func TestAuthCache_NoDeadlocks(t *testing.T) {
	cache := New(1*time.Second, 500*time.Millisecond, 100, 100*time.Millisecond)
	defer cache.Stop(context.Background())

	const numGoroutines = 50
	const duration = 2 * time.Second

	done := make(chan bool)
	var wg sync.WaitGroup

	// Launch goroutines performing random operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for {
				select {
				case <-done:
					return
				default:
					username := fmt.Sprintf("user%d@example.com", id%20)

					// Randomly choose operation
					switch id % 6 {
					case 0:
						cache.Set("imap-server", username, &CacheEntry{AccountID: int64(id), AuthResult: AuthSuccess})
					case 1:
						cache.Get("imap-server", username)
					case 2:
						cache.Refresh("imap-server", username)
					case 3:
						cache.Invalidate("imap-server", username)
					case 4:
						cache.GetStats()
					case 5:
						cache.Clear()
					}

					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	// Run for fixed duration
	time.Sleep(duration)
	close(done)

	// Wait with timeout to detect deadlocks
	timeout := make(chan bool, 1)
	go func() {
		wg.Wait()
		timeout <- true
	}()

	select {
	case <-timeout:
		t.Log("✓ No deadlocks detected during concurrent operations")
	case <-time.After(5 * time.Second):
		t.Fatal("Deadlock detected: goroutines did not finish within timeout")
	}
}

// TestAuthCache_RapidStopStart tests that Stop() and cleanup work correctly
func TestAuthCache_RapidStopStart(t *testing.T) {
	const numCycles = 10

	for i := 0; i < numCycles; i++ {
		cache := New(1*time.Second, 500*time.Millisecond, 100, 50*time.Millisecond)

		// Add some entries
		for j := 0; j < 10; j++ {
			cache.Set("imap-server", fmt.Sprintf("user%d@example.com", j), &CacheEntry{
				AccountID:  int64(j),
				AuthResult: AuthSuccess,
			})
		}

		// Stop immediately
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		err := cache.Stop(ctx)
		cancel()

		if err != nil {
			t.Errorf("Cycle %d: Stop() returned error: %v", i, err)
		}
	}

	t.Logf("✓ Successfully created and stopped cache %d times", numCycles)
}

// TestAuthCache_MemoryBoundedUnderPressure verifies memory doesn't grow unbounded
func TestAuthCache_MemoryBoundedUnderPressure(t *testing.T) {
	cache := New(100*time.Millisecond, 50*time.Millisecond, 500, 25*time.Millisecond)
	defer cache.Stop(context.Background())

	const numWaves = 5
	const entriesPerWave = 2000

	for wave := 0; wave < numWaves; wave++ {
		// Add many entries
		for i := 0; i < entriesPerWave; i++ {
			username := fmt.Sprintf("wave%d-user%d@example.com", wave, i)
			cache.Set("imap-server", username, &CacheEntry{
				AccountID:     int64(wave*1000 + i),
				ServerAddress: "backend.example.com:143",
				AuthResult:    AuthSuccess,
			})
		}

		// Check size is bounded
		_, _, size, _ := cache.GetStats()
		maxSize := 400 + 100 // maxPositive=400, maxNegative=100
		if size > maxSize {
			t.Errorf("Wave %d: Cache size %d exceeds max %d", wave, size, maxSize)
		}

		t.Logf("Wave %d: Added %d entries, cache size: %d/%d", wave, entriesPerWave, size, maxSize)

		// Let cleanup run
		time.Sleep(100 * time.Millisecond)
	}

	t.Log("✓ Memory stayed bounded across multiple waves of additions")
}
