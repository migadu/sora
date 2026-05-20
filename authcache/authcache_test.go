package authcache

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempDBPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "auth_cache_test.db")
}

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	c, err := New(tempDBPath(t), 1*time.Hour, 24*time.Hour, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNew(t *testing.T) {
	dbPath := tempDBPath(t)
	c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer c.Close()

	// Verify the SQLite database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file was not created")
	}
}

func TestNew_InvalidPath(t *testing.T) {
	_, err := New("/nonexistent/deeply/nested/path/auth_cache.db", time.Hour, 24*time.Hour, time.Hour)
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestPutAndGet(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	// Put an entry
	err := c.Put(ctx, "user@example.com", 42, "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012")
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Get the entry back
	accountID, hash, err := c.Get(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if accountID != 42 {
		t.Errorf("accountID = %d, want 42", accountID)
	}
	if hash != "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012" {
		t.Errorf("unexpected hash: %s", hash)
	}
}

func TestGet_CacheMiss(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	_, _, err := c.Get(ctx, "nonexistent@example.com")
	if err != ErrCacheMiss {
		t.Errorf("Get() error = %v, want ErrCacheMiss", err)
	}
}

func TestGet_EmptyAddress(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	_, _, err := c.Get(ctx, "")
	if err == nil {
		t.Error("Get('') should return error")
	}
}

func TestPut_EmptyAddress(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	err := c.Put(ctx, "", 1, "hash")
	if err == nil {
		t.Error("Put('') should return error")
	}
}

func TestGet_AddressNormalization(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	// Store with mixed case
	err := c.Put(ctx, "User@Example.COM", 42, "hash123")
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Retrieve with different case
	accountID, hash, err := c.Get(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if accountID != 42 || hash != "hash123" {
		t.Errorf("address normalization failed: got accountID=%d hash=%s", accountID, hash)
	}

	// Also with whitespace
	accountID2, _, err := c.Get(ctx, "  User@Example.COM  ")
	if err != nil {
		t.Fatalf("Get() with whitespace error: %v", err)
	}
	if accountID2 != 42 {
		t.Error("whitespace normalization failed")
	}
}

func TestPut_Upsert(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	// First insert
	err := c.Put(ctx, "user@example.com", 42, "oldhash")
	if err != nil {
		t.Fatalf("first Put() error: %v", err)
	}

	// Update (upsert)
	err = c.Put(ctx, "user@example.com", 99, "newhash")
	if err != nil {
		t.Fatalf("second Put() error: %v", err)
	}

	// Verify updated values
	accountID, hash, err := c.Get(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if accountID != 99 {
		t.Errorf("accountID = %d, want 99", accountID)
	}
	if hash != "newhash" {
		t.Errorf("hash = %s, want newhash", hash)
	}
}

func TestGet_Expiration(t *testing.T) {
	dbPath := tempDBPath(t)
	// Create cache with 1 second max age (cached_at uses Unix seconds precision)
	c, err := New(dbPath, 1*time.Second, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	err = c.Put(ctx, "user@example.com", 42, "hash")
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Should work immediately
	_, _, err = c.Get(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Get() should succeed immediately: %v", err)
	}

	// Wait for expiration (need >2s: with 1s max age and integer-second timestamps,
	// cached_at=T, after 2.5s now=T+2, threshold=T+2-1=T+1, T < T+1 → expired)
	time.Sleep(2500 * time.Millisecond)

	// Should now be expired
	_, _, err = c.Get(ctx, "user@example.com")
	if err != ErrCacheMiss {
		t.Errorf("Get() after expiry = %v, want ErrCacheMiss", err)
	}
}

func TestInvalidate(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	err := c.Put(ctx, "user@example.com", 42, "hash")
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Verify it exists
	_, _, err = c.Get(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Get() before invalidate error: %v", err)
	}

	// Invalidate
	err = c.Invalidate(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Invalidate() error: %v", err)
	}

	// Should be gone
	_, _, err = c.Get(ctx, "user@example.com")
	if err != ErrCacheMiss {
		t.Errorf("Get() after invalidate = %v, want ErrCacheMiss", err)
	}
}

func TestInvalidateAccount(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	// Add multiple entries for same account
	c.Put(ctx, "alice@example.com", 42, "hash1")
	c.Put(ctx, "bob@example.com", 42, "hash2")
	c.Put(ctx, "carol@example.com", 99, "hash3") // different account

	// Invalidate account 42
	err := c.InvalidateAccount(ctx, 42)
	if err != nil {
		t.Fatalf("InvalidateAccount() error: %v", err)
	}

	// alice and bob should be gone
	_, _, err = c.Get(ctx, "alice@example.com")
	if err != ErrCacheMiss {
		t.Error("alice should be invalidated")
	}
	_, _, err = c.Get(ctx, "bob@example.com")
	if err != ErrCacheMiss {
		t.Error("bob should be invalidated")
	}

	// carol (account 99) should remain
	accountID, _, err := c.Get(ctx, "carol@example.com")
	if err != nil {
		t.Fatalf("carol Get() error: %v", err)
	}
	if accountID != 99 {
		t.Errorf("carol accountID = %d, want 99", accountID)
	}
}

func TestStats(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	c.Put(ctx, "user@example.com", 42, "hash")

	// Generate some hits and misses
	c.Get(ctx, "user@example.com")    // hit
	c.Get(ctx, "user@example.com")    // hit
	c.Get(ctx, "unknown@example.com") // miss

	totalEntries, _, hits, misses, hitRate, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}
	if totalEntries != 1 {
		t.Errorf("totalEntries = %d, want 1", totalEntries)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	// hitRate should be ~66.67%
	if hitRate < 60 || hitRate > 70 {
		t.Errorf("hitRate = %f, want ~66.67", hitRate)
	}
}

func TestCleanup(t *testing.T) {
	dbPath := tempDBPath(t)
	// 1 second max age and purge unused (cached_at uses Unix seconds precision)
	// cleanup uses strict less-than (cached_at < threshold), so we need to sleep
	// long enough that now - maxAge is strictly greater than the cached_at value
	c, err := New(dbPath, 1*time.Second, 1*time.Second, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	c.Put(ctx, "old@example.com", 1, "hash")

	// Wait >2 full seconds to ensure the integer-second threshold is strictly past cached_at
	// cached_at=T, after 2.5s: now=T+2, threshold=T+2-1=T+1, T < T+1 ✓
	time.Sleep(2500 * time.Millisecond)

	// Run cleanup directly
	c.cleanup(ctx)

	// Entry should be removed
	_, _, err = c.Get(ctx, "old@example.com")
	if err != ErrCacheMiss {
		t.Errorf("old entry should be cleaned up: err=%v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	// Seed some data
	for i := 0; i < 10; i++ {
		addr := "user" + string(rune('a'+i)) + "@example.com"
		c.Put(ctx, addr, int64(i), "hash"+string(rune('0'+i)))
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Concurrent reads
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			addr := "user" + string(rune('a'+(n%10))) + "@example.com"
			_, _, err := c.Get(ctx, addr)
			if err != nil && err != ErrCacheMiss {
				errChan <- err
			}
		}(i)
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			addr := "new" + string(rune('a'+n)) + "@example.com"
			if err := c.Put(ctx, addr, int64(100+n), "newhash"); err != nil {
				errChan <- err
			}
		}(i)
	}

	// Concurrent invalidations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			addr := "user" + string(rune('a'+n)) + "@example.com"
			if err := c.Invalidate(ctx, addr); err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent operation error: %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dbPath := tempDBPath(t)
	ctx := context.Background()

	// Create cache, write data, close it
	c1, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("first New() error: %v", err)
	}
	c1.Put(ctx, "persist@example.com", 42, "persisthash")
	c1.Close()

	// Reopen and verify data persists
	c2, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("second New() error: %v", err)
	}
	defer c2.Close()

	accountID, hash, err := c2.Get(ctx, "persist@example.com")
	if err != nil {
		t.Fatalf("Get() after reopen error: %v", err)
	}
	if accountID != 42 {
		t.Errorf("accountID = %d, want 42", accountID)
	}
	if hash != "persisthash" {
		t.Errorf("hash = %s, want persisthash", hash)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	c := newTestCache(t)

	// First close should succeed
	if err := c.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}

	// Second close should not panic (db is nil-safe)
	err := c.Close()
	_ = err // double close may error but should not panic
}

func TestStartCleanupLoop(t *testing.T) {
	dbPath := tempDBPath(t)
	// 1 second max age, cleanup every 500ms (cached_at uses Unix seconds precision)
	c, err := New(dbPath, 1*time.Second, 1*time.Second, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Put(ctx, "expire@example.com", 1, "hash")

	c.StartCleanupLoop(ctx)

	// Wait for entry to expire (>1s) and cleanup to run (every 500ms)
	time.Sleep(2500 * time.Millisecond)

	// Entry should have been cleaned up by the loop
	_, _, err = c.Get(ctx, "expire@example.com")
	if err != ErrCacheMiss {
		t.Errorf("entry should be cleaned up by loop: err=%v", err)
	}
}

func TestNew_CorruptedDB_Recreates(t *testing.T) {
	dbPath := tempDBPath(t)
	ctx := context.Background()

	// Create a valid cache and populate it
	c1, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("first New() error: %v", err)
	}
	c1.Put(ctx, "user@example.com", 42, "hash")
	c1.Close()

	// Corrupt the database file by writing garbage
	if err := os.WriteFile(dbPath, []byte("this is not a valid sqlite database"), 0644); err != nil {
		t.Fatalf("failed to corrupt db: %v", err)
	}

	// New() should detect corruption, delete, and recreate
	c2, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() after corruption should succeed, got error: %v", err)
	}
	defer c2.Close()

	// Old data should be gone (db was recreated)
	_, _, err = c2.Get(ctx, "user@example.com")
	if err != ErrCacheMiss {
		t.Errorf("expected cache miss after recreation, got: %v", err)
	}

	// Should be able to write new data
	if err := c2.Put(ctx, "new@example.com", 99, "newhash"); err != nil {
		t.Fatalf("Put() after recreation error: %v", err)
	}
	accountID, _, err := c2.Get(ctx, "new@example.com")
	if err != nil {
		t.Fatalf("Get() after recreation error: %v", err)
	}
	if accountID != 99 {
		t.Errorf("accountID = %d, want 99", accountID)
	}
}

func TestMultipleAddresses(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	addresses := map[string]int64{
		"alice@example.com": 1,
		"bob@example.com":   2,
		"carol@example.com": 3,
		"dave@other.com":    4,
		"eve@another.org":   5,
	}

	for addr, id := range addresses {
		if err := c.Put(ctx, addr, id, "hash-"+addr); err != nil {
			t.Fatalf("Put(%s) error: %v", addr, err)
		}
	}

	for addr, expectedID := range addresses {
		id, hash, err := c.Get(ctx, addr)
		if err != nil {
			t.Errorf("Get(%s) error: %v", addr, err)
			continue
		}
		if id != expectedID {
			t.Errorf("Get(%s) id = %d, want %d", addr, id, expectedID)
		}
		if hash != "hash-"+addr {
			t.Errorf("Get(%s) hash = %s, want hash-%s", addr, hash, addr)
		}
	}

	// Verify stats
	totalEntries, _, _, _, _, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}
	if totalEntries != int64(len(addresses)) {
		t.Errorf("totalEntries = %d, want %d", totalEntries, len(addresses))
	}
}

func TestFilePermissions(t *testing.T) {
	dbPath := tempDBPath(t)
	c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer c.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("os.Stat() error: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected 0600 permissions, got %04o", mode)
	}
}
