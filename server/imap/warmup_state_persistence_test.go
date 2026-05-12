package imap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
)

// mockCacheForState is a minimal mock that satisfies cache.GetBasePath()
// We use the real cache package but only need the basePath accessor.
// Since we can't easily construct a real cache.Cache without SQLite,
// we use an interface approach via a thin wrapper.

// testWarmupStateServer creates a minimal IMAPServer for state persistence tests
func testWarmupStateServer(t *testing.T, interval time.Duration) (*IMAPServer, string) {
	t.Helper()
	tmpDir := t.TempDir()

	// Create a real cache just for basePath — use the cache package
	// Actually, we need GetBasePath() from the cache. Let's create a minimal one.
	// The simplest approach: create a real cache.Cache with a temp dir.
	cacheModule, err := createTestCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}
	t.Cleanup(func() { cacheModule.Close() })

	s := &IMAPServer{
		name:           "test-state",
		warmupInterval: interval,
		cache:          cacheModule,
		enableWarmup:   true,
	}
	return s, tmpDir
}

// createTestCache creates a minimal cache.Cache for testing
func createTestCache(basePath string) (*cache.Cache, error) {
	// Import handled by the package — cache is already imported in server.go
	return cache.New(basePath, 1024*1024, 512*1024, time.Hour, 24*time.Hour, nil)
}

// TestWarmupStatePersistAndLoad tests the full round-trip:
// persist state → load state → verify entries match
func TestWarmupStatePersistAndLoad(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	// Store some warmup times
	now := time.Now()
	s.lastWarmupTimes.Store(int64(100), now.Add(-1*time.Hour))    // 1h ago — within interval
	s.lastWarmupTimes.Store(int64(200), now.Add(-2*time.Hour))    // 2h ago — within interval
	s.lastWarmupTimes.Store(int64(300), now.Add(-30*time.Minute)) // 30m ago — within interval

	// Persist
	s.persistWarmupState()

	// Verify file was created
	statePath := filepath.Join(tmpDir, warmupStateFile)
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatal("Expected warmup state file to exist after persist")
	}

	// Create a fresh server to load into
	s2, _ := testWarmupStateServer(t, 24*time.Hour)
	// Point s2 at the same cache (same basePath) — the file is already there
	s2.cache = s.cache

	// Load
	s2.loadWarmupState()

	// Verify all 3 entries were loaded
	for _, accountID := range []int64{100, 200, 300} {
		if _, ok := s2.lastWarmupTimes.Load(accountID); !ok {
			t.Errorf("Expected account %d to be loaded from state file", accountID)
		}
	}

	// Verify file was removed after loading
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Expected warmup state file to be removed after load")
	}
}

// TestWarmupStatePersistFiltersExpired verifies that expired entries are not persisted
func TestWarmupStatePersistFiltersExpired(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 1*time.Hour)

	now := time.Now()
	s.lastWarmupTimes.Store(int64(100), now.Add(-30*time.Minute)) // 30m ago — within 1h interval
	s.lastWarmupTimes.Store(int64(200), now.Add(-2*time.Hour))    // 2h ago — EXPIRED (beyond 1h)
	s.lastWarmupTimes.Store(int64(300), now.Add(-5*time.Minute))  // 5m ago — within interval

	s.persistWarmupState()

	// Load into fresh server
	s2, _ := testWarmupStateServer(t, 1*time.Hour)
	s2.cache = s.cache
	s2.loadWarmupState()

	// Account 100 and 300 should be loaded, 200 should not (expired at persist time)
	if _, ok := s2.lastWarmupTimes.Load(int64(100)); !ok {
		t.Error("Expected account 100 to be loaded (within interval)")
	}
	if _, ok := s2.lastWarmupTimes.Load(int64(200)); ok {
		t.Error("Expected account 200 to NOT be loaded (expired at persist time)")
	}
	if _, ok := s2.lastWarmupTimes.Load(int64(300)); !ok {
		t.Error("Expected account 300 to be loaded (within interval)")
	}

	// Verify file was cleaned up
	statePath := filepath.Join(tmpDir, warmupStateFile)
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Expected state file to be removed after load")
	}
}

// TestWarmupStateLoadFiltersExpired verifies that entries expired between persist and load
// are filtered out during load
func TestWarmupStateLoadFiltersExpired(t *testing.T) {
	s, _ := testWarmupStateServer(t, 1*time.Hour)

	// Store entries that were valid when persisted but will be expired when loaded
	// by creating timestamps just barely within the interval
	now := time.Now()
	s.lastWarmupTimes.Store(int64(100), now.Add(-59*time.Minute)) // Barely within 1h
	s.lastWarmupTimes.Store(int64(200), now.Add(-10*time.Minute)) // Well within 1h

	s.persistWarmupState()

	// Load with a much shorter interval — account 100 should be filtered
	s2, _ := testWarmupStateServer(t, 30*time.Minute) // 30m interval
	s2.cache = s.cache
	s2.loadWarmupState()

	if _, ok := s2.lastWarmupTimes.Load(int64(100)); ok {
		t.Error("Expected account 100 to be filtered out (59m ago exceeds 30m interval)")
	}
	if _, ok := s2.lastWarmupTimes.Load(int64(200)); !ok {
		t.Error("Expected account 200 to be loaded (10m ago within 30m interval)")
	}
}

// TestWarmupStateCorruptFile verifies that a corrupt file is handled gracefully
func TestWarmupStateCorruptFile(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	statePath := filepath.Join(tmpDir, warmupStateFile)

	// Write garbage to the state file
	err := os.WriteFile(statePath, []byte("this is not valid data\x00\xff\xfe binary garbage\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupt file: %v", err)
	}

	// loadWarmupState should NOT panic and should remove the corrupt file
	s.loadWarmupState()

	// Verify no entries were loaded
	count := 0
	s.lastWarmupTimes.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected 0 entries from corrupt file, got %d", count)
	}

	// Verify file was removed
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Expected corrupt state file to be removed")
	}
}

// TestWarmupStatePartiallyCorruptFile verifies that valid entries before corruption are loaded
func TestWarmupStatePartiallyCorruptFile(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	statePath := filepath.Join(tmpDir, warmupStateFile)

	// Write a file with some valid entries followed by garbage
	now := time.Now()
	content := fmt.Sprintf("100 %d\n200 %d\nGARBAGE LINE\n300 notanumber\n400 %d\n",
		now.Add(-1*time.Hour).Unix(),
		now.Add(-2*time.Hour).Unix(),
		now.Add(-3*time.Hour).Unix(),
	)
	err := os.WriteFile(statePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write partially corrupt file: %v", err)
	}

	s.loadWarmupState()

	// Accounts 100, 200, 400 should be loaded (valid lines), 300 should be skipped (parse error)
	if _, ok := s.lastWarmupTimes.Load(int64(100)); !ok {
		t.Error("Expected account 100 to be loaded (valid line)")
	}
	if _, ok := s.lastWarmupTimes.Load(int64(200)); !ok {
		t.Error("Expected account 200 to be loaded (valid line)")
	}
	if _, ok := s.lastWarmupTimes.Load(int64(300)); ok {
		t.Error("Expected account 300 to NOT be loaded (parse error)")
	}
	if _, ok := s.lastWarmupTimes.Load(int64(400)); !ok {
		t.Error("Expected account 400 to be loaded (valid line after garbage)")
	}

	// Verify file was removed
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Expected state file to be removed after load")
	}
}

// TestWarmupStateMissingFile verifies that a missing file is handled gracefully
func TestWarmupStateMissingFile(t *testing.T) {
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	// loadWarmupState with no file should be a no-op
	s.loadWarmupState()

	count := 0
	s.lastWarmupTimes.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected 0 entries when no state file exists, got %d", count)
	}
}

// TestWarmupStateEmptyFile verifies that an empty file is handled gracefully
func TestWarmupStateEmptyFile(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	statePath := filepath.Join(tmpDir, warmupStateFile)
	err := os.WriteFile(statePath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	s.loadWarmupState()

	count := 0
	s.lastWarmupTimes.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected 0 entries from empty file, got %d", count)
	}

	// File should be removed
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Expected empty state file to be removed")
	}
}

// TestWarmupStateMalformedLines verifies various malformed line formats
func TestWarmupStateMalformedLines(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	statePath := filepath.Join(tmpDir, warmupStateFile)
	now := time.Now()

	content := fmt.Sprintf(
		// Valid line
		"100 %d\n"+
			// Too few fields
			"200\n"+
			// Too many fields
			"300 %d extra\n"+
			// Non-numeric account ID
			"abc %d\n"+
			// Non-numeric timestamp
			"400 xyz\n"+
			// Empty line
			"\n"+
			// Whitespace only
			"   \n"+
			// Valid line at end
			"500 %d\n",
		now.Add(-1*time.Hour).Unix(),
		now.Add(-2*time.Hour).Unix(),
		now.Add(-3*time.Hour).Unix(),
		now.Add(-4*time.Hour).Unix(),
	)
	err := os.WriteFile(statePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	s.loadWarmupState()

	// Only accounts 100 and 500 should be loaded (valid lines)
	if _, ok := s.lastWarmupTimes.Load(int64(100)); !ok {
		t.Error("Expected account 100 to be loaded")
	}
	if _, ok := s.lastWarmupTimes.Load(int64(500)); !ok {
		t.Error("Expected account 500 to be loaded")
	}

	// All others should NOT be loaded
	for _, id := range []int64{200, 300, 400} {
		if _, ok := s.lastWarmupTimes.Load(id); ok {
			t.Errorf("Expected account %d to NOT be loaded (malformed line)", id)
		}
	}
}

// TestWarmupStateAtomicWrite verifies that persist uses atomic write (temp + rename)
func TestWarmupStateAtomicWrite(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	now := time.Now()
	s.lastWarmupTimes.Store(int64(100), now.Add(-1*time.Hour))

	s.persistWarmupState()

	statePath := filepath.Join(tmpDir, warmupStateFile)

	// Verify the file exists and has content
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("Failed to read state file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("State file should not be empty")
	}

	// Verify no temp files were left behind
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read dir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != warmupStateFile && entry.Name() != "data" && !strings.HasPrefix(entry.Name(), "cache_index") {
			t.Errorf("Unexpected file in cache dir: %s (possible leaked temp file)", entry.Name())
		}
	}
}

// TestWarmupStatePersistNilCache verifies persist is a no-op when cache is nil
func TestWarmupStatePersistNilCache(t *testing.T) {
	s := &IMAPServer{
		name:           "test",
		warmupInterval: time.Hour,
		cache:          nil,
	}
	s.lastWarmupTimes.Store(int64(100), time.Now())

	// Should not panic
	s.persistWarmupState()
}

// TestWarmupStateLoadNilCache verifies load is a no-op when cache is nil
func TestWarmupStateLoadNilCache(t *testing.T) {
	s := &IMAPServer{
		name:           "test",
		warmupInterval: time.Hour,
		cache:          nil,
	}

	// Should not panic
	s.loadWarmupState()
}

// TestWarmupStatePersistEmpty verifies persist with no entries creates a valid (empty) file
func TestWarmupStatePersistEmpty(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	// No entries stored — persist should still create the file
	s.persistWarmupState()

	statePath := filepath.Join(tmpDir, warmupStateFile)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("Failed to read state file: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected empty state file for no entries, got %d bytes", len(data))
	}
}

// TestWarmupStateConcurrentPersistLoad verifies no races between persist and load
func TestWarmupStateConcurrentPersistLoad(t *testing.T) {
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	now := time.Now()
	for i := int64(0); i < 100; i++ {
		s.lastWarmupTimes.Store(i, now.Add(-time.Duration(i)*time.Minute))
	}

	var wg sync.WaitGroup
	// Run persist and load concurrently — should not race or panic
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.persistWarmupState()
		}()
		go func() {
			defer wg.Done()
			s.loadWarmupState()
		}()
	}
	wg.Wait()
}

// TestWarmupStateTimestampAccuracy verifies timestamps survive round-trip with second precision
func TestWarmupStateTimestampAccuracy(t *testing.T) {
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	// Use a specific timestamp (truncated to seconds since we store Unix timestamps)
	ts := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	s.lastWarmupTimes.Store(int64(42), ts)

	s.persistWarmupState()

	// Load into fresh server
	s2, _ := testWarmupStateServer(t, 24*time.Hour)
	s2.cache = s.cache
	s2.loadWarmupState()

	raw, ok := s2.lastWarmupTimes.Load(int64(42))
	if !ok {
		t.Fatal("Expected account 42 to be loaded")
	}
	loaded := raw.(time.Time)

	// Compare Unix timestamps (our format has second precision)
	if loaded.Unix() != ts.Unix() {
		t.Errorf("Timestamp mismatch: stored %d, loaded %d", ts.Unix(), loaded.Unix())
	}
}
