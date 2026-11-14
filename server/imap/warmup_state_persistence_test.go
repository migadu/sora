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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	// Store some warmup times
	now := time.Now()
	s.lastWarmupTimes.Store(int64(100), now.Add(-1*time.Hour))    // 1h ago — within interval
	s.lastWarmupTimes.Store(int64(200), now.Add(-2*time.Hour))    // 2h ago — within interval
	s.lastWarmupTimes.Store(int64(300), now.Add(-30*time.Minute)) // 30m ago — within interval

	// Persist
	s.persistWarmupState()

	// Verify file was created
	statePath := s.warmupStatePath()
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
	s, _ := testWarmupStateServer(t, 1*time.Hour)

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
	statePath := s.warmupStatePath()
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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	statePath := s.warmupStatePath()

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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	statePath := s.warmupStatePath()

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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	statePath := s.warmupStatePath()
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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	statePath := s.warmupStatePath()
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

	statePath := s.warmupStatePath()

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
		if entry.Name() != filepath.Base(statePath) && entry.Name() != "data" && !strings.HasPrefix(entry.Name(), "cache_index") {
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
	s, _ := testWarmupStateServer(t, 24*time.Hour)

	// No entries stored — persist should still create the file
	s.persistWarmupState()

	statePath := s.warmupStatePath()
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

// TestWarmupStateIsPerServer covers IMAP servers that share one cache, as every
// type = "imap" server of a process does: each must get its own entries back after a
// restart, whichever order the servers stop and start in. With one shared file, the
// server that starts first takes the entries of the server that stopped last, and the
// others get nothing.
func TestWarmupStateIsPerServer(t *testing.T) {
	plain, _ := testWarmupStateServer(t, 24*time.Hour)
	plain.name = "imap"
	tls := &IMAPServer{name: "imaps", warmupInterval: 24 * time.Hour, cache: plain.cache, enableWarmup: true}

	warmedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	plain.lastWarmupTimes.Store(int64(1), warmedAt)
	tls.lastWarmupTimes.Store(int64(2), warmedAt)

	// Shutdown: imap stops first, imaps last.
	plain.persistWarmupState()
	tls.persistWarmupState()

	// Restart: imap starts first.
	plain2 := &IMAPServer{name: "imap", warmupInterval: 24 * time.Hour, cache: plain.cache, enableWarmup: true}
	tls2 := &IMAPServer{name: "imaps", warmupInterval: 24 * time.Hour, cache: plain.cache, enableWarmup: true}
	plain2.loadWarmupState()
	tls2.loadWarmupState()

	for _, tc := range []struct {
		srv        *IMAPServer
		own, other int64
	}{
		{plain2, 1, 2},
		{tls2, 2, 1},
	} {
		if raw, ok := tc.srv.lastWarmupTimes.Load(tc.own); !ok {
			t.Errorf("server %q lost its own entry for account %d across the restart", tc.srv.name, tc.own)
		} else if got := raw.(time.Time); !got.Equal(warmedAt) {
			t.Errorf("server %q: account %d warmed at %v, want %v", tc.srv.name, tc.own, got, warmedAt)
		}
		if _, ok := tc.srv.lastWarmupTimes.Load(tc.other); ok {
			t.Errorf("server %q loaded account %d, which another server warmed", tc.srv.name, tc.other)
		}
	}
}

// TestWarmupStateMigratesSharedFile covers the restart that upgrades from the single
// .sora_warmup_state every IMAP server used to share: the server that starts first
// reads it along with its own file and removes it, so the others do not read it again.
// The servers share the cache, so an account listed there is warm whichever server
// warmed it. Dropping the file unread would warm every account again at the upgrade,
// the herd the file is there to prevent.
func TestWarmupStateMigratesSharedFile(t *testing.T) {
	first, tmpDir := testWarmupStateServer(t, 24*time.Hour)
	second := &IMAPServer{name: "imaps", warmupInterval: 24 * time.Hour, cache: first.cache, enableWarmup: true}

	warmedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	shared := filepath.Join(tmpDir, warmupStateFile)
	if err := os.WriteFile(shared, []byte(fmt.Sprintf("7 %d\n", warmedAt.Unix())), 0600); err != nil {
		t.Fatalf("Failed to write shared state file: %v", err)
	}
	if err := os.WriteFile(first.warmupStatePath(), []byte(fmt.Sprintf("9 %d\n", warmedAt.Unix())), 0600); err != nil {
		t.Fatalf("Failed to write per-server state file: %v", err)
	}

	first.loadWarmupState()
	second.loadWarmupState()

	for _, id := range []int64{7, 9} {
		if raw, ok := first.lastWarmupTimes.Load(id); !ok {
			t.Errorf("the first server to start did not load account %d", id)
		} else if got := raw.(time.Time); !got.Equal(warmedAt) {
			t.Errorf("account %d warmed at %v, want %v", id, got, warmedAt)
		}
	}
	if n := countWarmupTimes(second); n != 0 {
		t.Errorf("the second server loaded %d entries, want 0: the shared file is read once", n)
	}
	if _, err := os.Stat(shared); !os.IsNotExist(err) {
		t.Error("Expected the shared state file to be removed")
	}
}

// TestWarmupStatePathStaysInCacheDir checks that every server name, whatever it
// contains, maps to its own file directly in the cache directory.
func TestWarmupStatePathStaysInCacheDir(t *testing.T) {
	s, tmpDir := testWarmupStateServer(t, 24*time.Hour)

	seen := make(map[string]string)
	for _, name := range []string{"imap", "../imap", "a/b", "a%2Fb", "imap 993"} {
		s.name = name
		path := s.warmupStatePath()
		if filepath.Dir(path) != tmpDir {
			t.Errorf("server %q: state file %q is outside the cache directory %q", name, path, tmpDir)
		}
		if other, dup := seen[path]; dup {
			t.Errorf("servers %q and %q share the state file %q", other, name, path)
		}
		seen[path] = name
	}
}

// Names remain distinct on case-insensitive filesystems and fit within a
// filesystem component even when the accepted server name itself is long.
func TestWarmupStateNamesArePortable(t *testing.T) {
	base, _ := testWarmupStateServer(t, time.Hour)
	for _, names := range [][2]string{
		{"imap-case", "IMAP-case"},
		{strings.Repeat("long/server/", 40), strings.Repeat("long/server/", 40) + "other"},
	} {
		a := &IMAPServer{name: names[0], cache: base.cache, warmupInterval: time.Hour}
		b := &IMAPServer{name: names[1], cache: base.cache, warmupInterval: time.Hour}
		a.lastWarmupTimes.Store(int64(1), time.Now())
		b.lastWarmupTimes.Store(int64(2), time.Now())
		a.persistWarmupState()
		b.persistWarmupState()
		a.lastWarmupTimes.Clear()
		b.lastWarmupTimes.Clear()
		a.loadWarmupState()
		b.loadWarmupState()
		if _, ok := a.lastWarmupTimes.Load(int64(1)); !ok {
			t.Errorf("server %q lost its own persisted entry", a.name)
		}
		if _, ok := a.lastWarmupTimes.Load(int64(2)); ok {
			t.Errorf("server %q loaded the other server's entry", a.name)
		}
		if _, ok := b.lastWarmupTimes.Load(int64(2)); !ok {
			t.Errorf("server %q lost its own persisted entry", b.name)
		}
	}
}
