package affinitycache

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "affinity_test.db")
}

func TestNew(t *testing.T) {
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()
}

func TestNew_InvalidPath(t *testing.T) {
	_, err := New("/nonexistent/deeply/nested/path/db.sqlite")
	if err == nil {
		t.Fatal("Expected error for invalid path")
	}
}

func TestSetAndLoadAll(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	now := time.Now()
	entries := []AffinityEntry{
		{Username: "alice@example.com", Protocol: "imap", Backend: "backend1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"},
		{Username: "alice@example.com", Protocol: "pop3", Backend: "backend1:110", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"},
		{Username: "bob@example.com", Protocol: "imap", Backend: "backend2:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-2"},
	}

	for _, e := range entries {
		if err := store.Set(ctx, e); err != nil {
			t.Fatalf("Set() error: %v", err)
		}
	}

	loaded, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll() error: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(loaded))
	}
}

func TestLoadAll_ExcludesExpired(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	now := time.Now()

	// One valid, one expired
	store.Set(ctx, AffinityEntry{Username: "valid@example.com", Protocol: "imap", Backend: "b1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"})
	store.Set(ctx, AffinityEntry{Username: "expired@example.com", Protocol: "imap", Backend: "b2:143", AssignedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), NodeID: "n1"})

	loaded, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll() error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Expected 1 entry (expired excluded), got %d", len(loaded))
	}
	if loaded[0].Username != "valid@example.com" {
		t.Fatalf("Expected valid@example.com, got %s", loaded[0].Username)
	}
}

func TestSet_Upsert(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	now := time.Now()

	// Set initial
	store.Set(ctx, AffinityEntry{Username: "alice@example.com", Protocol: "imap", Backend: "backend1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"})

	// Update to different backend
	store.Set(ctx, AffinityEntry{Username: "alice@example.com", Protocol: "imap", Backend: "backend2:143", AssignedAt: now.Add(time.Minute), ExpiresAt: now.Add(2 * time.Hour), NodeID: "node-2"})

	loaded, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll() error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Expected 1 entry after upsert, got %d", len(loaded))
	}
	if loaded[0].Backend != "backend2:143" {
		t.Fatalf("Expected backend2:143, got %s", loaded[0].Backend)
	}
	if loaded[0].NodeID != "node-2" {
		t.Fatalf("Expected node-2, got %s", loaded[0].NodeID)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	now := time.Now()
	store.Set(ctx, AffinityEntry{Username: "alice@example.com", Protocol: "imap", Backend: "b1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"})
	store.Set(ctx, AffinityEntry{Username: "alice@example.com", Protocol: "pop3", Backend: "b1:110", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"})

	// Delete only IMAP affinity
	if err := store.Delete(ctx, "alice@example.com", "imap"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	loaded, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll() error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Expected 1 remaining entry, got %d", len(loaded))
	}
	if loaded[0].Protocol != "pop3" {
		t.Fatalf("Expected pop3 to remain, got %s", loaded[0].Protocol)
	}
}

func TestCleanup(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	now := time.Now()

	// Add mix of valid and expired
	store.Set(ctx, AffinityEntry{Username: "valid@example.com", Protocol: "imap", Backend: "b1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"})
	store.Set(ctx, AffinityEntry{Username: "expired1@example.com", Protocol: "imap", Backend: "b2:143", AssignedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), NodeID: "n1"})
	store.Set(ctx, AffinityEntry{Username: "expired2@example.com", Protocol: "pop3", Backend: "b3:110", AssignedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(-2 * time.Hour), NodeID: "n1"})

	removed, err := store.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
	if removed != 2 {
		t.Fatalf("Expected 2 removed, got %d", removed)
	}

	count, _ := store.Count(ctx)
	if count != 1 {
		t.Fatalf("Expected 1 remaining, got %d", count)
	}
}

func TestCount(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count() error: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected 0 entries, got %d", count)
	}

	now := time.Now()
	store.Set(ctx, AffinityEntry{Username: "a@b.com", Protocol: "imap", Backend: "b:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"})

	count, _ = store.Count(ctx)
	if count != 1 {
		t.Fatalf("Expected 1 entry, got %d", count)
	}
}

func TestPersistence(t *testing.T) {
	ctx := context.Background()
	dbPath := tempDB(t)
	now := time.Now()

	// Create and populate
	store1, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	store1.Set(ctx, AffinityEntry{Username: "alice@example.com", Protocol: "imap", Backend: "backend1:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-1"})
	store1.Close()

	// Reopen and verify
	store2, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() second open error: %v", err)
	}
	defer store2.Close()

	loaded, err := store2.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll() error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Expected 1 persisted entry, got %d", len(loaded))
	}
	if loaded[0].Backend != "backend1:143" {
		t.Fatalf("Expected backend1:143, got %s", loaded[0].Backend)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	var wg sync.WaitGroup
	now := time.Now()

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := AffinityEntry{
				Username:   "user@example.com",
				Protocol:   "imap",
				Backend:    "backend:143",
				AssignedAt: now,
				ExpiresAt:  now.Add(time.Hour),
				NodeID:     "node-1",
			}
			store.Set(ctx, entry)
			store.LoadAll(ctx)
		}(i)
	}

	wg.Wait()

	count, _ := store.Count(ctx)
	if count != 1 {
		t.Fatalf("Expected 1 entry after concurrent writes, got %d", count)
	}
}

func TestCorruptedDB_Recreates(t *testing.T) {
	dbPath := tempDB(t)

	// Write garbage
	os.WriteFile(dbPath, []byte("not a sqlite database"), 0644)

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("Expected auto-recovery, got error: %v", err)
	}
	defer store.Close()

	// Should work after recreation
	ctx := context.Background()
	now := time.Now()
	if err := store.Set(ctx, AffinityEntry{Username: "a@b.com", Protocol: "imap", Backend: "b:143", AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "n1"}); err != nil {
		t.Fatalf("Set() after recovery error: %v", err)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	store, err := New(tempDB(t))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	store.Close()
	// Second close should not panic
	store.Close()
}

func TestFilePermissions(t *testing.T) {
	dbPath := tempDB(t)
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer store.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("os.Stat() error: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected 0600 permissions, got %04o", mode)
	}
}
