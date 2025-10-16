package cache

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSourceDatabase is a mock implementation of the SourceDatabase for testing.
type mockSourceDatabase struct {
	mu             sync.Mutex
	existingHashes map[string]bool
	warmupData     map[string][]string
	warmupError    error
}

func newMockSourceDatabase() *mockSourceDatabase {
	return &mockSourceDatabase{
		existingHashes: make(map[string]bool),
	}
}

func (m *mockSourceDatabase) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var existing []string
	for _, h := range hashes {
		if m.existingHashes[h] {
			existing = append(existing, h)
		}
	}
	return existing, nil
}

func (m *mockSourceDatabase) GetRecentMessagesForWarmupWithRetry(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.warmupError != nil {
		return nil, m.warmupError
	}
	return m.warmupData, nil
}

func (m *mockSourceDatabase) SetExistingHashes(hashes ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existingHashes = make(map[string]bool)
	for _, h := range hashes {
		m.existingHashes[h] = true
	}
}

func (m *mockSourceDatabase) SetWarmupData(data map[string][]string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warmupData = data
	m.warmupError = err
}

// newTestCache is a test helper to create a cache instance in a temporary directory.
func newTestCache(t *testing.T, capacity int64, maxObjectSize int64) (*Cache, *mockSourceDatabase) {
	t.Helper()
	basePath := t.TempDir()
	mockDB := newMockSourceDatabase()

	// Use short intervals for testing purge loops
	purgeInterval := 100 * time.Millisecond
	orphanCleanupAge := 1 * time.Second

	c, err := New(basePath, capacity, maxObjectSize, purgeInterval, orphanCleanupAge, mockDB)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := c.Close()
		assert.NoError(t, err)
	})

	return c, mockDB
}

// randomDataAndHash generates random data and its SHA256 hash.
func randomDataAndHash(t *testing.T, size int) ([]byte, string) {
	t.Helper()
	data := make([]byte, size)
	_, err := rand.Read(data)
	require.NoError(t, err)
	hash := sha256.Sum256(data)
	return data, hex.EncodeToString(hash[:])
}

func TestNewCache(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		c, _ := newTestCache(t, 1024, 512)
		assert.NotNil(t, c)
		assert.NotNil(t, c.db)
		assert.DirExists(t, filepath.Join(c.basePath, DataDir))
		assert.FileExists(t, filepath.Join(c.basePath, IndexDB))
	})

	t.Run("empty base path", func(t *testing.T) {
		_, err := New("", 1024, 512, time.Minute, time.Hour, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cache base path cannot be empty")
	})
}

func TestPutGetExistsDelete(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	data, hash := randomDataAndHash(t, 100)

	// 1. Get non-existent
	_, err := c.Get(hash)
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, int64(1), c.cacheMisses)

	// 2. Put
	err = c.Put(hash, data)
	require.NoError(t, err)

	// 3. Get existent
	retrievedData, err := c.Get(hash)
	require.NoError(t, err)
	assert.Equal(t, data, retrievedData)
	assert.Equal(t, int64(1), c.cacheHits)

	// 4. Exists
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, int64(2), c.cacheHits) // Exists also counts as a hit

	// 5. Delete
	err = c.Delete(hash)
	require.NoError(t, err)

	// 6. Verify deleted
	exists, err = c.Exists(hash)
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, int64(2), c.cacheMisses) // Exists on non-existent is a miss

	_, err = c.Get(hash)
	assert.Error(t, err)
}

func TestDelete_RemovesEmptyParents(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)

	// Use a crafted hash to ensure a predictable directory structure.
	hash1 := "aabb111111111111111111111111111111111111111111111111111111111111"
	data, _ := randomDataAndHash(t, 10)

	// Put a file, which creates parent directories.
	require.NoError(t, c.Put(hash1, data))
	path1 := c.GetPathForContentHash(hash1)

	// Delete the file.
	require.NoError(t, c.Delete(hash1))

	// The file's direct parent and its parent should be removed.
	dir_level2 := filepath.Dir(path1)
	dir_level1 := filepath.Dir(dir_level2)
	_, err := os.Stat(dir_level1)
	assert.True(t, os.IsNotExist(err), "empty parent directories should be removed")
}

func TestPut_ObjectTooLarge(t *testing.T) {
	c, _ := newTestCache(t, 1024, 100)
	data, hash := randomDataAndHash(t, 101)

	err := c.Put(hash, data)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrObjectTooLarge)
	assert.Contains(t, err.Error(), "exceeds limit")
}

func TestConcurrentPut(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	data, hash := randomDataAndHash(t, 100)

	var wg sync.WaitGroup
	numGoroutines := 10
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := c.Put(hash, data)
			// It's okay if some Puts fail with "file exists" during the rename, as the code handles this.
			// We just want to ensure no other errors occur.
			if err != nil {
				assert.Contains(t, err.Error(), "file exists")
			}
		}()
	}
	wg.Wait()

	// Verify the file is in the cache
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPurgeIfNeeded(t *testing.T) {
	c, _ := newTestCache(t, 100, 50)
	ctx := context.Background()

	// Put two items, filling the cache
	data1, hash1 := randomDataAndHash(t, 50)
	require.NoError(t, c.Put(hash1, data1))
	time.Sleep(10 * time.Millisecond) // Ensure different mod_time

	data2, hash2 := randomDataAndHash(t, 50)
	require.NoError(t, c.Put(hash2, data2))

	// Cache is full, but not over capacity. Nothing should be purged.
	require.NoError(t, c.PurgeIfNeeded(ctx))
	exists, _ := c.Exists(hash1)
	assert.True(t, exists)
	exists, _ = c.Exists(hash2)
	assert.True(t, exists)

	// Put a third item, exceeding capacity
	data3, hash3 := randomDataAndHash(t, 20)
	require.NoError(t, c.Put(hash3, data3))

	// Now purge should run and remove the oldest item (hash1)
	require.NoError(t, c.PurgeIfNeeded(ctx))

	// Verify hash1 is gone, and others remain
	exists, _ = c.Exists(hash1)
	assert.False(t, exists)
	exists, _ = c.Exists(hash2)
	assert.True(t, exists)
	exists, _ = c.Exists(hash3)
	assert.True(t, exists)
}

func TestPurgeIfNeeded_UpdateRecency(t *testing.T) {
	c, _ := newTestCache(t, 100, 50)
	ctx := context.Background()

	data1, hash1 := randomDataAndHash(t, 50)
	data2, hash2 := randomDataAndHash(t, 50)
	data3, hash3 := randomDataAndHash(t, 20)

	// 1. Put hash1, then hash2. hash1 is now the oldest.
	require.NoError(t, c.Put(hash1, data1))
	time.Sleep(20 * time.Millisecond) // Ensure mod_time is different
	require.NoError(t, c.Put(hash2, data2))
	time.Sleep(20 * time.Millisecond)

	// 2. Update hash1 by putting it again. This should make it the newest of the first two.
	require.NoError(t, c.Put(hash1, data1))

	// 3. Put hash3, which will exceed capacity and should trigger a purge of the oldest item.
	require.NoError(t, c.Put(hash3, data3))
	require.NoError(t, c.PurgeIfNeeded(ctx))

	// 4. Verify that hash2 (now the oldest) was purged, not hash1.
	assert.False(t, fileExists(c, hash2), "hash2 should be purged as it's the oldest")
	assert.True(t, fileExists(c, hash1), "hash1 should exist because it was updated")
	assert.True(t, fileExists(c, hash3), "hash3 should exist")
}

func TestPurgeOrphanedContentHashes(t *testing.T) {
	// Use a very short orphan age for the test
	c, mockDB := newTestCache(t, 1024, 512)
	c.orphanCleanupAge = 0 // Consider anything for cleanup
	ctx := context.Background()

	// Put 3 items in the cache
	data1, hash1 := randomDataAndHash(t, 10) // Will be kept
	data2, hash2 := randomDataAndHash(t, 10) // Will be orphaned
	data3, hash3 := randomDataAndHash(t, 10) // Will be orphaned

	require.NoError(t, c.Put(hash1, data1))
	require.NoError(t, c.Put(hash2, data2))
	require.NoError(t, c.Put(hash3, data3))

	// Configure mock DB to know only about hash1
	mockDB.SetExistingHashes(hash1)

	// Run the orphan purge
	err := c.PurgeOrphanedContentHashes(ctx)
	require.NoError(t, err)

	// Verify that only the non-orphaned file remains
	exists, _ := c.Exists(hash1)
	assert.True(t, exists, "hash1 should exist")

	exists, _ = c.Exists(hash2)
	assert.False(t, exists, "hash2 should be purged")

	exists, _ = c.Exists(hash3)
	assert.False(t, exists, "hash3 should be purged")
}

func TestPurgeOrphanedContentHashes_WithAge(t *testing.T) {
	c, mockDB := newTestCache(t, 1024, 512)
	ctx := context.Background()

	// Set a specific cleanup age
	c.orphanCleanupAge = 2 * time.Second

	// 1. Put an item that will be an old orphan
	dataOldOrphan, hashOldOrphan := randomDataAndHash(t, 10)
	require.NoError(t, c.Put(hashOldOrphan, dataOldOrphan))

	// 2. Put an item that will be old but known to the DB
	dataOldKept, hashOldKept := randomDataAndHash(t, 10)
	require.NoError(t, c.Put(hashOldKept, dataOldKept))

	// 3. Wait for the orphan age to pass
	time.Sleep(3 * time.Second)

	// 4. Put an item that will be a new orphan (too new to be checked)
	dataNewOrphan, hashNewOrphan := randomDataAndHash(t, 10)
	require.NoError(t, c.Put(hashNewOrphan, dataNewOrphan))

	// 5. Configure mock DB to know only about the "kept" hash
	mockDB.SetExistingHashes(hashOldKept)

	// 6. Run the orphan purge
	require.NoError(t, c.PurgeOrphanedContentHashes(ctx))

	// 7. Verify results
	assert.False(t, fileExists(c, hashOldOrphan), "old orphan should be purged")
	assert.True(t, fileExists(c, hashOldKept), "old but known item should be kept")
	assert.True(t, fileExists(c, hashNewOrphan), "new orphan should not be purged yet")
}

func TestSyncFromDiskAndStaleEntries(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	ctx := context.Background()

	// Manually create a file in the cache directory
	data, hash := randomDataAndHash(t, 50)
	path := c.GetPathForContentHash(hash)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, data, 0644))

	// At this point, the file is on disk but not in the index
	exists, _ := c.Exists(hash)
	assert.False(t, exists)

	// Run sync
	require.NoError(t, c.SyncFromDisk())

	// Now it should exist in the index
	exists, _ = c.Exists(hash)
	assert.True(t, exists)

	// Now, test stale entry removal. Add a fake entry to the index.
	_, err := c.db.Exec(`INSERT INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`, "fake/path", 123, time.Now())
	require.NoError(t, err)

	// Run RemoveStaleDBEntries (which is also called by SyncFromDisk)
	require.NoError(t, c.RemoveStaleDBEntries(ctx))

	// Verify the fake entry is gone
	var count int
	err = c.db.QueryRow(`SELECT COUNT(*) FROM cache_index WHERE path = ?`, "fake/path").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestPurgeAll(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	ctx := context.Background()

	// Add some files
	data1, hash1 := randomDataAndHash(t, 50)
	require.NoError(t, c.Put(hash1, data1))
	data2, hash2 := randomDataAndHash(t, 50)
	require.NoError(t, c.Put(hash2, data2))

	stats, err := c.GetStats()
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.ObjectCount)

	// Purge all
	require.NoError(t, c.PurgeAll(ctx))

	// Verify cache is empty
	stats, err = c.GetStats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.ObjectCount)
	assert.Equal(t, int64(0), stats.TotalSize)

	// Verify data directory is empty (or just contains empty subdirs)
	dataDir := filepath.Join(c.basePath, DataDir)
	entries, err := os.ReadDir(dataDir)
	require.NoError(t, err)
	// The subdirs might remain, but they should be empty. A full check is complex,
	// but checking the object count from the DB is sufficient.
	assert.LessOrEqual(t, len(entries), 2) // Dirs for hashes might exist
}

func TestMoveIn(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	data, hash := randomDataAndHash(t, 100)

	// Create a source file
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "source.eml")
	require.NoError(t, os.WriteFile(srcPath, data, 0644))

	// Move it in
	err := c.MoveIn(srcPath, hash)
	require.NoError(t, err)

	// Verify source is gone
	_, err = os.Stat(srcPath)
	assert.True(t, os.IsNotExist(err))

	// Verify it exists in cache
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.True(t, exists)

	retrievedData, err := c.Get(hash)
	require.NoError(t, err)
	assert.Equal(t, data, retrievedData)
}

func TestMoveIn_TargetExists(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)
	data, hash := randomDataAndHash(t, 100)
	existingData, _ := randomDataAndHash(t, 100)

	// Create a source file
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "source.eml")
	require.NoError(t, os.WriteFile(srcPath, data, 0644))

	// Manually place a file at the target location
	targetPath := c.GetPathForContentHash(hash)
	require.NoError(t, os.MkdirAll(filepath.Dir(targetPath), 0755))
	require.NoError(t, os.WriteFile(targetPath, existingData, 0644))
	require.NoError(t, c.trackFile(targetPath)) // Also track it in the index

	// Move it in
	err := c.MoveIn(srcPath, hash)
	require.NoError(t, err)

	// Verify source is gone
	_, err = os.Stat(srcPath)
	assert.True(t, os.IsNotExist(err), "source file should be removed")

	// Verify the content is the *original* content, not the new one.
	retrievedData, err := c.Get(hash)
	require.NoError(t, err)
	assert.Equal(t, existingData, retrievedData, "existing cache content should be preserved")
}

func TestGetPathForContentHash(t *testing.T) {
	c, _ := newTestCache(t, 1024, 1024)
	basePath := c.basePath

	tests := []struct {
		name        string
		contentHash string
		want        string
	}{
		{
			name:        "standard hash",
			contentHash: "abcdef1234567890",
			want:        filepath.Join(basePath, DataDir, "ab", "cd", "ef1234567890"),
		},
		{
			name:        "short hash (less than 4 chars)",
			contentHash: "abc",
			want:        filepath.Join(basePath, DataDir, "abc"),
		},
		{
			name:        "exact 4 char hash",
			contentHash: "abcd",
			want:        filepath.Join(basePath, DataDir, "ab", "cd", ""),
		},
		{
			name:        "empty hash",
			contentHash: "",
			want:        filepath.Join(basePath, DataDir, ""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.GetPathForContentHash(tt.contentHash)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetRecentMessagesForWarmup(t *testing.T) {
	c, mockDB := newTestCache(t, 1024, 512)
	ctx := context.Background()

	t.Run("successful call", func(t *testing.T) {
		expectedData := map[string][]string{"INBOX": {"hash1", "hash2"}}
		mockDB.SetWarmupData(expectedData, nil)

		data, err := c.GetRecentMessagesForWarmup(ctx, 1, []string{"INBOX"}, 2)
		require.NoError(t, err)
		assert.Equal(t, expectedData, data)
	})

	t.Run("error call", func(t *testing.T) {
		expectedError := fmt.Errorf("database is down")
		mockDB.SetWarmupData(nil, expectedError)

		_, err := c.GetRecentMessagesForWarmup(ctx, 1, []string{"INBOX"}, 2)
		require.Error(t, err)
		assert.Equal(t, expectedError, err)
	})
}

func TestGet_FileOnDiskNotInIndex(t *testing.T) {
	c, _ := newTestCache(t, 1024, 512)

	// Manually create a file in the cache directory
	data, hash := randomDataAndHash(t, 50)
	path := c.GetPathForContentHash(hash)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, data, 0644))

	// At this point, the file is on disk but not in the index.
	// Exists() should fail.
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, int64(1), c.cacheMisses)

	// Get() should succeed because it reads directly from the filesystem.
	retrievedData, err := c.Get(hash)
	require.NoError(t, err)
	assert.Equal(t, data, retrievedData)
	assert.Equal(t, int64(1), c.cacheHits) // Get() increments hits
}

// fileExists is a helper to check for file existence without affecting cache metrics.
func fileExists(c *Cache, hash string) bool {
	_, err := os.Stat(c.GetPathForContentHash(hash))
	return err == nil
}
