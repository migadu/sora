package cache

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingSourceDB counts the orphan lookups the purge cycle makes and reports every
// hash as still referenced, so nothing is removed as an orphan.
type countingSourceDB struct {
	lookups atomic.Int32
}

func (d *countingSourceDB) FindExistingContentHashesWithRetry(_ context.Context, hashes []string) ([]string, error) {
	d.lookups.Add(1)
	return hashes, nil
}

func (d *countingSourceDB) GetRecentMessagesForWarmupWithRetry(context.Context, int64, []string, int) (map[string][]string, error) {
	return nil, nil
}

// populatedCacheDir returns a cache directory that holds one 100-byte object, and
// that object's hash. The cache that wrote it is closed again.
func populatedCacheDir(t *testing.T) (string, string) {
	t.Helper()
	basePath := t.TempDir()
	c, err := New(basePath, 1<<30, 1024, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	data, hash := randomDataAndHash(t, 100)
	require.NoError(t, c.Put(hash, data))
	require.NoError(t, c.Close())
	return basePath, hash
}

// New only opens the cache. sora-admin opens the cache of a running server with it
// (cache stats, cache purge), and must not set a purge cycle off there.
func TestNewStartsNoPurgeLoop(t *testing.T) {
	basePath, hash := populatedCacheDir(t)

	// One byte per shard: any purge cycle evicts the object at once.
	c, err := New(basePath, NumShards, 1024, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	defer c.Close()

	time.Sleep(500 * time.Millisecond)
	assert.True(t, fileExists(c, hash), "opening the cache ran a purge cycle")
}

// sora starts the purge loop itself, once: every cycle (capacity purge, orphan lookups
// in the database, stale-entry sweep) must run once, not once per loop.
func TestStartPurgeLoopIsTheOnlyLoop(t *testing.T) {
	basePath, _ := populatedCacheDir(t)

	sourceDB := &countingSourceDB{}
	// orphanCleanupAge 0: the object is old enough for an orphan lookup at once.
	c, err := New(basePath, 1<<30, 1024, time.Hour, 0, sourceDB)
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartPurgeLoop(ctx)

	require.Eventually(t, func() bool { return sourceDB.lookups.Load() > 0 }, 5*time.Second, 10*time.Millisecond,
		"the purge loop ran no cycle")
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), sourceDB.lookups.Load(), "one shard holds an object: one cycle makes one orphan lookup")
}

// MoveIn, which the uploader moves every uploaded body in with, applies
// max_object_size as Put does. The source is left for the caller to remove, as on
// MoveIn's other errors.
func TestMoveIn_ObjectTooLarge(t *testing.T) {
	c, _ := newTestCache(t, 262144, 100)
	data, hash := randomDataAndHash(t, 101)
	srcPath := filepath.Join(t.TempDir(), "source.eml")
	require.NoError(t, os.WriteFile(srcPath, data, 0644))

	err := c.MoveIn(srcPath, hash)
	assert.ErrorIs(t, err, ErrObjectTooLarge)

	assert.False(t, fileExists(c, hash), "an object above max_object_size was cached")
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.False(t, exists, "an object above max_object_size was indexed")
	assert.FileExists(t, srcPath)
}

// capacity holds when objects are added, not only at the next purge cycle
// (purge_interval, 12h by default): every uploaded body is moved into the cache.
func TestCapacityEnforcedOnWrite(t *testing.T) {
	writers := map[string]func(t *testing.T, c *Cache, hash string, data []byte){
		"Put": func(t *testing.T, c *Cache, hash string, data []byte) {
			require.NoError(t, c.Put(hash, data))
		},
		"MoveIn": func(t *testing.T, c *Cache, hash string, data []byte) {
			srcPath := filepath.Join(t.TempDir(), hash)
			require.NoError(t, os.WriteFile(srcPath, data, 0644))
			require.NoError(t, c.MoveIn(srcPath, hash))
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			// 100 bytes per shard; randomDataAndHash puts every object in shard 00.
			c, err := New(t.TempDir(), 100*NumShards, 1024, time.Hour, time.Hour, nil)
			require.NoError(t, err)
			defer c.Close()

			var hashes []string
			for i := 0; i < 3; i++ {
				data, hash := randomDataAndHash(t, 60)
				write(t, c, hash, data)
				hashes = append(hashes, hash)
				time.Sleep(20 * time.Millisecond) // distinct mod_time
			}

			stats, err := c.GetStats()
			require.NoError(t, err)
			assert.LessOrEqual(t, stats.TotalSizeBytes, int64(100), "the cache holds more than its capacity")
			assert.False(t, fileExists(c, hashes[0]), "the least recently used object stayed")
			assert.True(t, fileExists(c, hashes[2]), "the object just added was evicted")
		})
	}
}

// capacity is enforced per shard, at capacity/256 each. An object larger than its
// shard's share cannot stay cached: writing it evicts every other object of the shard
// and then the object itself. It is refused like one above max_object_size.
func TestObjectAboveShardCapacityIsRefused(t *testing.T) {
	writers := map[string]func(t *testing.T, c *Cache, hash string, data []byte) error{
		"Put": func(t *testing.T, c *Cache, hash string, data []byte) error {
			return c.Put(hash, data)
		},
		"MoveIn": func(t *testing.T, c *Cache, hash string, data []byte) error {
			srcPath := filepath.Join(t.TempDir(), hash)
			require.NoError(t, os.WriteFile(srcPath, data, 0644))
			return c.MoveIn(srcPath, hash)
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			// 100 bytes per shard, max_object_size well above that; randomDataAndHash
			// puts every object in shard 00.
			c, err := New(t.TempDir(), 100*NumShards, 1024, time.Hour, time.Hour, nil)
			require.NoError(t, err)
			defer c.Close()

			var small []string
			for i := 0; i < 2; i++ {
				data, hash := randomDataAndHash(t, 40)
				require.NoError(t, write(t, c, hash, data))
				small = append(small, hash)
			}

			data, hash := randomDataAndHash(t, 150)
			assert.ErrorIs(t, write(t, c, hash, data), ErrObjectTooLarge)
			assert.False(t, fileExists(c, hash), "an object above its shard's capacity was cached")
			for _, h := range small {
				assert.True(t, fileExists(c, h), "writing an object above its shard's capacity evicted the shard")
			}
		})
	}
}
