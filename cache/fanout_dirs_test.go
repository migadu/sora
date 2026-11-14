package cache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Removing an object, by any path, leaves its fan-out directory data/XX/YY in place: a
// writer of another object of that directory may be between creating it and putting its
// file into it, and would fail if the directory went away underneath it (#645).
func TestRemovalsKeepFanOutDirectories(t *testing.T) {
	ctx := context.Background()
	hash := "aabb" + strings.Repeat("1", 60)
	const shardIdx = 0xaa

	removals := []struct {
		name   string
		remove func(t *testing.T, c *Cache)
	}{
		{"Delete", func(t *testing.T, c *Cache) {
			require.NoError(t, c.Delete(hash))
		}},
		{"capacity purge", func(t *testing.T, c *Cache) {
			require.NoError(t, c.purgeShardIfNeeded(ctx, c.shards[shardIdx], 0))
		}},
		{"orphan purge", func(t *testing.T, c *Cache) {
			_, err := c.shards[shardIdx].db.Exec(`UPDATE cache_index SET mod_time = ?`, time.Now().Add(-time.Hour))
			require.NoError(t, err)
			require.NoError(t, c.PurgeOrphanedContentHashes(ctx))
		}},
		{"purge cycle", func(t *testing.T, c *Cache) {
			// The object is gone already (evicted by hand); the cycle sweeps its shard.
			require.NoError(t, os.Remove(c.GetPathForContentHash(hash)))
			idx := shardIdx
			c.runPurgeCycle(ctx, &idx)
		}},
	}

	for _, r := range removals {
		t.Run(r.name, func(t *testing.T) {
			// The mock database knows no hash, so the orphan purge removes the object.
			c, _ := newTestCache(t, 262144, 512)
			data, _ := randomDataAndHash(t, 10)
			require.NoError(t, c.Put(hash, data))
			path := c.GetPathForContentHash(hash)

			r.remove(t, c)

			assert.NoFileExists(t, path)
			assert.DirExists(t, filepath.Dir(path), "the object's fan-out directory was removed")
		})
	}
}

// Put and MoveIn write into a fan-out directory while maintenance removes other objects
// of it and sweeps its shard. Neither may fail because the directory they just created
// was removed before their file landed in it (#645).
func TestWritesSurviveConcurrentMaintenance(t *testing.T) {
	ctx := context.Background()
	// Every hash is referenced: the orphan purge removes nothing. The capacity is never
	// reached: the capacity purge removes nothing. Only directories can go.
	c, err := New(t.TempDir(), 1<<30, 1024, time.Hour, time.Hour, &countingSourceDB{})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	hash := "002f" + strings.Repeat("a", 60)
	sibling := "002f" + strings.Repeat("b", 60)
	path := c.GetPathForContentHash(hash)
	body := []byte("fixture body")
	srcDir := t.TempDir()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	maintain := func(step func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					step()
				}
			}
		}()
	}
	// Removal of another object of the same directory, and the purge cycle's sweep of
	// the shard (data/00).
	maintain(func() { _ = c.Delete(sibling) })
	maintain(func() {
		idx := 0
		c.runPurgeCycle(ctx, &idx)
	})
	defer func() {
		close(stop)
		wg.Wait()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < 500 && time.Now().Before(deadline); i++ {
		if err := c.Put(hash, body); err != nil {
			t.Fatalf("Put failed at attempt %d: %v", i, err)
		}
		// Evict the object by hand, leaving its directory empty for maintenance.
		require.NoError(t, os.Remove(path))

		src := filepath.Join(srcDir, "upload.eml")
		require.NoError(t, os.WriteFile(src, body, 0644))
		if err := c.MoveIn(src, hash); err != nil {
			t.Fatalf("MoveIn failed at attempt %d: %v", i, err)
		}
		require.NoError(t, os.Remove(path))
	}
}
