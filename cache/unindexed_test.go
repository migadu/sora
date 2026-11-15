package cache

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every eviction (capacity purge, orphan purge, stale-entry sweep) starts from the index,
// and Get serves a file from disk without looking at it. A file without its index row
// therefore stays on disk for good, outside the capacity (#768).

// unindexedFiles returns the files under data/ that no index row covers, relative to it.
func unindexedFiles(t *testing.T, c *Cache) []string {
	t.Helper()
	root := filepath.Join(c.basePath, DataDir)
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		var n int
		shard := c.getShard(strings.ReplaceAll(rel, string(filepath.Separator), ""))
		require.NoError(t, shard.db.QueryRow(`SELECT COUNT(*) FROM cache_index WHERE path = ?`, path).Scan(&n))
		if n == 0 {
			out = append(out, rel)
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

// hashInShard returns a random content hash of shard idx.
func hashInShard(t *testing.T, idx int) string {
	t.Helper()
	b := make([]byte, 31)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return fmt.Sprintf("%02x%x", idx, b)
}

// writeFile puts data at path, creating its directory, with the given modification time.
func writeFile(t *testing.T, path string, data []byte, modTime time.Time) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, data, 0644))
	require.NoError(t, os.Chtimes(path, modTime, modTime))
}

// A write the index does not take (an INSERT failing with SQLITE_BUSY, say) leaves no
// file behind: Put and MoveIn put the file in place before they index it.
func TestWriteTheIndexRefusesLeavesNoFile(t *testing.T) {
	writers := map[string]func(t *testing.T, c *Cache, hash string, data []byte) error{
		"Put": func(t *testing.T, c *Cache, hash string, data []byte) error {
			return c.Put(hash, data)
		},
		"MoveIn": func(t *testing.T, c *Cache, hash string, data []byte) error {
			srcPath := filepath.Join(t.TempDir(), "upload.eml")
			require.NoError(t, os.WriteFile(srcPath, data, 0644))
			return c.MoveIn(srcPath, hash)
		},
		"MoveIn onto an unindexed file": func(t *testing.T, c *Cache, hash string, data []byte) error {
			writeFile(t, c.GetPathForContentHash(hash), data, time.Now())
			srcPath := filepath.Join(t.TempDir(), "upload.eml")
			require.NoError(t, os.WriteFile(srcPath, data, 0644))
			return c.MoveIn(srcPath, hash)
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestCache(t, 262144, 512)
			data, hash := randomDataAndHash(t, 100)
			// The index insert fails.
			_, err := c.getShard(hash).db.Exec(`DROP TABLE cache_index`)
			require.NoError(t, err)

			assert.Error(t, write(t, c, hash, data))

			assert.False(t, fileExists(c, hash), "the file the index did not take stayed on disk")
			_, err = c.Get(hash)
			assert.True(t, os.IsNotExist(err), "Get served a body the index does not cover: %v", err)
		})
	}
}

// The orphan purge drops an object's row only once its file is gone: a row dropped next
// to a file the remove could not take leaves that file outside every eviction.
func TestOrphanPurgeKeepsTheRowOfAFileItCannotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files from read-only directories")
	}
	ctx := context.Background()
	// The mock database knows no hash: every object is an orphan.
	c, _ := newTestCache(t, 262144, 512)
	data, hash := randomDataAndHash(t, 10)
	require.NoError(t, c.Put(hash, data))
	_, err := c.getShard(hash).db.Exec(`UPDATE cache_index SET mod_time = ?`, time.Now().Add(-time.Hour))
	require.NoError(t, err)

	// The remove fails (EACCES): the object's directory is read-only.
	dir := filepath.Dir(c.GetPathForContentHash(hash))
	require.NoError(t, os.Chmod(dir, 0555))
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	require.NoError(t, c.PurgeOrphanedContentHashes(ctx))

	require.True(t, fileExists(c, hash))
	assert.Empty(t, unindexedFiles(t, c), "the orphan purge dropped the row of a file it could not remove")

	// Once the remove can succeed, the next purge removes both.
	require.NoError(t, os.Chmod(dir, 0755))
	require.NoError(t, c.PurgeOrphanedContentHashes(ctx))
	assert.False(t, fileExists(c, hash))
	exists, err := c.Exists(hash)
	require.NoError(t, err)
	assert.False(t, exists)
}

// PurgeAll runs while the server writes into the cache (sora-admin cache purge, the Admin
// API). A write landing between the removal of the files and the clearing of the index
// must not leave a file whose row the clearing drops.
func TestPurgeAllRacingWritesLeavesNoUnindexedFile(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCache(t, 1<<30, 1024)

	// Files in every other shard keep PurgeAll removing trees for a while after it has
	// removed data/00, which the writers below write into.
	for idx := 1; idx < NumShards; idx++ {
		for i := 0; i < 4; i++ {
			writeFile(t, c.GetPathForContentHash(hashInShard(t, idx)), []byte("x"), time.Now())
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 31)
			for {
				select {
				case <-stop:
					return
				default:
				}
				rand.Read(b)
				// A write may fail when PurgeAll removes its directory (#645).
				_ = c.Put(fmt.Sprintf("00%x", b), b)
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	err := c.PurgeAll(ctx)
	close(stop)
	wg.Wait()
	if err != nil {
		// A writer can make a directory nonempty again while RemoveAll walks it.
		// PurgeAll reports the incomplete removal and indexes what remains.
		require.ErrorIs(t, err, syscall.ENOTEMPTY)
	}

	assert.Empty(t, unindexedFiles(t, c), "a write racing PurgeAll left a file without its index row")
}

// A failed filesystem removal must be reported, and the bodies it leaves behind
// must remain covered by the index so capacity eviction can retry them later.
func TestPurgeAllKeepsFailedRemovalsIndexed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files from read-only directories")
	}
	c, _ := newTestCache(t, 262144, 512)
	data, hash := randomDataAndHash(t, 10)
	require.NoError(t, c.Put(hash, data))
	path := c.GetPathForContentHash(hash)
	dir := filepath.Dir(path)
	require.NoError(t, os.Chmod(dir, 0555))
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	require.Error(t, c.PurgeAll(context.Background()))
	assert.FileExists(t, path)
	assert.Empty(t, unindexedFiles(t, c), "the failed removal left a body outside the capacity accounting")

	require.NoError(t, os.Chmod(dir, 0755))
	require.NoError(t, c.PurgeAll(context.Background()))
	assert.NoFileExists(t, path)
}

// A crash between a write's rename and its index insert leaves a file without a row; one
// before the rename leaves the write's temporary file. The purge cycle's sweep of a shard
// indexes the first, so the capacity purge reaches it, and removes the second once it is
// old enough not to be a write in progress. It keeps the fan-out directories (#645).
func TestPurgeCycleSweepTakesBackFilesTheIndexLost(t *testing.T) {
	ctx := context.Background()
	const idx = 0xab
	// 100 bytes per shard.
	c, err := New(t.TempDir(), 100*NumShards, 1024, time.Hour, time.Hour, &countingSourceDB{})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	// Left by a crash a day ago, between rename and index insert.
	lostOld := hashInShard(t, idx)
	writeFile(t, c.GetPathForContentHash(lostOld), make([]byte, 60), time.Now().Add(-24*time.Hour))
	// Left the same way, but within the capacity.
	lost := hashInShard(t, idx)
	writeFile(t, c.GetPathForContentHash(lost), make([]byte, 30), time.Now().Add(-time.Hour))
	// The object written since.
	fresh := hashInShard(t, idx)
	require.NoError(t, c.Put(fresh, make([]byte, 60)))
	// Temporary files of Put and of MoveIn's cross-device copy, two hours old, and one of
	// a write in progress.
	staleTmpPut := c.GetPathForContentHash(hashInShard(t, idx)) + ".tmp.1700000000000000000_0a1b2c3d"
	writeFile(t, staleTmpPut, []byte("partial"), time.Now().Add(-2*time.Hour))
	staleTmpCopy := c.GetPathForContentHash(hashInShard(t, idx)) + ".tmp.1700000000000000000"
	writeFile(t, staleTmpCopy, []byte("partial"), time.Now().Add(-2*time.Hour))
	liveTmp := c.GetPathForContentHash(hashInShard(t, idx)) + fmt.Sprintf(".tmp.%d_0a1b2c3d", time.Now().UnixNano())
	writeFile(t, liveTmp, []byte("partial"), time.Now())

	shardIdx := idx
	c.runPurgeCycle(ctx, &shardIdx)

	assert.False(t, fileExists(c, lostOld), "an unindexed file over the capacity was not evicted")
	assert.True(t, fileExists(c, fresh), "the object written since was evicted")
	assert.True(t, fileExists(c, lost))
	exists, err := c.Exists(lost)
	require.NoError(t, err)
	assert.True(t, exists, "an unindexed file was not indexed")
	stats, err := c.GetStats()
	require.NoError(t, err)
	assert.Equal(t, int64(90), stats.TotalSizeBytes, "the capacity does not count the file indexed")

	assert.NoFileExists(t, staleTmpPut, "a temporary file of a write cut off was not removed")
	assert.NoFileExists(t, staleTmpCopy, "a temporary file of a copy cut off was not removed")
	assert.FileExists(t, liveTmp, "the temporary file of a write in progress was removed")
	assert.DirExists(t, filepath.Dir(c.GetPathForContentHash(lostOld)), "a fan-out directory was removed")
}

// The purge cycle sweeps one shard per purge_interval, 256 intervals for all of them (128
// days at the default 12h). A node restarted more often than that must not start over at
// shard 00 each time, or it sweeps the first few shards again and again and never the
// rest: the rotation follows the clock across restarts.
func TestPurgeLoopShardSweepFollowsTheClock(t *testing.T) {
	const interval = time.Hour
	c, err := New(t.TempDir(), 1<<30, 1024, interval, time.Hour, &countingSourceDB{})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	// A row without its file in every shard; the stale-entry sweep drops the one of the
	// shard it sweeps.
	for idx := 0; idx < NumShards; idx++ {
		_, err := c.shards[idx].db.Exec(`INSERT INTO cache_index (path, size, mod_time) VALUES (?, 1, ?)`,
			c.GetPathForContentHash(hashInShard(t, idx)), time.Now())
		require.NoError(t, err)
	}

	slot := func() int { return int(time.Now().UnixNano() / int64(interval) % NumShards) }
	before := slot()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartPurgeLoop(ctx)
	after := slot()

	swept := -1
	require.Eventually(t, func() bool {
		for idx := 0; idx < NumShards; idx++ {
			var n int
			require.NoError(t, c.shards[idx].db.QueryRow(`SELECT COUNT(*) FROM cache_index`).Scan(&n))
			if n == 0 {
				swept = idx
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "the first purge cycle swept no shard")
	assert.Contains(t, []int{before, after}, swept, "the first cycle after a start swept shard %02x, not the one the clock gives", swept)
}
