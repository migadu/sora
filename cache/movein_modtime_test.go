package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A staged upload file starts life before its S3 upload finishes (often minutes earlier
// when S3 retries). Moving it into a full shard must treat the newly cached body as the
// newest entry, not index its old staging mtime and immediately evict the body itself.
func TestMoveInStagedFileDoesNotSelfEvict(t *testing.T) {
	c, err := New(t.TempDir(), 100*NumShards, 1024, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	defer c.Close()

	// Staged upload file created 5 minutes ago on the same filesystem.
	stagedData, stagedHash := randomDataAndHash(t, 60)
	srcPath := filepath.Join(c.GetBasePath(), "staged-upload.eml")
	writeFile(t, srcPath, stagedData, time.Now().Add(-5*time.Minute))

	// Another 60-byte object is already in shard 00.
	olderCachedData, olderCachedHash := randomDataAndHash(t, 60)
	require.NoError(t, c.Put(olderCachedHash, olderCachedData))

	// Uploader completes and moves the staged body into shard 00 (60 + 60 > 100).
	require.NoError(t, c.MoveIn(srcPath, stagedHash))

	got, err := c.Get(stagedHash)
	require.NoError(t, err, "MoveIn immediately evicted the newly cached staged body")
	assert.Equal(t, stagedData, got)

	exists, err := c.Exists(olderCachedHash)
	require.NoError(t, err)
	assert.False(t, exists, "the older cached body should have been evicted to make room")
}

// When MoveIn finds the content-addressed file already on disk (e.g. a second recipient's
// staged upload of the same message, or after Get updated mod_time in SQLite without
// touching filesystem mtime), it must refresh mod_time rather than rewinding it to the
// target file's old creation mtime.
func TestMoveInExistingTargetRefreshesModTimeInsteadOfRewinding(t *testing.T) {
	c, err := New(t.TempDir(), 120*NumShards, 1024, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	defer c.Close()

	now := time.Now()
	tenMinAgo := now.Add(-10 * time.Minute)
	fiveMinAgo := now.Add(-5 * time.Minute)

	dataA, hashA := randomDataAndHash(t, 60)
	require.NoError(t, c.Put(hashA, dataA))
	pathA := c.GetPathForContentHash(hashA)
	require.NoError(t, os.Chtimes(pathA, tenMinAgo, tenMinAgo))
	_, err = c.getShard(hashA).db.Exec(`UPDATE cache_index SET mod_time = ? WHERE path = ?`, now.Add(-time.Second), pathA)
	require.NoError(t, err)

	dataB, hashB := randomDataAndHash(t, 60)
	require.NoError(t, c.Put(hashB, dataB))
	pathB := c.GetPathForContentHash(hashB)
	require.NoError(t, os.Chtimes(pathB, fiveMinAgo, fiveMinAgo))
	_, err = c.getShard(hashB).db.Exec(`UPDATE cache_index SET mod_time = ? WHERE path = ?`, fiveMinAgo, pathB)
	require.NoError(t, err)

	// Duplicate staged upload of hashA arrives now.
	dupSrc := filepath.Join(c.GetBasePath(), "dup-upload.eml")
	writeFile(t, dupSrc, dataA, tenMinAgo)
	require.NoError(t, c.MoveIn(dupSrc, hashA))

	// Adding hashC (60 bytes) pushes shard 00 over 120 bytes; hashB (5m old) must go,
	// not hashA (just accessed/moved in).
	dataC, hashC := randomDataAndHash(t, 60)
	require.NoError(t, c.Put(hashC, dataC))

	existsA, err := c.Exists(hashA)
	require.NoError(t, err)
	assert.True(t, existsA, "hashA was evicted after duplicate MoveIn rewound its mod_time")

	existsB, err := c.Exists(hashB)
	require.NoError(t, err)
	assert.False(t, existsB, "older hashB should have been evicted instead of hashA")
}

// Replacing an existing entry via Put/MoveIn or deleting an entry via Delete must keep
// shard.size aligned with cache_index rather than double-counting replacements or
// retaining deleted bytes.
func TestDuplicateWriteAndDeleteKeepShardSizeAccurate(t *testing.T) {
	c, err := New(t.TempDir(), 100*NumShards, 1024, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	defer c.Close()

	dataA, hashA := randomDataAndHash(t, 40)
	shard := c.getShard(hashA)

	require.NoError(t, c.Put(hashA, dataA))
	shard.mu.Lock()
	sizeAfterFirstPut := shard.size
	shard.mu.Unlock()
	assert.Equal(t, int64(40), sizeAfterFirstPut)

	// Overwriting the same hash via Put (40+40 <= 100, before any purge recalculates)
	// and MoveIn must not inflate shard.size.
	require.NoError(t, c.Put(hashA, dataA))
	shard.mu.Lock()
	sizeAfterSecondPut := shard.size
	shard.mu.Unlock()
	assert.Equal(t, int64(40), sizeAfterSecondPut, "replacing an existing row must not double-count shard.size")

	dupSrc := filepath.Join(c.GetBasePath(), "dup.eml")
	require.NoError(t, os.WriteFile(dupSrc, dataA, 0644))
	require.NoError(t, c.MoveIn(dupSrc, hashA))

	shard.mu.Lock()
	sizeAfterDuplicates := shard.size
	shard.mu.Unlock()
	assert.Equal(t, int64(40), sizeAfterDuplicates)

	require.NoError(t, c.Delete(hashA))
	shard.mu.Lock()
	sizeAfterDelete := shard.size
	shard.mu.Unlock()
	assert.Equal(t, int64(0), sizeAfterDelete)
}
