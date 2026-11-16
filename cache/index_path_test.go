package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each shard's index is <cache path>/cache_index_XX.db. A plain SQLite DSN is cut at its
// first '?' (the rest is read as DSN parameters), so a '?' in the cache path used to open
// all 256 shard indexes as one file at the path truncated there, and every shard counted
// every shard's objects. '#' and '%' are special in a file: URI and must reach SQLite as
// part of the name too.
func TestShardIndexesAreInsideCachePath(t *testing.T) {
	for _, dir := range []string{"a?b", "a#b", "a%3Fb", "a%b"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			basePath := filepath.Join(root, dir)
			c, err := New(basePath, 100*NumShards, 1024, time.Hour, time.Hour, nil)
			require.NoError(t, err)
			defer c.Close()

			data, hash := randomDataAndHash(t, 60)
			require.NoError(t, c.Put(hash, data))

			stats, err := c.GetStats()
			require.NoError(t, err)
			assert.Equal(t, int64(1), stats.ObjectCount)
			assert.Equal(t, int64(60), stats.TotalSizeBytes)

			objects, size, err := Usage(basePath)
			require.NoError(t, err)
			assert.Equal(t, int64(1), objects)
			assert.Equal(t, int64(60), size)

			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			require.Len(t, entries, 1, "an index was created outside the cache path")
			assert.Equal(t, dir, entries[0].Name())
		})
	}
}
