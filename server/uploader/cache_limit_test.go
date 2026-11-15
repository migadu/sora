package uploader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A body above the local cache's max_object_size is uploaded but not cached: the
// staged copy is deleted instead of moved in, as Put refuses such a body on the read
// path.
func TestUploadedBodyAboveMaxObjectSizeIsNotCached(t *testing.T) {
	worker, _, _, _, _ := setupTestWorker(t)
	localCache, err := cache.New(t.TempDir(), 1<<20, 4, time.Hour, time.Hour, nil)
	require.NoError(t, err)
	defer localCache.Close()
	worker.cache = localCache

	upload := db.PendingUpload{
		ID:          1,
		AccountID:   100,
		ContentHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		Size:        9, // len("test data"), above the cache's 4-byte max_object_size
		CreatedAt:   time.Now(),
	}
	filePath := worker.FilePath(upload.ContentHash, upload.AccountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, []byte("test data"), 0644))

	assert.Equal(t, uploadDone, worker.processSingleUpload(context.Background(), upload))

	assert.NoFileExists(t, localCache.GetPathForContentHash(upload.ContentHash), "a body above max_object_size was cached")
	assert.NoFileExists(t, filePath, "the staged copy was left behind")
}
