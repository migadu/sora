package uploader

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"runtime"
	"sync"
	"testing"

	"github.com/migadu/sora/db"
)

// TestProcessSingleUpload_DoesNotBufferBodyInMemory covers the memory amplification of
// the upload path: the worker runs concurrency (20 by default) uploads at once, so a
// body held whole in memory costs concurrency x message size on a node that is already
// carrying a delivery burst. Nothing downstream needs the bytes resident - the S3 seam
// takes an io.Reader, the size guard can stat, and the cache moves the file by path -
// so the body must reach S3 straight off the disk it is already on.
func TestProcessSingleUpload_DoesNotBufferBodyInMemory(t *testing.T) {
	worker, rdb, s3, _, _ := setupTestWorker(t)

	const payloadSize = 16 << 20 // large enough that buffering dwarfs everything else
	const hash = "b3a8e0e1f9ab1bfe3a36f231f676f7e08a43ac7f0b6a53873b52444d67707d01"
	const accountID = int64(7)

	payload := bytes.Repeat([]byte("attachment-"), payloadSize/11+1)[:payloadSize]
	if _, err := worker.StoreLocally(hash, accountID, payload); err != nil {
		t.Fatalf("StoreLocally: %v", err)
	}

	// One content hash can span several keys, so the body is written more than once.
	keys := []string{"a/one/" + hash, "b/two/" + hash}
	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accID int64) ([]string, error) {
		return keys, nil
	}

	want := fnv.New64a()
	want.Write(payload)
	wantSum := want.Sum64()

	var mu sync.Mutex
	received := make(map[string]uint64)
	s3.PutWithRetryFunc = func(ctx context.Context, key string, reader io.Reader, size int64) error {
		h := fnv.New64a()
		n, err := io.Copy(h, reader)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if n != int64(payloadSize) {
			t.Errorf("S3 PUT of %s received %d bytes, want %d", key, n, payloadSize)
		}
		received[key] = h.Sum64()
		return nil
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	worker.processSingleUpload(context.Background(), db.PendingUpload{
		ContentHash: hash,
		AccountID:   accountID,
		Size:        payloadSize,
	})
	runtime.ReadMemStats(&after)

	if len(received) != len(keys) {
		t.Fatalf("uploaded %d keys, want %d", len(received), len(keys))
	}
	for _, key := range keys {
		if received[key] != wantSum {
			t.Errorf("S3 PUT of %s did not receive the message body (checksum %x, want %x) - "+
				"every key needs the whole body, so the source must be rewound per key",
				key, received[key], wantSum)
		}
	}

	// TotalAlloc is cumulative and GC-independent, so this measures what the upload
	// actually allocated rather than what happened to be live at a sampling point.
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > payloadSize/4 {
		t.Errorf("uploading a %d byte body allocated %d bytes; the body must stream from disk, "+
			"not be read whole into memory (x concurrency)", payloadSize, allocated)
	}
}
