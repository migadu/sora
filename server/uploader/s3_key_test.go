package uploader

import (
	"context"
	"io"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The S3 key of a message body is not derived from the account's current primary
// address: every message row records the s3_domain/s3_localpart it was inserted with,
// and every reader (IMAP FETCH, POP3 RETR, User API, exporter, cleaner) builds its key
// from those columns. Promoting an alias to primary between insert and upload — a
// routine admin operation, and the upload queue can be minutes or hours deep — changes
// the current primary but not the recorded columns, so an upload keyed off the current
// primary writes where no reader will ever look.

const (
	keyTestHash      = "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
	keyTestAccountID = int64(4711)
)

// recordingS3 records the keys a worker writes and answers existence from a fixed set.
type recordingS3 struct {
	mu      sync.Mutex
	puts    []string
	present map[string]bool
}

func (s *recordingS3) PutWithRetry(ctx context.Context, key string, reader io.Reader, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts = append(s.puts, key)
	return nil
}

func (s *recordingS3) ExistsWithRetry(ctx context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.present[key], nil
}

func (s *recordingS3) writtenKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := append([]string(nil), s.puts...)
	sort.Strings(keys)
	return keys
}

func keyTestUpload() db.PendingUpload {
	return db.PendingUpload{
		ID:          1,
		AccountID:   keyTestAccountID,
		ContentHash: keyTestHash,
		Size:        9, // len("test data")
	}
}

func stageBody(t *testing.T, w *UploadWorker) {
	t.Helper()
	if _, err := w.StoreLocally(keyTestHash, keyTestAccountID, []byte("test data")); err != nil {
		t.Fatalf("StoreLocally: %v", err)
	}
}

// TestProcessSingleUpload_WritesKeyRecordedOnMessageRow covers the alias promotion:
// the row was inserted under olduser@example.com, the account's primary is now
// user@example.com, and the object must still land where the row says it is.
func TestProcessSingleUpload_WritesKeyRecordedOnMessageRow(t *testing.T) {
	worker, rdb, _, _, _ := setupTestWorker(t)
	s3 := &recordingS3{}
	worker.s3 = s3
	stageBody(t, worker)

	recordedKey := helpers.NewS3Key("example.com", "olduser", keyTestHash)
	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
		return []string{recordedKey}, nil
	}

	worker.processSingleUpload(context.Background(), keyTestUpload())

	assert.Equal(t, []string{recordedKey}, s3.writtenKeys(),
		"the body must be written under the key recorded on the message row; a key built from "+
			"the account's current primary address is unreadable and leaks the object")
}

// TestProcessSingleUpload_WritesEveryRecordedKey covers the same account holding rows
// for one content hash under two keys — the same message delivered before and after
// the promotion. pending_uploads is unique on (content_hash, account_id) and
// CompleteS3Upload marks every row of the pair uploaded, so both keys must be written
// or half of them end up marked uploaded with no object behind them.
func TestProcessSingleUpload_WritesEveryRecordedKey(t *testing.T) {
	worker, rdb, _, _, _ := setupTestWorker(t)
	s3 := &recordingS3{}
	worker.s3 = s3
	stageBody(t, worker)

	oldKey := helpers.NewS3Key("example.com", "olduser", keyTestHash)
	newKey := helpers.NewS3Key("example.com", "user", keyTestHash)
	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
		return []string{oldKey, newKey}, nil
	}

	var completed bool
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
		completed = true
		return nil
	}

	worker.processSingleUpload(context.Background(), keyTestUpload())

	assert.Equal(t, []string{oldKey, newKey}, s3.writtenKeys(),
		"every distinct key recorded for the (content_hash, account_id) pair must be written")
	assert.True(t, completed, "the upload must be finalized once all its keys are written")
}

// TestProcessSingleUpload_MissingLocalFileNeedsEveryKeyInS3 guards the self-heal path
// for the same split: with the staged file gone, finalizing on the strength of one key
// marks rows uploaded whose object was never written, and those messages read as empty
// forever.
func TestProcessSingleUpload_MissingLocalFileNeedsEveryKeyInS3(t *testing.T) {
	worker, rdb, _, _, _ := setupTestWorker(t)
	presentKey := helpers.NewS3Key("example.com", "user", keyTestHash)
	missingKey := helpers.NewS3Key("example.com", "olduser", keyTestHash)
	s3 := &recordingS3{present: map[string]bool{presentKey: true}}
	worker.s3 = s3
	// Deliberately no staged file: it was moved to cache or cleaned up.

	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
		return []string{presentKey, missingKey}, nil
	}

	var completed bool
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
		completed = true
		return nil
	}

	worker.processSingleUpload(context.Background(), keyTestUpload())

	assert.False(t, completed,
		"an upload whose content is missing from one of its keys must not be finalized: "+
			"CompleteS3Upload marks every row of the pair uploaded, including the ones with no object")
}

// TestProcessSingleUpload_NoKeysNeedWriting is the finish of a partially completed
// upload: the rows are already uploaded, so there is nothing to write and the stale
// pending_uploads row and staged file must go.
func TestProcessSingleUpload_NoKeysNeedWriting(t *testing.T) {
	worker, rdb, _, cache, _ := setupTestWorker(t)
	s3 := &recordingS3{}
	worker.s3 = s3
	stageBody(t, worker)
	cache.MoveInFunc = func(srcPath, contentHash string) error {
		return os.Remove(srcPath)
	}

	rdb.PendingUploadKeysFunc = func(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
		return nil, nil
	}

	var completed bool
	rdb.CompleteS3UploadWithRetryFunc = func(ctx context.Context, contentHash string, accountID int64) error {
		completed = true
		return nil
	}

	worker.processSingleUpload(context.Background(), keyTestUpload())

	assert.Empty(t, s3.writtenKeys(), "no key needs writing, so S3 must not be touched")
	assert.True(t, completed, "the stale pending upload must be cleared")
	_, err := os.Stat(worker.FilePath(keyTestHash, keyTestAccountID))
	require.True(t, os.IsNotExist(err), "the staged file must be removed")
}
